/**
 * C373 P1, per-workflow companion grants, bridge side (specs#63 head 472560d, BRIDGE §8.6; P1-DESIGN §4, §10 C4, §12/§13):
 *
 * Gate (a grant with `wfl` = a "workflow grant"; quiet on good, fire on bad for every refusal):
 * - rule 2.1 `exp − iat` > 900 → 403 `grant_invalid` (counted `rejected` kind `grant`); 900 passes;
 * - rule 2.2 workflow grant + another workflow, or + no workflow → 403 `workflow_mismatch`;
 * - rule 2.3 base grant + a workflow in the envelope → 403 `workflow_grant_required` (never a fallback to the base grant);
 * - rule 2.4 the `grant_stale` rule is skipped for a workflow grant; instead `workflow_grant_withdrawn` for (a) a record,
 *   (b) the epoch, (c) no `workflowGrantEdges[sub]` entry for `aud` (an ABSENT field too; `companionTargets` does not count),
 *   (d) `held` lacking a family of the current `appsPolicy.held` (absent policy = DEFAULT_HELD_FAMILIES);
 * - rule 2.5 the normal `wf` / crud checks run on the workflow grant (`not_in_workflow`); a base grant is unchanged;
 * - re-gate after the before hooks (a record that arrives during the hooks wins); hooks see the verified `call.caller.workflow`;
 *   the audit line carries `wfl`; a malformed envelope `workflow` → 400 `input_invalid` `/workflow`.
 * C4: withdraw → the next call with the OLD cached grant (14 min left) is refused as soon as the bridge applies that ONE config
 * revision: record path (`workflowGrantsWithdrawn`) AND epoch path (`wflEpoch`); records for other workflows, targets, instances
 * or older than the grant stay quiet.
 * Relays (`/tb/v1/workflow-grants/{request,get,release}`): Core gets `ins` = the asserting instance (a body `ins` is refused),
 * Core's answer is passed through; a wrong instance key, an assertion for another path and a companion service are refused
 * before Core; a paused caller → `paused` on all three; Portal down or no readable answer → 503 `portal_unavailable`.
 * App caps (rule 7): `AppStatus.caps` (claim, then every push) normalised into `StatusReport.apps[].caps`.
 *
 * TEMP (until the bridge pins the manifest release that knows `wfl`): the pinned manifest's grant claim set is CLOSED, so it
 * refuses every grant with `wfl` (`grant_invalid`, asserted below: fail closed). The bridge in this file runs with a test-only
 * ManifestApi wrapper that verifies a workflow grant through its TWIN (the same claims without `wfl`, signed by the same Portal
 * key) and adds `wfl` back to the verified claims: exactly what the P1 manifest's verifier does. Delete the wrapper at the re-pin.
 */
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import type { ManifestApi } from "@opt2-tealbrick/relay";
import { DEFAULT_HELD_FAMILIES } from "@opt2-tealbrick/spec/manifest";
import type { Ed25519KeyPair } from "@opt2-tealbrick/spec/sdk";
import { normaliseAppCaps } from "../src/app-reported-caps.ts";
import { WORKFLOW_GRANT_PATHS } from "../src/spec-p1.temp.ts";
import { hasWorkflowEdge, heldCoversPolicy, withdrawalReason } from "../src/workflow-grants.ts";
import { type AppClient, claimApp } from "./support/app-client.ts";
import { BRG, INS, makeWorld, SVC_CODE, type World, WS, waitFor } from "./support/world.ts";

const now = () => Math.floor(Date.now() / 1000);
const WFL = "wf-daily-digest";
const OTHER = "wf-other-flow";
const SUB = `tb:ins:${INS}`;

/** workflow grant token → its twin (same claims without `wfl`) and the `wfl` value */
const twins = new Map<string, { twin: string; wfl: unknown }>();
const wrapApi = (api: ManifestApi): ManifestApi => ({
  ...api,
  verifyGrant: (token, ctx) => {
    const t = twins.get(token);
    if (!t) return api.verifyGrant(token, ctx);
    const r = api.verifyGrant(t.twin, ctx);
    return "claims" in r ? { ...r, token, claims: { ...r.claims, wfl: t.wfl } as typeof r.claims } : r;
  },
  gate: (input) => api.gate({ ...input, grant: twins.get(input.grant)?.twin ?? input.grant }),
});

const lines: { event: string; fields: Record<string, unknown> }[] = [];
const logger = {
  info: (event: string, fields: Record<string, unknown> = {}) => lines.push({ event, fields }),
  warn: (event: string, fields: Record<string, unknown> = {}) => lines.push({ event, fields }),
  error: (event: string, fields: Record<string, unknown> = {}) => lines.push({ event, fields }),
};

let w: World;
let a: AppClient;

const HELD = [...DEFAULT_HELD_FAMILIES];
const claims = (wf: string[], o: { iat?: number; exp?: number; held?: string[] } = {}) => {
  const iat = o.iat ?? now() - 60;
  return { iss: "tb:portal", sub: SUB, aud: `tb:ins:${INS}`, iat, exp: o.exp ?? iat + 900, jti: w.api.ulid(), ws: WS, cnf: { brg: BRG }, crud: ["read", "create"], mode: "bound", held: o.held ?? HELD, caps: {}, wf, polrev: 1, prd: "notes" };
};
/** a workflow grant (registered with the TEMP verifier unless `register` is false) */
const workflowGrant = async (wfl: unknown, wf: string[] = ["notes_list"], o: { iat?: number; exp?: number; held?: string[]; register?: boolean } = {}) => {
  const c = claims(wf, o);
  const token = await w.signPortalUnchecked("tb-grant+jwt", { ...c, wfl });
  if (o.register !== false) twins.set(token, { twin: await w.signPortal("tb-grant+jwt", c), wfl });
  return token;
};
let base = "";
let baseOld = "";

const signedPost = async (who: { ins: string; key: Ed25519KeyPair }, path: string, body: unknown, o: { headers?: Record<string, string>; svc?: string; signPath?: string } = {}) => {
  const raw = Buffer.from(JSON.stringify(body));
  const assertion = await w.api.signAssertion(
    "tb-instance-assert+jwt",
    { iss: `tb:ins:${who.ins}`, sub: `tb:ins:${who.ins}`, aud: `tb:brg:${BRG}`, iat: now(), exp: now() + 60, jti: w.api.ulid(), ...(o.svc ? { svc: o.svc } : {}) },
    who.key,
    { method: "POST", pathAndQuery: o.signPath ?? path, body: raw },
  );
  const r = await fetch(`${w.internalUrl}${path}`, { method: "POST", headers: { "content-type": "application/json", "TB-Assert": assertion, ...(o.headers ?? {}) }, body: raw });
  const text = await r.text();
  return { status: r.status, text, json: text ? (JSON.parse(text) as Record<string, any>) : undefined, retryAfter: r.headers.get("retry-after") };
};
const call = (grant: string, envelope: Record<string, unknown>) => signedPost(a, "/tb/v1/call", { target: "notes", op: "notes_list", input: {}, ...envelope }, { headers: { "TB-Grant": grant } });

const mark = () => ({ ops: w.appLog.ops.length, hooks: w.appLog.hooks.length });
const untouched = (m: { ops: number; hooks: number }, why: string) => {
  assert.equal(w.appLog.ops.length, m.ops, `${why}: the app is not called`);
  assert.equal(w.appLog.hooks.length, m.hooks, `${why}: no hook ran`);
};
const refused = async (r: { status: number; text: string; json?: Record<string, any> }, status: number, code: string, m: { ops: number; hooks: number }) => {
  assert.equal(r.status, status, r.text);
  assert.equal(r.json?.error.code, code, r.text);
  untouched(m, code);
};
const routed = (r: { status: number; text: string }, m: { ops: number }) => {
  assert.equal(r.status, 200, r.text);
  assert.equal(w.appLog.ops.length, m.ops + 1, "the app ran the op once");
};

/** the caller's slice: its base grants, the target in `companionTargets` (a wildcard entry lists targets too; NOT an edge for rule 2.4c), and `appsPolicy` when given */
const sliceFor = (grants: string[], o: { held?: string[] } = {}) =>
  w.signPortal("tb-slice+jws", { v: 1, iss: "tb:portal", sub: SUB, aud: SUB, iat: now(), exp: now() + 43200, jti: w.api.ulid(), ws: WS, rev: 2, ins: INS, product: "notes", grants, companionTargets: [{ product: "notes", ins: INS }], ...(o.held ? { appsPolicy: { held: o.held } } : {}) });
const OTHER_INS = "tb:ins:ins_01HQQQQQQQQQQQQQQQQQQQQQQQ";
const applied = async (rev: number) => waitFor(() => w.bridge.ctx.table?.rev === rev && w.bridge.ctx.table?.apps.get(INS as never)?.down === false, 15000);
/** publish ONE revision with these workflow fields (the base config keeps the slice set by `amend`) */
const withConfig = async (fields: Record<string, unknown>) => applied(await w.publish((c) => Object.assign(c, fields)));

before(async () => {
  w = await makeWorld({ real: true, withHook: true, wrapApi, logger });
  await waitFor(() => w.bridge.ctx.table?.rev === w.rev(), 15000);
  base = await w.signPortal("tb-grant+jwt", claims(["notes_list"]));
  baseOld = await w.signPortal("tb-grant+jwt", claims(["notes_list"]));
  const slice = await sliceFor([base]);
  await applied(await w.amend((c) => {
    for (const app of c.apps) if (app.ins === INS) (app as { slice: string }).slice = slice;
    // rule 2.4c: the enabled companion edge caller → target (here the instance calls itself)
    Object.assign(c, { workflowGrantEdges: { [SUB]: [SUB] } });
  }));
  a = await claimApp(w);
  assert.equal(a.claimStatus, 200);
  w.hookMode.mode = "allow";
});
after(async () => {
  w.portalRoutes.answer = undefined;
  await w.close();
});

describe("C373 P1 gate: workflow grants (BRIDGE §8.6)", () => {
  test("TEMP pin: without the P1 verifier (closed claim set) a grant with wfl is refused grant_invalid, never forwarded", async () => {
    const token = await workflowGrant(WFL, ["notes_list"], { register: false });
    const m = mark();
    await refused(await call(token, { workflow: WFL }), 403, "grant_invalid", m);
  });

  test("good: workflow grant (not in the slice) + matching workflow → routed; hooks see the verified workflow; the audit line has wfl", async () => {
    const token = await workflowGrant(WFL);
    const m = mark();
    lines.length = 0;
    const r = await call(token, { workflow: WFL });
    routed(r, m);
    const hook = w.appLog.hooks.at(-1)?.body as { call: { caller: Record<string, unknown> } } | undefined;
    assert.deepEqual(hook?.call.caller, { type: "app", id: INS, product: "notes", workflow: WFL });
    const audit = lines.find((l) => l.event === "call.app_initiated");
    assert.equal(audit?.fields.wfl, WFL);
    assert.equal(audit?.fields.decision, "forwarded");
    assert.ok(!JSON.stringify(lines).includes(token.split(".")[2] as string), "the grant never reaches a log line");
  });

  test("bad: workflow grant + another workflow → 403 workflow_mismatch", async () => {
    const token = await workflowGrant(WFL);
    const m = mark();
    await refused(await call(token, { workflow: OTHER }), 403, "workflow_mismatch", m);
  });

  test("bad: workflow grant + no workflow in the envelope → 403 workflow_mismatch", async () => {
    const token = await workflowGrant(WFL);
    const m = mark();
    await refused(await call(token, {}), 403, "workflow_mismatch", m);
  });

  test("bad: base grant + a workflow in the envelope → 403 workflow_grant_required (no fallback to the base grant)", async () => {
    const m = mark();
    await refused(await call(base, { workflow: WFL }), 403, "workflow_grant_required", m);
  });

  test("quiet: base grant without a workflow is unchanged; a base grant not in the slice is still grant_stale", async () => {
    let m = mark();
    routed(await call(base, {}), m);
    const hook = w.appLog.hooks.at(-1)?.body as { call: { caller: Record<string, unknown> } } | undefined;
    assert.equal(hook?.call.caller.workflow, undefined, "no workflow for a base-grant call");
    m = mark();
    await refused(await call(baseOld, {}), 403, "grant_stale", m);
  });

  test("bad: workflow grant, op outside its wf → not_in_workflow (the normal wf check runs on the workflow grant)", async () => {
    const token = await workflowGrant(WFL, ["notes_list"]);
    const m = mark();
    await refused(await call(token, { op: "notes_create", workflow: WFL, idempotencyKey: "k-1" }), 403, "not_in_workflow", m);
  });

  test("bad: a malformed envelope workflow → 400 input_invalid /workflow (the value is not echoed)", async () => {
    const token = await workflowGrant(WFL);
    for (const bad of ["Bad-Id", "ab", 7, "x".repeat(41), ""]) {
      const m = mark();
      const r = await call(token, { workflow: bad });
      await refused(r, 400, "input_invalid", m);
      assert.equal(r.json?.error.details?.pointer, "/workflow");
    }
  });

  test("bad: a malformed wfl claim → grant_invalid", async () => {
    const token = await workflowGrant("NOT A WORKFLOW");
    const m = mark();
    await refused(await call(token, { workflow: WFL }), 403, "grant_invalid", m);
  });

  test("rule 2.1: exp − iat = 900 is accepted; 901 → grant_invalid (counted rejected kind grant), never forwarded", async () => {
    const iat = now() - 60;
    let m = mark();
    routed(await call(await workflowGrant(WFL, ["notes_list"], { iat, exp: iat + 900 }), { workflow: WFL }), m);
    lines.length = 0;
    m = mark();
    await refused(await call(await workflowGrant(WFL, ["notes_list"], { iat, exp: iat + 901 }), { workflow: WFL }), 403, "grant_invalid", m);
    assert.ok(lines.some((l) => l.event === "bridge.rejected" && l.fields.kind === "grant" && l.fields.code === "grant_invalid" && l.fields.ins === INS), "counted as a rejected grant");
  });

  test("B-WFL.edge_disabled: no workflowGrantEdges[sub] entry for aud → 403 workflow_grant_withdrawn with no record; the edge back → routed", async () => {
    const token = await workflowGrant(WFL);
    for (const edges of [{}, { [SUB]: [] }, { [SUB]: [OTHER_INS] }, { [OTHER_INS]: [SUB] }, { [SUB]: "x" }, []]) {
      await withConfig({ workflowGrantEdges: edges });
      const m = mark();
      await refused(await call(token, { workflow: WFL }), 403, "workflow_grant_withdrawn", m);
    }
    await applied(await w.publish());
    const m = mark();
    routed(await call(token, { workflow: WFL }), m);
  });

  test("B-WFL.no_edges_field: an ABSENT workflowGrantEdges (the config carries no P1 field at all) refuses every wfl grant", async () => {
    const token = await workflowGrant(WFL);
    await applied(await w.publish((c) => {
      Reflect.deleteProperty(c, "workflowGrantEdges");
    }));
    assert.equal("workflowGrantEdges" in (w.bridge.ctx.table?.config ?? {}), false, "the config really has no P1 field");
    const m = mark();
    await refused(await call(token, { workflow: WFL }), 403, "workflow_grant_withdrawn", m);
    await applied(await w.publish());
  });

  test("B-WFL.wildcard_not_edge: the slice companionTargets lists the target but workflowGrantEdges does not → refused", async () => {
    const token = await workflowGrant(WFL);
    await withConfig({ workflowGrantEdges: { [SUB]: [OTHER_INS] } });
    const m = mark();
    await refused(await call(token, { workflow: WFL }), 403, "workflow_grant_withdrawn", m);
    await applied(await w.publish());
  });

  test("B-WFL.held_stale: the current appsPolicy.held has a family the grant's held lacks → withdrawn; with it → routed; absent policy = DEFAULT", async () => {
    const stale = await workflowGrant(WFL);
    const wider = await workflowGrant(WFL, ["notes_list"], { held: [...HELD, "outward"] });
    const policy = await sliceFor([base], { held: [...HELD, "outward"] });
    await applied(await w.publish((c) => {
      for (const app of c.apps) if (app.ins === INS) (app as { slice: string }).slice = policy;
    }));
    let m = mark();
    await refused(await call(stale, { workflow: WFL }), 403, "workflow_grant_withdrawn", m);
    m = mark();
    routed(await call(wider, { workflow: WFL }), m);
    // a policy that the grant covers (a subset), and a family this bridge does not know (filtered on both sides)
    const subset = await sliceFor([base], { held: ["money", "unknown_family"] });
    await applied(await w.publish((c) => {
      for (const app of c.apps) if (app.ins === INS) (app as { slice: string }).slice = subset;
    }));
    m = mark();
    routed(await call(stale, { workflow: WFL }), m);
    // no appsPolicy: DEFAULT_HELD_FAMILIES; a grant with held [] lacks them
    await applied(await w.publish());
    m = mark();
    await refused(await call(await workflowGrant(WFL, ["notes_list"], { held: [] }), { workflow: WFL }), 403, "workflow_grant_withdrawn", m);
    m = mark();
    routed(await call(stale, { workflow: WFL }), m);
  });

  test("pure rules: edges and held fail closed on malformed input", () => {
    assert.equal(hasWorkflowEdge({ workflowGrantEdges: { [SUB]: [SUB] } }, SUB as never, SUB), true);
    assert.equal(hasWorkflowEdge({}, SUB as never, SUB), false, "absent field");
    assert.equal(hasWorkflowEdge({ workflowGrantEdges: { [SUB]: [SUB] } }, OTHER_INS as never, SUB), false, "another caller");
    assert.equal(hasWorkflowEdge({ workflowGrantEdges: { constructor: [SUB] } } as never, "constructor" as never, SUB), true, "own keys only are read");
    assert.equal(hasWorkflowEdge({ workflowGrantEdges: Object.create({ [SUB]: [SUB] }) } as never, SUB as never, SUB), false, "no inherited entry");
    assert.equal(heldCoversPolicy(["money"], new Set(["money"])), true);
    assert.equal(heldCoversPolicy(["money"], new Set(["money", "outward"])), false);
    assert.equal(heldCoversPolicy("money", new Set()), false, "held must be an array");
    assert.equal(heldCoversPolicy(undefined, new Set()), false);
    assert.equal(heldCoversPolicy([], new Set()), true, "nothing required");
  });

  test("regate (step 9): a withdrawal record that arrives while the before hooks run refuses the call; the target is not called", async () => {
    const token = await workflowGrant(WFL);
    let m = mark();
    routed(await call(token, { workflow: WFL }), m);
    // the before hook (the only enabled hook) swaps the bridge's table the way a config apply does (swapTable): the same table with
    // a withdrawal record. A real revision takes seconds to apply; the hook cap is 1 s.
    w.hookMode.answer = async (hook) => {
      const t = w.bridge.ctx.table;
      if (hook === "check" && t) w.bridge.ctx.swapTable({ ...t, config: { ...t.config, workflowGrantsWithdrawn: [{ sub: SUB, wfl: WFL, at: now() }] } as typeof t.config });
      return undefined;
    };
    try {
      const ops = w.appLog.ops.length;
      const r = await call(token, { workflow: WFL });
      assert.equal(r.status, 403, r.text);
      assert.equal(r.json?.error.code, "workflow_grant_withdrawn");
      assert.equal(w.appLog.ops.length, ops, "the app is not called");
    } finally {
      w.hookMode.answer = undefined;
      await applied(await w.publish());
    }
    m = mark();
    routed(await call(token, { workflow: WFL }), m);
  });
});

describe("C373 P1 C4: withdrawal reaches the next call within one config revision (OLD cached grant, 14 min left)", () => {
  test("record path: workflowGrantsWithdrawn {sub, wfl, aud, at} → refused; other workflow / target / instance / older record → quiet", async () => {
    const token = await workflowGrant(WFL); // iat = now − 60 → 14 min left
    const iat = now() - 60;
    let m = mark();
    routed(await call(token, { workflow: WFL }), m);
    // quiet: records that do not cover this grant
    await withConfig({
      workflowGrantsWithdrawn: [
        { sub: SUB, wfl: OTHER, at: now() },
        { sub: SUB, wfl: WFL, aud: "tb:ins:ins_01HQQQQQQQQQQQQQQQQQQQQQQQ", at: now() },
        { sub: "tb:ins:ins_01HQQQQQQQQQQQQQQQQQQQQQQQ", wfl: WFL, at: now() },
        { sub: SUB, wfl: WFL, at: iat - 120 },
      ],
    });
    m = mark();
    routed(await call(token, { workflow: WFL }), m);
    // fire: the record for this (sub, wfl, aud) — refused as soon as THIS revision is applied
    await withConfig({ workflowGrantsWithdrawn: [{ sub: SUB, wfl: WFL, aud: SUB, at: now() }] });
    m = mark();
    await refused(await call(token, { workflow: WFL }), 403, "workflow_grant_withdrawn", m);
    // fire: a record without aud covers every target
    await withConfig({ workflowGrantsWithdrawn: [{ sub: SUB, wfl: WFL, at: now() }] });
    m = mark();
    await refused(await call(token, { workflow: WFL }), 403, "workflow_grant_withdrawn", m);
    // a grant minted after the withdrawal (re-approved) passes while the record is still listed
    const fresh = await workflowGrant(WFL, ["notes_list"], { iat: now() + 1 });
    m = mark();
    routed(await call(fresh, { workflow: WFL }), m);
    await applied(await w.publish());
  });

  test("epoch path: wflEpoch[sub] ≥ iat → refused; an epoch of another instance or before iat → quiet", async () => {
    const token = await workflowGrant(WFL);
    const iat = now() - 60;
    await withConfig({ wflEpoch: { "tb:ins:ins_01HQQQQQQQQQQQQQQQQQQQQQQQ": now(), [SUB]: iat - 120 } });
    let m = mark();
    routed(await call(token, { workflow: WFL }), m);
    await withConfig({ wflEpoch: { [SUB]: now() } });
    m = mark();
    await refused(await call(token, { workflow: WFL }), 403, "workflow_grant_withdrawn", m);
    await applied(await w.publish());
    m = mark();
    routed(await call(token, { workflow: WFL }), m);
  });

  test("B-WFL.withdrawn_record / withdrawn_epoch boundary: at = iat is refused, at = iat − 1 accepted; epoch = iat refused, iat − 1 accepted", async () => {
    const iat = now() - 120;
    const token = await workflowGrant(WFL, ["notes_list"], { iat });
    const token2 = await workflowGrant(OTHER, ["notes_list"], { iat });
    for (const [fields, code] of [
      [{ workflowGrantsWithdrawn: [{ sub: SUB, wfl: WFL, at: iat - 1 }] }, undefined],
      [{ workflowGrantsWithdrawn: [{ sub: SUB, wfl: WFL, at: iat }] }, "workflow_grant_withdrawn"],
      [{ wflEpoch: { [SUB]: iat - 1 } }, undefined],
      [{ wflEpoch: { [SUB]: iat } }, "workflow_grant_withdrawn"],
    ] as const) {
      await withConfig(fields);
      const m = mark();
      const r = await call(token, { workflow: WFL });
      if (code) await refused(r, 403, code, m);
      else routed(r, m);
      // a record for WFL leaves OTHER quiet; the epoch covers every workflow of the caller
      const m2 = mark();
      const r2 = await call(token2, { workflow: OTHER });
      if ("wflEpoch" in fields && code) await refused(r2, 403, code, m2);
      else routed(r2, m2);
    }
    await applied(await w.publish());
  });

  test("fail closed on malformed withdrawal fields; the base grant is never affected", () => {
    const g = { sub: SUB as never, aud: SUB, wfl: WFL, iat: 1000 };
    assert.equal(withdrawalReason({}, g), undefined);
    assert.equal(withdrawalReason({ workflowGrantsWithdrawn: [{ sub: SUB, wfl: WFL, at: 1000 }] } as never, g), "record", "iat = at is withdrawn (iat ≤ at)");
    assert.equal(withdrawalReason({ workflowGrantsWithdrawn: [{ sub: SUB, wfl: WFL, at: 999 }] } as never, g), undefined);
    assert.equal(withdrawalReason({ workflowGrantsWithdrawn: [{ sub: SUB, wfl: WFL, at: "x" }] } as never, g), "record");
    assert.equal(withdrawalReason({ workflowGrantsWithdrawn: {} } as never, g), "record list unreadable");
    assert.equal(withdrawalReason({ wflEpoch: [] } as never, g), "epoch unreadable");
    assert.equal(withdrawalReason({ wflEpoch: { [SUB]: "1" } } as never, g), "epoch");
    assert.equal(withdrawalReason({ wflEpoch: { [SUB]: 1000 } } as never, g), "epoch");
    assert.equal(withdrawalReason({ wflEpoch: { [SUB]: 999 } } as never, g), undefined);
  });

  test("withdrawal records never touch a base-grant call", async () => {
    await withConfig({ workflowGrantsWithdrawn: [{ sub: SUB, wfl: WFL, at: now() }], wflEpoch: { [SUB]: now() } });
    const m = mark();
    routed(await call(base, {}), m);
    await applied(await w.publish());
  });
});

describe("C373 P1 relays: workflow-grants request / get / release", () => {
  const status = { wfl: WFL, state: "requested", title: "Daily digest", applied: null, appliedDigest: null, pending: null, rejectedDigest: null, updatedAt: null };
  const seen = () => w.portalRoutes.seen.length;

  test("B-WFL.relay_ins: Core gets ins = the asserting instance, the rest unchanged, Core's answer passes through; a body member ins → 400 input_invalid /ins, Core not called", async () => {
    w.portalRoutes.answer = (path) => (path === "/api/v1/bridge/workflow-grants/request" ? { status: 202, body: { status } } : undefined);
    const body = { wfl: WFL, title: "Daily digest", targets: [{ product: "notes", ops: ["notes_list"], crud: ["read"] }], reason: "summarise" };
    const r = await signedPost(a, WORKFLOW_GRANT_PATHS.workflowGrantRequest, body);
    assert.equal(r.status, 202, r.text);
    assert.deepEqual(r.json, { status });
    assert.deepEqual(w.portalRoutes.seen.at(-1), { path: "/api/v1/bridge/workflow-grants/request", body: { ...body, ins: INS } });
    for (const path of Object.values(WORKFLOW_GRANT_PATHS)) {
      const n = seen();
      for (const ins of ["ins_01HQQQQQQQQQQQQQQQQQQQQQQQ", INS, null]) {
        const bad = await signedPost(a, path, { ...body, ins });
        assert.equal(bad.status, 400, bad.text);
        assert.equal(bad.json?.error.code, "input_invalid");
        assert.equal(bad.json?.error.details?.pointer, "/ins");
      }
      assert.equal(seen(), n, "Core is not called");
    }
  });

  test("get: the minted grant and Core's refusals (410 workflow_grant_withdrawn) pass through", async () => {
    w.portalRoutes.answer = (_p, b) => (b.aud ? { status: 200, body: { status: { ...status, state: "applied" }, grant: "a.b.c" } } : { status: 410, body: { error: { code: "workflow_grant_withdrawn", message: "withdrawn", requestId: "r" } } });
    let r = await signedPost(a, WORKFLOW_GRANT_PATHS.workflowGrantGet, { wfl: WFL, aud: INS });
    assert.equal(r.status, 200, r.text);
    assert.equal(r.json?.grant, "a.b.c");
    assert.deepEqual(w.portalRoutes.seen.at(-1), { path: "/api/v1/bridge/workflow-grants/get", body: { wfl: WFL, aud: INS, ins: INS } });
    r = await signedPost(a, WORKFLOW_GRANT_PATHS.workflowGrantGet, { wfl: WFL });
    assert.equal(r.status, 410, r.text);
    assert.equal(r.json?.error.code, "workflow_grant_withdrawn");
  });

  test("a Core answer without a readable body → 503 portal_unavailable, retryable (no answer is invented)", async () => {
    w.portalRoutes.answer = undefined;
    const r = await signedPost(a, WORKFLOW_GRANT_PATHS.workflowGrantRelease, { wfl: WFL });
    assert.equal(r.status, 503, r.text);
    assert.equal(r.json?.error.code, "portal_unavailable");
    assert.equal(r.text.includes(WFL), false);
  });

  test("auth: a wrong instance key, an assertion for another path, no assertion → 401; Core is never called", async () => {
    const stranger = { ins: INS, key: await w.api.generateKeyPair() };
    const n = seen();
    let r = await signedPost(stranger, WORKFLOW_GRANT_PATHS.workflowGrantRequest, { wfl: WFL });
    assert.equal(r.status, 401, r.text);
    r = await signedPost(a, WORKFLOW_GRANT_PATHS.workflowGrantRelease, { wfl: WFL }, { signPath: WORKFLOW_GRANT_PATHS.workflowGrantGet });
    assert.equal(r.status, 401, r.text);
    const plain = await fetch(`${w.internalUrl}${WORKFLOW_GRANT_PATHS.workflowGrantGet}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ wfl: WFL }) });
    assert.equal(plain.status, 401);
    await plain.body?.cancel();
    assert.equal(seen(), n, "Core is not called");
  });

  test("auth: a companion service of the instance is refused 403 no_grant; Core is never called", async () => {
    const svc = await claimApp(w, { code: SVC_CODE, service: "engine" });
    assert.equal(svc.claimStatus, 200);
    const n = seen();
    const r = await signedPost({ ins: INS, key: svc.key }, WORKFLOW_GRANT_PATHS.workflowGrantRequest, { wfl: WFL }, { svc: "engine" });
    assert.equal(r.status, 403, r.text);
    assert.equal(r.json?.error.code, "no_grant");
    assert.equal(seen(), n, "Core is not called");
  });

  test("a body without a workflow id → 400 input_invalid /wfl; Core is never called", async () => {
    const n = seen();
    for (const body of [{ wfl: "Bad" }, {}, [1]]) {
      const r = await signedPost(a, WORKFLOW_GRANT_PATHS.workflowGrantGet, body);
      assert.equal(r.status, 400, r.text);
      assert.equal(r.json?.error.code, "input_invalid");
    }
    assert.equal(seen(), n);
  });

  test("B-WFL.relay_ins paused: all three relays are refused 403 paused before Core (the owner revokes in Portal); resumed → relayed", async () => {
    w.portalRoutes.answer = () => ({ status: 200, body: { status: { ...status, state: "withdrawn" } } });
    await withConfig({ pause: { workspace: false, agents: [], instances: [INS] } });
    const n = seen();
    for (const path of Object.values(WORKFLOW_GRANT_PATHS)) {
      const r = await signedPost(a, path, { wfl: WFL });
      assert.equal(r.status, 403, r.text);
      assert.equal(r.json?.error.code, "paused");
    }
    assert.equal(seen(), n, "Core is not called while paused");
    await applied(await w.publish());
    const r = await signedPost(a, WORKFLOW_GRANT_PATHS.workflowGrantRelease, { wfl: WFL });
    assert.equal(r.status, 200, r.text);
    assert.deepEqual(w.portalRoutes.seen.at(-1), { path: "/api/v1/bridge/workflow-grants/release", body: { wfl: WFL, ins: INS } });
  });

  test("the relay bucket (WORKFLOW_GRANT_RELAY_LIMIT, separate from calls) answers 429 + Retry-After when spent", async () => {
    w.portalRoutes.answer = () => ({ status: 200, body: { status } });
    // all at once, so the refill (4 per second) cannot keep up even on a slow runner
    const answers = await Promise.all(Array.from({ length: 90 }, () => signedPost(a, WORKFLOW_GRANT_PATHS.workflowGrantGet, { wfl: WFL })));
    const limited = answers.find((r) => r.status === 429);
    assert.ok(limited, "the bucket ran out within 90 requests");
    assert.equal(limited.json?.error.code, "rate_limited");
    assert.ok(Number(limited.retryAfter) >= 1, "Retry-After is set");
    // the call path has its own bucket
    const m = mark();
    routed(await call(base, {}), m);
  });
});

describe("C373 P1 app caps (BRIDGE §8.6 rule 7): AppStatus.caps → StatusReport.apps[].caps", () => {
  const reported = () => w.acks.at(-1)?.apps.find((x) => x.ins === INS) as ({ caps?: string[] } & Record<string, unknown>) | undefined;
  const settled = async (want: string[] | undefined) => {
    const n = w.acks.length;
    await waitFor(() => w.acks.length > n && JSON.stringify(reported()?.caps) === JSON.stringify(want), 15000);
  };

  test("B-WFL.app_caps_reported: the push's caps are normalised (unknown dropped, sorted, no duplicates) and reported; a change reaches Portal", async () => {
    assert.ok([200, 204].includes(await a.status({ caps: ["grant_wfl", "app_workflow_grants", "grant_wfl", "future_cap"] })));
    await settled(["app_workflow_grants", "grant_wfl"]);
    assert.ok([200, 204].includes(await a.status({ caps: [] })));
    await settled([]);
  });

  test("B-WFL.app_caps_reported: a malformed caps push is omitted (fail closed); a held-back older push does not overwrite", async () => {
    assert.ok([200, 204].includes(await a.status({ caps: ["app_workflow_grants"] })));
    await settled(["app_workflow_grants"]);
    for (const bad of ["app_workflow_grants", { 0: "grant_wfl" }, Array.from({ length: 17 }, () => "grant_wfl"), ["x".repeat(33)], [7]]) {
      assert.ok([200, 204].includes(await a.status({ caps: bad })));
      await settled(undefined);
      assert.equal("caps" in (reported() ?? {}), false, "omitted, not []");
      assert.ok([200, 204].includes(await a.status({ caps: ["grant_wfl"] })));
      await settled(["grant_wfl"]);
    }
    // a push signed 20 s ago arrives after a newer one: ignored
    assert.ok([200, 204].includes(await a.status({ caps: [] }, { age: 20 })));
    assert.deepEqual(w.bridge.ctx.appCaps.get(INS as never), ["grant_wfl"]);
  });

  test("the pure rules: limits are APP_CAPS_LIMITS (16 entries of ≤ 32 chars)", () => {
    assert.deepEqual(normaliseAppCaps(Array.from({ length: 16 }, () => "person_op")), ["person_op"]);
    assert.equal(normaliseAppCaps(Array.from({ length: 17 }, () => "person_op")), undefined);
    assert.deepEqual(normaliseAppCaps(["x".repeat(32)]), []);
    assert.equal(normaliseAppCaps(undefined), undefined);
  });
});
