/**
 * Bridge 0.2.5 (spec 0.1.54, C292 / C292a): `StatusReport.bridge.caps`. The bridge declares ONLY what it implements:
 * `owner_rows` = the C283 A1 owner-row filter; `events` (bridge 0.2.7, spec 0.1.57) = all of BRIDGE §14 (app events); `hook_tool`
 * (spec 0.1.68) = BRIDGE v0.1.68 hook target tool. `secret_output` waits for the manifest re-pin (C354). Core copies the set into the slices; a standalone bridge writes it into
 * the slices it re-mints itself. Caps are advisory and never widen access.
 *
 * The cap list is a constant in caps.ts, tied to its feature by a probe per entry (below): a cap whose behaviour is
 * missing fails its probe, and a cap without a probe fails the coverage test. A build without the A1 code path would
 * fail the `owner_rows` probe while its constant still said `owner_rows`, so the change that removes A1 has to remove
 * the entry.
 */
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { after, before, describe, test } from "node:test";
import { fileURLToPath } from "node:url";
import { BRIDGE_CAPS } from "@opt2-tealbrick/spec/bridge";
import { APP_HOLD_STATUS_MIN_SDK } from "../src/app-calls.ts";
import { CallRouter } from "../src/calls.ts";
import { BRIDGE_CAPS_DECLARED } from "../src/caps.ts";
import { buildStatusReport } from "../src/portal.ts";
import { trustFor } from "../src/table.ts";
import { visibleOps } from "../src/tools.ts";
import { AGT, BRG, CON, INS, makeWorld, type World, WS, waitFor } from "./support/world.ts";

const now = () => Math.floor(Date.now() / 1000);

/** one probe per cap: true when the build really has the behaviour the cap names */
const PROBES: Record<string, (w: World) => Promise<void>> = {
  // spec 0.1.68 (BRIDGE v0.1.68): a dynamic call whose resolution names another tool is refused; the canonical one runs. The
  // hook `target.tool` on all three paths is c336-hook-tool-secret.test.ts (B29.*)
  hook_tool: async (w) => {
    const app = w.bridge.ctx.table?.apps.get(INS as never);
    const op = app?.ops.get("notes_list");
    assert.ok(app && op);
    const dyn = { ...op, dynamic: { mode: "list", crudCeiling: ["read"], effectCeiling: "read" } } as never;
    const router = new CallRouter(w.bridge.ctx);
    const call = (tool: string) => router.route({ caller: { type: "agent", agt: AGT as never, con: CON as never }, target: { app, op: dyn, tool }, input: { tool, arguments: {} } as never });
    w.bridgeOps.answer = (path, body) => (path === "resolve" ? { tool: String(body.tool).toLowerCase(), crud: ["read"], effect: "read" } : undefined);
    try {
      await assert.rejects(call("Probe_Tool"), (e: unknown) => (e as { code?: string }).code === "dynamic_resolve_failed");
      assert.equal((await call("probe_tool")).result.status, "ok");
    } finally {
      w.bridgeOps.answer = undefined;
    }
  },
  events: async (w) => {
    assert.ok(w.bridge.ctx.events, "the event log is open");
    const r = await fetch(`${w.internalUrl}/tb/v1/events`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ items: [] }) });
    await r.body?.cancel();
    assert.equal(r.status, 401);
    const token = await w.agentToken();
    const init = await w.mcp(token, { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "caps" } } });
    for (const method of ["tealbrick/events/list", "tealbrick/events/poll", "tealbrick/events/stream"]) {
      const a = await w.mcp(token, { jsonrpc: "2.0", id: 2, method, params: {} }, init.session ?? undefined);
      assert.ok(a.json?.result && !a.json.error, `${method}: ${JSON.stringify(a.json)}`);
    }
  },
  // BRIDGE §15 (bridge 0.2.9): the resolve route answers (unauthenticated → 401, not 404), the status report carries
  // `roles[]`, and the key page is "Keys and models"; the full behaviour is model-roles.test.ts and persona.test.ts
  model_roles: async (w) => {
    const r = await fetch(`${w.internalUrl}/tb/v1/model-roles/reasoning`);
    await r.body?.cancel();
    assert.equal(r.status, 401);
    assert.ok(Array.isArray((buildStatusReport(w.bridge.ctx) as { roles?: unknown }).roles));
    const ticket = await w.signPortal("tb-ticket+jwt", { iss: "tb:portal", sub: "tb:per:per_01HPPPPPPPPPPPPPPPPPPPPPPP", aud: `tb:brg:${BRG}`, iat: now(), exp: now() + 120, jti: w.api.ulid(), ws: WS, pur: "keys" });
    const page = await fetch(`${w.keysUrl}/keys`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ ticket }) });
    assert.match(await page.text(), /<h1 id="h">Keys and models<\/h1>[\s\S]*Provider keys/);
  },
  // spec 0.1.77 (BRIDGE v0.1.77 §8.3, C367 P3): tb.hold_status for an APP caller needs the op in the companion grant's wf and a target
  // that reports an sdkVersion >= APP_HOLD_STATUS_MIN_SDK; otherwise not_in_workflow. The full behaviour is c367-app-hold-status-context.test.ts
  app_hold_status: async (w) => {
    const t = w.bridge.ctx.table;
    const app = t?.apps.get(INS as never);
    const op = app?.ops.get("tb.hold_status");
    assert.ok(t && app && op);
    const grantWith = (wf: string[]) => w.signPortal("tb-grant+jwt", { iss: "tb:portal", sub: `tb:ins:${INS}`, aud: `tb:ins:${INS}`, iat: now(), exp: now() + 3600, jti: w.api.ulid(), ws: WS, cnf: { brg: BRG }, crud: ["read"], mode: "bound", held: [], caps: {}, wf, polrev: 1, prd: "notes" });
    const call = async (wf: string[]) => new CallRouter(w.bridge.ctx).route({ caller: { type: "app", ins: INS as never, grant: await grantWith(wf) }, target: { app, op }, input: { holdId: "hold_1" } });
    const refused = (e: unknown) => (e as { code?: string }).code === "not_in_workflow";
    try {
      w.bridge.ctx.health.delete(INS as never);
      await assert.rejects(call(["tb.hold_status"]), refused, "an unknown sdkVersion is refused");
      w.bridge.ctx.health.set(INS as never, { status: { sdkVersion: APP_HOLD_STATUS_MIN_SDK, version: app.entry.version } as never, lastSeen: now() }); // QA-BR29-1: a push of the named version
      await assert.rejects(call(["notes_list"]), refused, "not in wf");
      assert.equal((await call(["tb.hold_status"])).result.status, "ok");
    } finally {
      w.bridge.ctx.health.delete(INS as never);
    }
  },
  // spec 0.1.77 (BRIDGE v0.1.77 §8.5, C367 P4): a companion context is checked against the grant's prd, merged into the op body
  // `context`, and refused 400 input_invalid when it breaks a rule. The full behaviour is c367-app-hold-status-context.test.ts
  app_call_context: async (w) => {
    const t = w.bridge.ctx.table;
    const app = t?.apps.get(INS as never);
    const op = app?.ops.get("notes_list");
    assert.ok(t && app && op);
    const grant = await w.signPortal("tb-grant+jwt", { iss: "tb:portal", sub: `tb:ins:${INS}`, aud: `tb:ins:${INS}`, iat: now(), exp: now() + 3600, jti: w.api.ulid(), ws: WS, cnf: { brg: BRG }, crud: ["read"], mode: "bound", held: [], caps: {}, wf: ["notes_list"], polrev: 1, prd: "notes" });
    const call = (callerContext: unknown) => new CallRouter(w.bridge.ctx).route({ caller: { type: "app", ins: INS as never, grant }, target: { app, op }, input: {}, callerContext });
    const before = w.appLog.ops.length;
    await call({ "notes.run": "run_1" });
    assert.deepEqual(w.appLog.ops[before]?.body.context, { "notes.run": "run_1" });
    await assert.rejects(call({ "kanban.card": 1 }), (e: unknown) => (e as { code?: string; details?: { pointer?: string } }).code === "input_invalid" && (e as { details?: { pointer?: string } }).details?.pointer === "/context/kanban.card");
    assert.equal(w.appLog.ops.length, before + 1, "the refused call was not forwarded");
  },
  owner_rows: async (w) => {
    const t = w.bridge.ctx.table;
    const app = t?.apps.get(INS as never);
    assert.ok(t && app);
    const scoped: Record<string, unknown> = { standard: false, id: "p_scoped", title: "p", description: "p", crud: ["update"], effect: "write", idempotency: "none", receipt: true, audience: "agent", scopeType: "notebook" };
    const { scopeType: _scopeType, ...unscopedBase } = scoped;
    const unscoped: Record<string, unknown> = { ...unscopedBase, id: "p_unscoped" };
    const probeApp = { ...app, ops: new Map([["p_scoped", scoped], ["p_unscoped", unscoped]]) } as never;
    const token = await w.signPortal("tb-grant+jwt", { iss: "tb:portal", sub: `tb:agt:${AGT}`, aud: `tb:ins:${INS}`, iat: now(), exp: now() + 3600, jti: w.api.ulid(), ws: WS, cnf: { brg: BRG }, crud: ["read"], mode: "free", held: [], caps: {}, wf: [], polrev: 1 });
    const v = w.api.verifyGrant(token, trustFor(t, INS as never, now()));
    assert.ok("claims" in v && v.ok);
    // (1) without the app's mark an op above the grant is not listed; with it, only the SCOPED one is
    assert.deepEqual(visibleOps(w.bridge.ctx, probeApp, v.claims).map((o) => o.id), []);
    assert.deepEqual(visibleOps(w.bridge.ctx, probeApp, v.claims, new Set(["p_scoped", "p_unscoped"])).map((o) => o.id), ["p_scoped"]);
    // (2) gate() passes the scoped op above grant.crud on to the SDK and keeps the ceiling for the unscoped one
    const gate = (op: unknown) => w.bridge.ctx.api.gate({ paused: { workspace: false, agent: false, connection: false, instance: false }, grant: token, trust: trustFor(t, INS as never, now()), op, declaredScopeTypes: ["notebook"] } as never);
    assert.equal(gate(scoped).decision, "pass");
    assert.equal(gate(unscoped).reason, "crud_exceeds_grant");
  },
};

describe("StatusReport.bridge.caps (spec 0.1.54, C292)", () => {
  let w: World;
  before(async () => {
    w = await makeWorld({ real: true });
    await waitFor(() => w.acks.length > 0 && w.bridge.ctx.table?.rev === w.rev(), 15000);
  });
  after(async () => {
    await w.close();
  });

  test("the bridge declares exactly owner_rows, events, model_roles, hook_tool, app_hold_status and app_call_context (secret_output waits for the manifest re-pin, C354), and only values the spec knows", () => {
    assert.deepEqual([...BRIDGE_CAPS_DECLARED], ["owner_rows", "events", "model_roles", "hook_tool", "app_hold_status", "app_call_context"]);
    assert.equal((BRIDGE_CAPS_DECLARED as readonly string[]).includes("secret_output"), false, "C354: not before the bridge pins a validator that accepts secretOutput");
    for (const c of BRIDGE_CAPS_DECLARED) assert.ok((BRIDGE_CAPS as readonly string[]).includes(c), `${c} is in the spec BRIDGE_CAPS`);
  });

  test("every status report carries the caps: the ones Portal received and a freshly built one", async () => {
    // a second revision and a health change produce more reports
    await w.publish();
    await waitFor(() => w.acks.some((a) => a.rev === w.rev()), 15000);
    assert.ok(w.acks.length >= 2, `reports received: ${w.acks.length}`);
    for (const a of w.acks) assert.deepEqual(a.bridge.caps, ["owner_rows", "events", "model_roles", "hook_tool", "app_hold_status", "app_call_context"], `report rev ${a.rev}`);
    assert.deepEqual(buildStatusReport(w.bridge.ctx).bridge.caps, ["owner_rows", "events", "model_roles", "hook_tool", "app_hold_status", "app_call_context"]);
    // a copy: changing a report never changes what the next one says
    (buildStatusReport(w.bridge.ctx).bridge.caps as string[]).push("x");
    assert.deepEqual(buildStatusReport(w.bridge.ctx).bridge.caps, ["owner_rows", "events", "model_roles", "hook_tool", "app_hold_status", "app_call_context"]);
  });

  test("every declared cap has a probe, and the probe passes (the behaviour the cap names exists in this build)", async () => {
    assert.deepEqual([...BRIDGE_CAPS_DECLARED].sort(), Object.keys(PROBES).sort(), "a cap without a probe, or a probe without a cap");
    for (const c of BRIDGE_CAPS_DECLARED) await (PROBES[c] as (w: World) => Promise<void>)(w);
  });

  test("the cap strings appear in one place only (caps.ts); no other source file names a capability", () => {
    const dir = fileURLToPath(new URL("../src/", import.meta.url));
    for (const f of readdirSync(dir).filter((n) => n.endsWith(".ts") && n !== "caps.ts")) {
      const text = readFileSync(`${dir}${f}`, "utf8");
      assert.ok(!/["'](owner_rows|events|model_roles|hook_tool|app_hold_status|app_call_context|secret_output)["']/.test(text), `${f} must take the caps from caps.ts`);
    }
  });
});

describe("standalone bridge: slice.bridge.caps from its own set (spec 0.1.54)", () => {
  let w: World;
  before(async () => {
    w = await makeWorld({ real: true });
    await waitFor(() => w.bridge.ctx.table?.rev === w.rev(), 15000);
  });
  after(async () => {
    await w.close();
  });

  test("a re-minted slice carries caps = the bridge's own set, whatever the Portal-signed slice said", async () => {
    const owner = await w.api.generateKeyPair();
    const id = w.bridge.ctx.identity;
    assert.ok(id);
    const standalone = { issuer: w.bridge.ctx.bridgeRef, kid: w.api.thumbprint(id.key.publicJwk), ownerKeys: [owner.publicJwk] };
    const t0 = w.bridge.ctx.table;
    assert.ok(t0);
    const finalSlices = new Map<string, string>();
    for (const a of t0.config.apps) {
      const claims = JSON.parse(Buffer.from(a.slice.split(".")[1] as string, "base64url").toString("utf8")) as Record<string, unknown>;
      // Core's slice claims `caps: []` here (an older set); the standalone bridge overrides it
      finalSlices.set(a.ins, await w.signPortal("tb-slice+jws", { ...claims, iat: now(), jti: w.api.ulid(), rev: Number(claims.rev ?? 1) + 1, standalone, bridge: { id: BRG, keys: [id.key.publicJwk], caps: ["old_cap"] } }));
    }
    await w.publish((c) => {
      (c as { standalone?: unknown }).standalone = standalone;
      for (const a of c.apps) a.slice = (finalSlices.get(a.ins) ?? a.slice) as never;
    });
    await waitFor(() => w.bridge.ctx.table?.standalone === true && w.bridge.ctx.table?.config.iss === w.bridge.ctx.bridgeRef, 15000);
    const slice = w.bridge.ctx.table?.config.apps.find((a) => a.ins === INS)?.slice as string;
    const claims = JSON.parse(Buffer.from(slice.split(".")[1] as string, "base64url").toString("utf8")) as { bridge?: { id?: string; keys?: unknown[]; caps?: string[] } };
    assert.deepEqual(claims.bridge?.caps, ["owner_rows", "events", "model_roles", "hook_tool", "app_hold_status", "app_call_context"]);
    assert.equal(claims.bridge?.id, BRG, "the rest of the bridge member is kept");
    assert.equal(claims.bridge?.keys?.length, 1);
  });
});
