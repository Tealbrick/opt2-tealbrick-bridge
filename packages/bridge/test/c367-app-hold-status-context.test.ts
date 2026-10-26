/**
 * Bridge 0.2.11 / spec 0.1.77 (C367 P3, P4; BRIDGE v0.1.77 §8.3 and §8.5; CONFORMANCE v0.1.77 rows B31 and B32, bridge side):
 *
 * P3, cap `app_hold_status` (B31.*):
 * - the own route: `tb.hold_status` on the companion path runs when the presented grant's `wf` lists it (the I4 CRUD skip applies:
 *   a grant with no `read` still passes it), and the app's answer, a `404 hold_not_found` included (errata 1), is passed through;
 * - undeclared (`wf` without it) → `not_in_workflow`, the app is never called;
 * - target gate (PK-D6): a target whose last reported `sdkVersion` is below APP_HOLD_STATUS_MIN_SDK, malformed, or never reported
 *   → `not_in_workflow`, the target is not called;
 * - an agent call of the same op is unchanged (no `wf` rule, no sdkVersion gate).
 *
 * P4, cap `app_call_context` (B32.*):
 * - a valid context reaches the app body `context` (and the before hook), the op proof's `ctx` digest covers it (the SDK's own
 *   `verifyCallProof` accepts the delivered body and refuses the same body after a tamper);
 * - a foreign key, a `tb.` key, a context over 2048 bytes (exactly 2048 passes), no verified product with a non-empty context,
 *   or a context that is not an object → 400 `input_invalid` with `details.pointer`; the app and the hooks are not called; the
 *   message never repeats a value; the product is the grant's `prd`, never the envelope;
 * - `{}` and absent add nothing; the context is informational (a gate refusal wins, nothing else reads it);
 * - context hooks: another product's hook cannot write a caller key, a hook of the caller's own product may overwrite one.
 */
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import { verifyCallProof } from "@opt2-tealbrick/manifest";
import type { Ed25519KeyPair } from "@opt2-tealbrick/spec/sdk";
import { APP_HOLD_STATUS_MIN_SDK, sdkVersionAtLeast } from "../src/app-calls.ts";
import { CallRouter } from "../src/calls.ts";
import { type AppClient, claimApp } from "./support/app-client.ts";
import { AGT, BRG, CON, HOOKINS, INS, makeWorld, type World, WS, waitFor } from "./support/world.ts";

const now = () => Math.floor(Date.now() / 1000);
const G_CODE = "tbe_guardinstancecode";
const LEAK = "VALUE-MUST-NOT-ECHO-7c1e";

// Two worlds (one per group): app-initiated calls are limited per instance (120/min, burst 30, internal.ts), and each group stays under it.
let w: World;
let a: AppClient; // instance INS, product notes (caller A, and the target)
let g: AppClient; // instance HOOKINS, product guard (caller G, a hook app of product guard)
const grants = { hs: "", hsNoCrud: "", plain: "", noPrd: "", guard: "" };
const jtis = new Map<string, string>();
/** the guard app's hook answers: before allows, the context hook adds `add`, the after hook changes nothing */
const answers = (add: Record<string, unknown> = {}) => (hook: string) => (hook === "enrich" ? { add } : hook === "audit" ? {} : undefined);

const mint = async (sub: string, wf: string[], extra: Record<string, unknown> = {}) => {
  const jti = w.api.ulid();
  const token = await w.signPortal("tb-grant+jwt", { iss: "tb:portal", sub: `tb:ins:${sub}`, aud: `tb:ins:${INS}`, iat: now(), exp: now() + 3600, jti, ws: WS, cnf: { brg: BRG }, crud: ["read"], mode: "bound", held: [], caps: {}, wf, polrev: 1, ...extra });
  jtis.set(token, jti);
  return token;
};

/** one world per group: registers its before/after (the variables above belong to the group that runs) */
function useWorld(): void {
  before(async () => {
    w = await makeWorld({ real: true, withHook: true });
    await waitFor(() => w.bridge.ctx.table?.rev === w.rev(), 15000);
    grants.hs = await mint(INS, ["notes_list", "notes_send", "tb.hold_status"], { prd: "notes", crud: ["read", "create"] });
    // no `read` in crud: the I4 skip of gate() lets tb.hold_status pass on a valid grant, notes_list still needs `read`
    grants.hsNoCrud = await mint(INS, ["notes_list", "tb.hold_status"], { prd: "notes", crud: ["create"] });
    grants.plain = await mint(INS, ["notes_list", "notes_send"], { prd: "notes", crud: ["read", "create"] });
    grants.noPrd = await mint(INS, ["notes_list", "tb.hold_status"]);
    grants.guard = await mint(HOOKINS, ["notes_list", "tb.hold_status"], { prd: "guard" });
    const slice = (ins: string, product: string, list: string[]) =>
      w.signPortal("tb-slice+jws", { v: 1, iss: "tb:portal", sub: `tb:ins:${ins}`, aud: `tb:ins:${ins}`, iat: now(), exp: now() + 43200, jti: w.api.ulid(), ws: WS, rev: 2, ins, product, grants: list });
    const sliceA = await slice(INS, "notes", [grants.hs, grants.hsNoCrud, grants.plain, grants.noPrd]);
    const sliceG = await slice(HOOKINS, "guard", [grants.guard]);
    await w.publish((c) => {
      for (const app of c.apps) (app as { slice: string }).slice = app.ins === INS ? sliceA : sliceG;
      // every hook of the guard app on (the world lists its context and after hooks switched off)
      for (const h of c.hooks) if (h.ins === HOOKINS) delete (h as { enabled?: boolean }).enabled;
      c.enrolCodes.push({ digest: w.api.opaqueDigest(G_CODE), kind: "instance", ins: HOOKINS as never, product: "guard", exp: now() + 3600 } as never);
    });
    await waitFor(() => w.bridge.ctx.table?.rev === w.rev() && w.bridge.ctx.table?.apps.get(INS as never)?.down === false && w.bridge.ctx.table?.apps.get(HOOKINS as never)?.down === false && w.bridge.ctx.table?.hooks.every((h) => h.enabled !== false) === true, 15000);
    a = await claimApp(w, { sdkVersion: "0.1.40" });
    g = await claimApp(w, { code: G_CODE, ins: HOOKINS });
    assert.equal(a.claimStatus, 200);
    assert.equal(g.claimStatus, 200);
    w.hookMode.mode = "allow";
    w.hookMode.answer = answers();
  });
  after(async () => {
    w.hookMode.answer = undefined;
    w.appOps.override = undefined;
    await w.close();
  });
}

const companion = async (who: { ins: string; key: Ed25519KeyPair }, grant: string, envelope: Record<string, unknown>) => {
  const raw = Buffer.from(JSON.stringify({ target: "notes", ...envelope }));
  const assertion = await w.api.signAssertion("tb-instance-assert+jwt", { iss: `tb:ins:${who.ins}`, sub: `tb:ins:${who.ins}`, aud: `tb:brg:${BRG}`, iat: now(), exp: now() + 60, jti: w.api.ulid() }, who.key, { method: "POST", pathAndQuery: "/tb/v1/call", body: raw });
  const r = await fetch(`${w.internalUrl}/tb/v1/call`, { method: "POST", headers: { "content-type": "application/json", "TB-Assert": assertion, "TB-Grant": grant }, body: raw });
  const text = await r.text();
  return { status: r.status, text, json: text ? (JSON.parse(text) as Record<string, any>) : undefined };
};
const callA = (grant: string, envelope: Record<string, unknown>) => companion(a, grant, envelope);
const holdStatus = (grant: string) => callA(grant, { op: "tb.hold_status", input: { holdId: "hold_1" } });
const list = (grant: string, context?: unknown) => callA(grant, { op: "notes_list", input: {}, ...(context !== undefined ? { context } : {}) });
const reported = async (sdkVersion: string) => assert.ok([200, 204].includes(await a.status({ sdkVersion })), "status accepted");

/** counters of everything the call must NOT have reached */
const mark = () => ({ ops: w.appLog.ops.length, hooks: w.appLog.hooks.length });
const untouched = (m: { ops: number; hooks: number }, why: string) => {
  assert.equal(w.appLog.ops.length, m.ops, `${why}: the app is not called`);
  assert.equal(w.appLog.hooks.length, m.hooks, `${why}: no hook ran`);
};
const lastOp = () => w.appLog.ops[w.appLog.ops.length - 1] as (typeof w.appLog.ops)[number];
const payloadOf = (jws: string) => JSON.parse(Buffer.from(jws.split(".")[1] as string, "base64url").toString("utf8")) as Record<string, unknown>;

describe("sdkVersionAtLeast (the target gate's comparison)", () => {
  test("the reserved constant, and semver order with fail-closed edges", () => {
    assert.equal(APP_HOLD_STATUS_MIN_SDK, "0.1.41");
    for (const ok of ["0.1.41", "0.1.42", "0.1.100", "0.2.0", "1.0.0", "0.1.41+build.5", "0.1.42-rc.1"]) assert.equal(sdkVersionAtLeast(ok, "0.1.41"), true, ok);
    for (const no of ["0.1.40", "0.1.9", "0.0.99", "0.1.41-rc.1", "banana", "", "0.1", "1", "0.1.41.1", undefined, null, 41, {}]) assert.equal(sdkVersionAtLeast(no, "0.1.41"), false, String(no));
  });
});

describe("C367 P3: tb.hold_status for an app caller (B31)", () => {
  useWorld();
  test("B31.hold_status_old_target: a target that has not reported an sdkVersion yet is unknown → refused, never called", async () => {
    const m = mark();
    const r = await holdStatus(grants.hs);
    assert.equal(r.status, 403, r.text);
    assert.equal(r.json?.error.code, "not_in_workflow");
    untouched(m, "no status pushed yet");
  });

  test("B31.hold_status_old_target: a target that reports a lower, an unreadable or a prerelease sdkVersion is refused, never called", async () => {
    for (const v of ["0.1.40", "0.1.41-rc.1", "banana"]) {
      await reported(v);
      const m = mark();
      const r = await holdStatus(grants.hs);
      assert.equal(r.status, 403, `${v}: ${r.text}`);
      assert.equal(r.json?.error.code, "not_in_workflow", v);
      untouched(m, v);
    }
  });

  test("B31.hold_status_own: the target reports 0.1.41 → the call is routed and the app's answer is the result", async () => {
    await reported("0.1.41");
    const m = mark();
    const r = await holdStatus(grants.hs);
    assert.equal(r.status, 200, r.text);
    assert.deepEqual(r.json, { status: "ok", output: { status: "pending" } });
    assert.equal(w.appLog.ops.length, m.ops + 1, "forwarded once");
    assert.equal(lastOp().op, "tb.hold_status");
    assert.deepEqual(lastOp().body.input, { holdId: "hold_1" });
  });

  test("B31.hold_status_own: a later sdkVersion (and a re-report that goes back down) decides on the LAST report", async () => {
    await reported("0.2.0");
    assert.equal((await holdStatus(grants.hs)).status, 200);
    await reported("0.1.40");
    assert.equal((await holdStatus(grants.hs)).json?.error?.code, "not_in_workflow");
    await reported("0.1.41");
    assert.equal((await holdStatus(grants.hs)).status, 200);
  });

  test("B31.hold_status_undeclared: a grant whose wf does not list tb.hold_status → not_in_workflow, the app never sees it", async () => {
    const m = mark();
    const r = await holdStatus(grants.plain);
    assert.equal(r.status, 403, r.text);
    assert.equal(r.json?.error.code, "not_in_workflow");
    untouched(m, "undeclared");
    // the same grant still runs the ops it lists
    assert.equal((await list(grants.plain)).status, 200);
  });

  test("the I4 CRUD skip applies: a valid grant without `read` passes tb.hold_status, an op of the same wf above its crud does not", async () => {
    const r = await holdStatus(grants.hsNoCrud);
    assert.equal(r.status, 200, r.text);
    const above = await list(grants.hsNoCrud);
    assert.equal(above.status, 403, above.text);
    assert.equal(above.json?.error.code, "crud_exceeds_grant");
  });

  test("errata 1: the app's `404 hold_not_found` (an unknown or not-owned hold) reaches the caller unchanged", async () => {
    w.appOps.override = (op, _b, res) => {
      if (op !== "tb.hold_status") return false;
      res.writeHead(404, { "content-type": "application/json" }).end(JSON.stringify({ status: "error", error: { code: "hold_not_found", message: "No such hold." } }));
      return true;
    };
    try {
      const r = await holdStatus(grants.hs);
      assert.equal(r.status, 404, r.text);
      assert.equal(r.json?.error.code, "hold_not_found");
      assert.equal(r.json?.error.message, "No such hold.");
      assert.equal(r.text.includes("hold_1"), false, "the id is not echoed");
    } finally {
      w.appOps.override = undefined;
    }
  });

  test("an agent call of tb.hold_status is unchanged: no wf rule and no sdkVersion gate (the target reports 0.1.0)", async () => {
    await reported("0.1.0");
    const t = w.bridge.ctx.table;
    const app = t?.apps.get(INS as never);
    const op = app?.ops.get("tb.hold_status");
    assert.ok(app && op);
    const router = new CallRouter(w.bridge.ctx);
    const m = mark();
    const out = await router.route({ caller: { type: "agent", agt: AGT as never, con: CON as never }, target: { app, op }, input: { holdId: "hold_1" } });
    assert.equal(out.result.status, "ok");
    assert.equal(w.appLog.ops.length, m.ops + 1);
    await reported("0.1.41");
  });
});

describe("C367 P4: caller context on a companion call (B32)", () => {
  useWorld();
  const CTX = { "notes.workflow": "wf_1", "notes.version": 3, "notes.run": "run_1", "notes.step": "step_1" };

  test("B32.context_reaches_target: the four keys are in the op body context and in the before hook; the op proof binds them", async () => {
    const m = mark();
    const r = await list(grants.hs, CTX);
    assert.equal(r.status, 200, r.text);
    assert.equal(w.appLog.ops.length, m.ops + 1);
    const op = lastOp();
    assert.deepEqual(op.body.context, CTX);
    const before = w.appLog.hooks.slice(m.hooks).find((h) => h.body.phase === "before");
    assert.deepEqual(before?.body.context, CTX, "the before hook sees the caller keys");
    // the app's own verifier (the manifest library the SDK uses): the delivered body verifies, the same body tampered after signing is refused
    const t = w.bridge.ctx.table;
    assert.ok(t && op.proof);
    const trust = { now: now(), self: `tb:ins:${INS}`, ws: t.ws, bridge: t.bridgeId, issuers: t.issuers, bridgeKeys: t.bridgeKeys, revokedJtis: t.revokedJtis } as never;
    const bind = (context: unknown) => ({ op: "notes_list", inputDigest: w.api.digest({} as never), contextDigest: w.api.digest(context as never), grantJti: jtis.get(grants.hs) as never });
    assert.equal(payloadOf(op.proof).ctx, w.api.digest(CTX as never), "ctx = digest of the delivered context");
    assert.equal(verifyCallProof(op.proof, trust, bind(op.body.context)).ok, true, "untampered");
    assert.equal(verifyCallProof(op.proof, trust, bind({ ...CTX, "notes.run": "run_2" })).ok, false, "B32.context_tampered: a changed value");
    assert.equal(verifyCallProof(op.proof, trust, bind({ ...CTX, "notes.extra": 1 })).ok, false, "B32.context_tampered: an added key");
    assert.equal(verifyCallProof(op.proof, trust, bind({})).ok, false, "B32.context_tampered: dropped");
  });

  test("`{}` and an absent context add nothing: the body context is `{}` and the proof binds `{}`", async () => {
    for (const context of [undefined, {}]) {
      const r = await list(grants.hs, context);
      assert.equal(r.status, 200, r.text);
      const op = lastOp();
      assert.deepEqual(op.body.context, {});
      assert.equal(payloadOf(op.proof as string).ctx, w.api.digest({} as never));
    }
  });

  test("B32.context_foreign_key: a key of another product → 400 input_invalid, pointer /context/<key>, nothing called, the value is not echoed", async () => {
    const m = mark();
    const r = await list(grants.hs, { "notes.run": "run_1", "kanban.card": LEAK });
    assert.equal(r.status, 400, r.text);
    assert.equal(r.json?.error.code, "input_invalid");
    assert.deepEqual(r.json?.error.details, { pointer: "/context/kanban.card" });
    assert.equal(r.text.includes(LEAK), false, "the message never repeats a value");
    untouched(m, "foreign key");
  });

  test("B32.context_tb_key: a tb. key from an app → pointer /context/tb.onBehalfOf", async () => {
    const m = mark();
    const r = await list(grants.hs, { "tb.onBehalfOf": { kind: "person", id: LEAK } });
    assert.equal(r.status, 400, r.text);
    assert.deepEqual(r.json?.error.details, { pointer: "/context/tb.onBehalfOf" });
    assert.equal(r.text.includes(LEAK), false);
    untouched(m, "tb key");
  });

  test("B32.context_too_large: JCS of 2049 bytes → pointer /context, exactly 2048 passes; an oversized context with a bad key answers /context", async () => {
    // JCS of {"notes.blob":"<n x>"} is n + 17 bytes
    const blob = (n: number) => ({ "notes.blob": "x".repeat(n) });
    assert.equal(Buffer.byteLength(JSON.stringify(blob(2031))), 2048);
    const ok = await list(grants.hs, blob(2031));
    assert.equal(ok.status, 200, ok.text);
    const m = mark();
    const big = await list(grants.hs, blob(2032));
    assert.equal(big.status, 400, big.text);
    assert.deepEqual(big.json?.error.details, { pointer: "/context" });
    const bad = await list(grants.hs, { ...blob(2032), "kanban.card": 1 });
    assert.deepEqual(bad.json?.error.details, { pointer: "/context" }, "rule 2 before rule 3");
    untouched(m, "too large");
  });

  test("the rules run in the spec's order: a bad key wins over a deep value; depth 3 passes, depth 4 → /context/<key>", async () => {
    assert.equal((await list(grants.hs, { "notes.deep": { a: { b: [1] } } })).status, 200, "depth 3 under the key");
    const deep = await list(grants.hs, { "notes.deep": { a: { b: { c: [1] } } } });
    assert.equal(deep.status, 400);
    assert.deepEqual(deep.json?.error.details, { pointer: "/context/notes.deep" });
    const both = await list(grants.hs, { "notes.deep": { a: { b: { c: [1] } } }, "kanban.x": 1 });
    assert.deepEqual(both.json?.error.details, { pointer: "/context/kanban.x" });
  });

  test("not a JSON object (array, string, null) → pointer /context", async () => {
    const m = mark();
    for (const context of [["notes.run"], "notes.run", null]) {
      const r = await list(grants.hs, context);
      assert.equal(r.status, 400, JSON.stringify(context));
      assert.deepEqual(r.json?.error.details, { pointer: "/context" }, JSON.stringify(context));
    }
    untouched(m, "not an object");
  });

  test("no verified product: a grant without prd refuses a non-empty context (/context); `{}` and absent still run", async () => {
    const m = mark();
    const r = await callA(grants.noPrd, { op: "notes_list", input: {}, context: { "notes.run": "run_1" } });
    assert.equal(r.status, 400, r.text);
    assert.deepEqual(r.json?.error.details, { pointer: "/context" });
    untouched(m, "no prd");
    assert.equal((await callA(grants.noPrd, { op: "notes_list", input: {}, context: {} })).status, 200);
    assert.equal((await callA(grants.noPrd, { op: "notes_list", input: {} })).status, 200);
  });

  test("the product is the grant's prd, never the envelope: an envelope naming another product changes nothing", async () => {
    const m = mark();
    const r = await callA(grants.hs, { op: "notes_list", input: {}, product: "kanban", prd: "kanban", caller: { product: "kanban" }, context: { "kanban.card": 1 } });
    assert.equal(r.status, 400, r.text);
    assert.deepEqual(r.json?.error.details, { pointer: "/context/kanban.card" });
    untouched(m, "envelope product");
    // and the grant's own product is accepted whatever the envelope says
    assert.equal((await callA(grants.hs, { op: "notes_list", input: {}, product: "kanban", context: { "notes.card": 1 } })).status, 200);
  });

  test("informational only: a gate refusal wins over the context (valid or not), and the context never changes a decision", async () => {
    const m = mark();
    const undeclared = await callA(grants.plain, { op: "tb.hold_status", input: { holdId: "hold_1" }, context: { "notes.run": "r" } });
    assert.equal(undeclared.json?.error.code, "not_in_workflow");
    const badToo = await callA(grants.plain, { op: "tb.hold_status", input: { holdId: "hold_1" }, context: { "kanban.x": 1 } });
    assert.equal(badToo.json?.error.code, "not_in_workflow", "the gate runs first");
    untouched(m, "gate refusal");
    // a held call is held by the app and forwarded the same with or without a context
    const plain = await callA(grants.hs, { op: "notes_send", input: {}, idempotencyKey: "k-ctx-1" });
    const withCtx = await callA(grants.hs, { op: "notes_send", input: {}, idempotencyKey: "k-ctx-2", context: CTX });
    assert.equal(plain.status, 202, plain.text);
    assert.equal(withCtx.status, 202, withCtx.text);
    assert.equal(withCtx.json?.status, "held");
  });

  test("an agent call carries no caller context: the op body context stays `{}` (the field is companion-only)", async () => {
    await reported("0.1.41");
    const t = w.bridge.ctx.table;
    const app = t?.apps.get(INS as never);
    const op = app?.ops.get("notes_list");
    assert.ok(app && op);
    const router = new CallRouter(w.bridge.ctx);
    await router.route({ caller: { type: "agent", agt: AGT as never, con: CON as never }, target: { app, op }, input: {}, callerContext: { "notes.run": "run_1" } });
    assert.deepEqual(lastOp().body.context, {});
  });

  test("hooks: another product's context hook cannot write a caller key (hook_failed, nothing forwarded); its own namespace still works", async () => {
    w.hookMode.answer = answers({ "notes.run": "forged" });
    try {
      const m = mark();
      const r = await list(grants.hs, CTX);
      assert.equal(r.status, 503, r.text);
      assert.equal(r.json?.error.code, "hook_failed");
      assert.equal(w.appLog.ops.length, m.ops, "not forwarded");
      w.hookMode.answer = answers({ "guard.note": "mine" });
      const ok = await list(grants.hs, CTX);
      assert.equal(ok.status, 200, ok.text);
      assert.deepEqual(lastOp().body.context, { ...CTX, "guard.note": "mine" });
    } finally {
      w.hookMode.answer = answers();
    }
  });

  test("hooks: a context hook of the caller's own product may overwrite a caller key; the proof binds the final context", async () => {
    const GCTX = { "guard.run": "run_1", "guard.step": "s1" };
    w.hookMode.answer = answers({ "guard.run": "run_2" });
    try {
      const m = mark();
      const r = await companion(g, grants.guard, { op: "notes_list", input: {}, context: GCTX });
      assert.equal(r.status, 200, r.text);
      const op = lastOp();
      assert.deepEqual(op.body.context, { "guard.run": "run_2", "guard.step": "s1" });
      const hooks = w.appLog.hooks.slice(m.hooks);
      assert.deepEqual(hooks.find((h) => h.body.phase === "before")?.body.context, GCTX, "the before hook saw the caller's original keys");
      assert.deepEqual(hooks.find((h) => h.body.phase === "context")?.body.context, GCTX);
      assert.equal(payloadOf(op.proof as string).ctx, w.api.digest({ "guard.run": "run_2", "guard.step": "s1" } as never));
    } finally {
      w.hookMode.answer = answers();
    }
  });

  test("hold status and context together: tb.hold_status with a context is routed, the context is informational", async () => {
    await reported("0.1.41");
    const r = await callA(grants.hs, { op: "tb.hold_status", input: { holdId: "hold_1" }, context: CTX });
    assert.equal(r.status, 200, r.text);
    assert.deepEqual(lastOp().body.context, CTX);
  });
});
