/**
 * Bridge 0.2.13 / spec 0.1.88 (C378, BRIDGE §8.7; CONFORMANCE v0.1.88 rows B-ACT, bridge side).
 * Source `parent_call`: only the target of an open agent call inherits; a hook app does not. Source `ticket`: minted only during that call,
 * bound to one job and one instance; every failed check refuses the call. Narrow only: a ticket changes no grant.
 * Policy recheck: own op only, gate + before hooks + re-gate, nothing forwarded.
 */
import assert from "node:assert/strict";
import type { ServerResponse } from "node:http";
import { after, before, describe, test } from "node:test";
import { signCompact } from "@opt2-tealbrick/manifest";
import type { Ed25519KeyPair } from "@opt2-tealbrick/spec/sdk";
import { ACTING_TICKET_LIFETIME_S } from "../src/acting.ts";
import { type AppClient, claimApp } from "./support/app-client.ts";
import { AGT, BRG, HOOKINS, INS, makeWorld, type World, WS, waitFor } from "./support/world.ts";

const now = () => Math.floor(Date.now() / 1000);
const G_CODE = "tbe_guardinstancecode";
let w: World;
let a: AppClient;
let g: AppClient;
const grants = { own: "", guard: "" };
const claims = (jws: string) => JSON.parse(Buffer.from(jws.split(".")[1] as string, "base64url").toString("utf8")) as Record<string, unknown>;

const post = async (who: { ins: string; key: Ed25519KeyPair }, path: string, body: unknown, grant?: string) => {
  const raw = Buffer.from(JSON.stringify(body));
  const assertion = await w.api.signAssertion("tb-instance-assert+jwt", { iss: `tb:ins:${who.ins}`, sub: `tb:ins:${who.ins}`, aud: `tb:brg:${BRG}`, iat: now(), exp: now() + 60, jti: w.api.ulid() }, who.key, { method: "POST", pathAndQuery: path, body: raw });
  const r = await fetch(`${w.internalUrl}${path}`, { method: "POST", headers: { "content-type": "application/json", "TB-Assert": assertion, ...(grant ? { "TB-Grant": grant } : {}) }, body: raw });
  const text = await r.text();
  return { status: r.status, json: text ? (JSON.parse(text) as Record<string, any>) : undefined };
};
const call = (who: { ins: string; key: Ed25519KeyPair }, grant: string, env: Record<string, unknown>) => post(who, "/tb/v1/call", { target: "notes", op: "notes_list", input: {}, ...env }, grant);
const mintFor = (who: { ins: string; key: Ed25519KeyPair }, callId: string, job = "run_1") => post(who, "/tb/v1/acting-tickets", { call: callId, job });
const recheck = (who: { ins: string; key: Ed25519KeyPair }, body: unknown) => post(who, "/tb/v1/policy-recheck", body);
/** the guard app's hooks: the before hook allows, the context hook adds nothing, the after hook changes nothing */
const plain = (hook: string) => (hook === "enrich" ? { add: {} } : hook === "audit" ? {} : undefined);
const lastOp = () => w.appLog.ops[w.appLog.ops.length - 1] as (typeof w.appLog.ops)[number];

/** Runs `inner(callId)` while one MCP call from the agent is open on notes_list; returns what it gave back. */
async function duringAgentCall<T>(inner: (callId: string) => Promise<T>): Promise<T> {
  let release: (() => void) | undefined;
  let open: Record<string, unknown> | undefined;
  w.appOps.override = (op: string, b: Record<string, unknown>, res: ServerResponse) => {
    if (op !== "notes_list" || release) return false;
    open = b;
    release = () => res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ status: "ok", output: { items: [] } }));
    return true;
  };
  const token = await w.agentToken();
  const init = await w.mcp(token, { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "0" } } });
  const running = w.mcp(token, { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "notes__notes_list", arguments: {} } }, init.session ?? undefined);
  await waitFor(() => !!release, 10000);
  assert.ok(open);
  const callId = claims(lastOp().proof as string).call as string;
  try {
    return await inner(callId);
  } finally {
    release?.();
    await running;
    w.appOps.override = undefined;
  }
}

describe("acting agents (BRIDGE §8.7)", () => {
  before(async () => {
    w = await makeWorld({ real: true, withHook: true });
    await waitFor(() => w.bridge.ctx.table?.rev === w.rev(), 15000);
    const mint = (sub: string, prd: string) => {
      const wf = ["notes_list"];
      const extra = { prd };
      const jti = w.api.ulid();
    return w.signPortal("tb-grant+jwt", { iss: "tb:portal", sub: `tb:ins:${sub}`, aud: `tb:ins:${INS}`, iat: now(), exp: now() + 3600, jti, ws: WS, cnf: { brg: BRG }, crud: ["read"], mode: "bound", held: [], caps: {}, wf, polrev: 1, ...extra });
    };
    grants.own = await mint(INS, "notes");
    grants.guard = await mint(HOOKINS, "guard");
    const slice = (ins: string, product: string, list: string[]) =>
      w.signPortal("tb-slice+jws", { v: 1, iss: "tb:portal", sub: `tb:ins:${ins}`, aud: `tb:ins:${ins}`, iat: now(), exp: now() + 43200, jti: w.api.ulid(), ws: WS, rev: 2, ins, product, grants: list });
    const sliceA = await slice(INS, "notes", [grants.own]);
    const sliceG = await slice(HOOKINS, "guard", [grants.guard]);
    await w.publish((c) => {
      for (const app of c.apps) (app as { slice: string }).slice = app.ins === INS ? sliceA : sliceG;
      // every hook of the guard app on (the world lists its context and after hooks switched off)
      for (const h of c.hooks) if (h.ins === HOOKINS) delete (h as { enabled?: boolean }).enabled;
      c.enrolCodes.push({ digest: w.api.opaqueDigest(G_CODE), kind: "instance", ins: HOOKINS as never, product: "guard", exp: now() + 3600 } as never);
    });
    await waitFor(() => w.bridge.ctx.table?.rev === w.rev() && w.bridge.ctx.table?.apps.get(INS as never)?.down === false && w.bridge.ctx.table?.apps.get(HOOKINS as never)?.down === false, 15000);
    a = await claimApp(w);
    g = await claimApp(w, { code: G_CODE, ins: HOOKINS });
    assert.equal(a.claimStatus, 200);
    assert.equal(g.claimStatus, 200);
    w.hookMode.mode = "allow";
    w.hookMode.answer = plain;
  });
  after(async () => {
    w.appOps.override = undefined;
    w.hookMode.answer = undefined;
    await w.close();
  });

  test("B-ACT.parent_agent: the target of an open agent call carries that agent; the hook and the app see it, covered by ctx", async () => {
    const hooksBefore = w.appLog.hooks.length;
    const r = await duringAgentCall((callId) => call(a, grants.own, { parentCall: callId }));
    assert.equal(r.status, 200, JSON.stringify(r.json));
    const child = w.appLog.ops.filter((o) => (o.body.context as Record<string, unknown> | undefined)?.["tb.acting"]).at(-1);
    assert.deepEqual((child?.body.context as Record<string, unknown> | undefined)?.["tb.acting"], { v: 1, agents: [{ id: AGT, via: "parent_call" }] });
    const hook = w.appLog.hooks.slice(hooksBefore).find((h) => (h.body.context as Record<string, unknown>)?.["tb.acting"]);
    assert.ok(hook, "a before hook sees tb.acting");
    assert.equal(claims(child?.proof as string).ctx, w.api.digest(child?.body.context as never));
  });

  test("B-ACT.no_parent: an app's own call has no tb.acting", async () => {
    const r = await call(a, grants.own, {});
    assert.equal(r.status, 200);
    assert.equal((lastOp().body.context as Record<string, unknown> | undefined)?.["tb.acting"], undefined);
  });

  test("B-ACT.hook_app_inherits_nothing: a hook app naming the open call gets no agent and no ticket", async () => {
    await duringAgentCall(async (callId) => {
      const r = await call(g, grants.guard, { parentCall: callId });
      assert.equal(r.status, 200, JSON.stringify(r.json));
      assert.equal((lastOp().body.context as Record<string, unknown> | undefined)?.["tb.acting"], undefined);
      const m = await mintFor(g, callId);
      assert.equal(m.status, 403);
      assert.equal(m.json?.error.code, "acting_call_invalid");
    });
  });

  test("B-ACT.reserved: a caller context key tb.acting is refused", async () => {
    const r = await call(a, grants.own, { context: { "tb.acting": { v: 1, agents: [{ id: AGT, via: "ticket" }] } } });
    assert.equal(r.status, 400);
    assert.equal(r.json?.error.code, "input_invalid");
    w.hookMode.answer = (hook: string) => (hook === "enrich" ? { add: { "tb.acting": { v: 1, agents: [] } } } : plain(hook));
    const byHook = await call(a, grants.own, {});
    w.hookMode.answer = plain;
    assert.equal(byHook.status, 503, "a context hook cannot write it");
    assert.equal(byHook.json?.error.code, "hook_failed");
  });

  test("B-ACT.mint and B-ACT.use: a ticket from the open call carries the agent later; after the call no new ticket", async () => {
    let callId = "";
    const m = await duringAgentCall(async (id) => {
      callId = id;
      return mintFor(a, id, "run_1");
    });
    assert.equal(m.status, 200, JSON.stringify(m.json));
    const ticket = ((m.json?.tickets as string[] | undefined) ?? [])[0] as string;
    assert.ok(ticket);
    const c = claims(ticket);
    assert.deepEqual([c.sub, c.aud, c.call, c.op, c.job, (c.exp as number) - (c.iat as number)], [`tb:agt:${AGT}`, `tb:ins:${INS}`, callId, "notes_list", "run_1", ACTING_TICKET_LIFETIME_S]);
    assert.equal(JSON.parse(Buffer.from(ticket.split(".")[0] as string, "base64url").toString("utf8")).typ, "tb-act+jwt");
    const late = await mintFor(a, callId);
    assert.equal(late.status, 403);
    assert.equal(late.json?.error.code, "acting_call_invalid");
    const r = await call(a, grants.own, { acting: { job: "run_1", tickets: [ticket] } });
    assert.equal(r.status, 200, JSON.stringify(r.json));
    assert.deepEqual((lastOp().body.context as Record<string, unknown>)["tb.acting"], { v: 1, agents: [{ id: AGT, via: "ticket", job: "run_1" }] });
  });

  test("B-ACT.refused: each failed check refuses the call and the app is not called; a ticket is no fallback", async () => {
    const m = await duringAgentCall((id) => mintFor(a, id, "run_2"));
    const ticket = ((m.json?.tickets as string[] | undefined) ?? [])[0] as string;
    const bridgeKey = w.bridge.ctx.identity?.key as Ed25519KeyPair;
    const base = claims(ticket as string);
    const forge = (over: Record<string, unknown>, typ = "tb-act+jwt") => signCompact(typ, { ...base, ...over }, bridgeKey, 8192);
    const otherKey = await w.api.generateKeyPair();
    const cases: [string, Record<string, unknown>, string][] = [
      ["job differs", { job: "run_x", tickets: [ticket] }, "job"],
      ["another instance", { job: "run_2", tickets: [await forge({ aud: `tb:ins:${HOOKINS}` })] }, "audience"],
      ["expired", { job: "run_2", tickets: [await forge({ iat: now() - 100, exp: now() - 10 })] }, "expired"],
      ["too long", { job: "run_2", tickets: [await forge({ exp: (base.iat as number) + ACTING_TICKET_LIFETIME_S + 1 })] }, "lifetime"],
      ["typ differs", { job: "run_2", tickets: [await forge({}, "tb-grant+jwt")] }, "signature"],
      ["tampered", { job: "run_2", tickets: [`${(ticket as string).slice(0, -6)}AAAAAA`] }, "signature"],
      ["other signer", { job: "run_2", tickets: [await signCompact("tb-act+jwt", base, otherKey, 8192)] }, "signature"],
      ["left the config", { job: "run_2", tickets: [await forge({ sub: "tb:agt:agt_01H0000000000000000000000X" })] }, "agent_removed"],
      ["five agents", { job: "run_2", tickets: [ticket, ticket, ticket, ticket, ticket] }, "too_many"],
      ["duplicate", { job: "run_2", tickets: [ticket, ticket] }, "duplicate"],
    ];
    for (const [name, acting, reason] of cases) {
      const before = w.appLog.ops.length;
      const r = await call(a, grants.own, { acting });
      assert.equal(r.status, 403, name);
      assert.equal(r.json?.error.code, "acting_ticket_invalid", name);
      assert.equal(r.json?.error.details?.reason, reason, name);
      assert.equal(w.appLog.ops.length, before, `${name}: the app is not called`);
    }
    const bad = await call(a, grants.own, { acting: { job: "not a job", tickets: [ticket] } });
    assert.equal(bad.status, 400);
    const stranger = await call(g, grants.guard, { acting: { job: "run_2", tickets: [ticket] } });
    assert.equal(stranger.status, 403, "another instance's ticket");
  });

  test("B-ACT.no_access: a ticket changes no grant: an op outside wf stays not_in_workflow", async () => {
    const m = await duringAgentCall((id) => mintFor(a, id, "run_3"));
    const r = await call(a, grants.own, { op: "notes_send", idempotencyKey: "k-no-access", acting: { job: "run_3", tickets: m.json?.tickets } });
    assert.equal(r.status, 403);
    assert.ok(["not_in_workflow", "crud_exceeds_grant"].includes(r.json?.error.code), JSON.stringify(r.json));
  });

  test("B-ACT.recheck_verdicts: allow, hold and refuse; nothing reaches the app; context and after hooks do not run; the hook sees tb.recheck", async () => {
    const who = { type: "agent", id: AGT };
    const ops = w.appLog.ops.length;
    const hooks = w.appLog.hooks.length;
    const ok = await recheck(a, { op: "notes_list", input: {}, caller: who });
    assert.deepEqual([ok.status, ok.json], [200, { decision: "allow" }]);
    const seen = w.appLog.hooks.slice(hooks);
    assert.ok(seen.length > 0);
    assert.ok(seen.every((h) => (h.body as { phase?: string }).phase === "before"), "only before hooks");
    assert.equal((seen[0]?.body.context as Record<string, unknown> | undefined)?.["tb.recheck"], true);
    w.hookMode.answer = (hook: string) => (hook === "check" ? { allow: false, reason: "wait", hold: { family: "policy", reason: "wait" } } : plain(hook));
    const held = await recheck(a, { op: "notes_list", input: {}, caller: who });
    assert.equal(held.status, 200, JSON.stringify(held.json));
    assert.equal(held.json?.decision, "hold");
    assert.equal(held.json?.family, "policy");
    w.hookMode.answer = (hook: string) => (hook === "check" ? { allow: false, reason: "no" } : plain(hook));
    const refused = await recheck(a, { op: "notes_list", input: {}, caller: who });
    assert.equal(refused.status, 403);
    assert.equal(refused.json?.error.code, "hook_denied");
    w.hookMode.answer = plain;
    assert.equal(w.appLog.ops.length, ops, "the app was never called");
  });

  test("B-ACT.recheck_own_only: a target field, a person op, an unknown op and a caller with no grant are refused", async () => {
    const who = { type: "agent", id: AGT };
    const ops = w.appLog.ops.length;
    const t = await recheck(a, { target: "guard", op: "notes_list", input: {}, caller: who });
    assert.deepEqual([t.status, t.json?.error.code], [400, "input_invalid"]);
    const u = await recheck(a, { op: "nope", input: {}, caller: who });
    assert.deepEqual([u.status, u.json?.error.code], [404, "unknown_tool"]);
    const n = await recheck(a, { op: "notes_list", input: {}, caller: { type: "agent", id: "agt_01H0000000000000000000000X" } });
    assert.deepEqual([n.status, n.json?.error.code], [403, "no_grant"]);
    // the hook app asks about an op of the notes app: not its own, so not found
    const other = await recheck(g, { op: "notes_list", input: {}, caller: who });
    assert.equal(other.status, 404, JSON.stringify(other.json));
    assert.equal(w.appLog.ops.length, ops);
  });
});
