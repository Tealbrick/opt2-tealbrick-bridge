/**
 * Hooks and the call kinds they do not cover or must cover (Rules review F1, F2):
 *
 * F2: MANIFEST §16 (Hooks): "Hooks match only `agent`-audience manifest operations reached through the bridge; never standard `tb.*`
 * ops, person ops or hook calls." A listed, enabled wildcard before hook (`products: ["*"]`, no `operations`) that denies everything
 * must NOT run on a standard op: the call answers 200 and the hook app receives no request. A declared hook that the config does not
 * list must not refuse a standard op `hook_failed` either. A normal agent op is the positive control: the same hook still refuses it.
 *
 * F1: a companion (app-initiated) call runs the full hook chain: a before hook refuses it `hook_denied` (the op is never forwarded to
 * the target app), and an after hook's redaction or withholding applies to the app caller's answer.
 */
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import { CallRouter, eventHookMatches } from "../src/calls.ts";
import { type AppClient, claimApp } from "./support/app-client.ts";
import { AGT, BRG, CON, HOOKINS, INS, makeWorld, type World, WS, waitFor } from "./support/world.ts";

const now = () => Math.floor(Date.now() / 1000);
/** the guard app answers context and after hooks with a no-op; `audit` is replaced per test */
let auditAnswer: unknown = {};
const answers = (hook: string) => (hook === "enrich" ? { add: {} } : hook === "audit" ? auditAnswer : undefined);

describe("hooks vs standard ops (F2) and the companion path (F1)", () => {
  let w: World;
  let a: AppClient;
  let grant: string;

  const target = (id: string) => {
    const app = w.bridge.ctx.table?.apps.get(INS as never);
    const op = app?.ops.get(id);
    assert.ok(app && op, `${id} is in the target's op table`);
    return { app, op };
  };
  const agentCall = (id: string, input: unknown = {}) => new CallRouter(w.bridge.ctx).route({ caller: { type: "agent", agt: AGT as never, con: CON as never }, target: target(id), input: input as never });
  const companion = async (op: string, input: unknown = {}) => {
    const raw = Buffer.from(JSON.stringify({ target: "notes", op, input }));
    const assertion = await w.api.signAssertion("tb-instance-assert+jwt", { iss: `tb:ins:${INS}`, sub: `tb:ins:${INS}`, aud: `tb:brg:${BRG}`, iat: now(), exp: now() + 60, jti: w.api.ulid() }, a.key, { method: "POST", pathAndQuery: "/tb/v1/call", body: raw });
    const r = await fetch(`${w.internalUrl}/tb/v1/call`, { method: "POST", headers: { "content-type": "application/json", "TB-Assert": assertion, "TB-Grant": grant }, body: raw });
    const text = await r.text();
    return { status: r.status, text, json: JSON.parse(text) as Record<string, any> };
  };
  const mark = () => ({ ops: w.appLog.ops.length, hooks: w.appLog.hooks.length });
  const refusedWith = async (p: Promise<unknown>, code: string, why: string) => {
    await assert.rejects(p, (e: { code?: string }) => e.code === code, why);
  };
  /** republish with the guard's `check` hook matching `match` (the declared match in the guard manifest stays `notes`) */
  const setCheckMatch = async (match: { products: string[] }) => {
    await w.publish((c) => {
      for (const h of c.hooks) {
        if (h.ins === HOOKINS) delete (h as { enabled?: boolean }).enabled;
        if (h.ins === HOOKINS && h.hookId === "check") (h as { match: unknown }).match = match;
      }
      (c.apps[0] as { slice: string }).slice = slice;
    });
    const rev = w.rev();
    await waitFor(() => w.bridge.ctx.table?.rev === rev && w.bridge.ctx.table?.apps.get(INS as never)?.down === false, 15000);
  };
  let slice: string;

  before(async () => {
    w = await makeWorld({ real: true, withHook: true });
    a = await claimApp(w);
    assert.equal(a.claimStatus, 200);
    grant = await w.signPortal("tb-grant+jwt", { iss: "tb:portal", sub: `tb:ins:${INS}`, aud: `tb:ins:${INS}`, iat: now(), exp: now() + 3600, jti: w.api.ulid(), ws: WS, cnf: { brg: BRG }, crud: ["read"], mode: "bound", held: [], caps: {}, wf: ["notes_list", "tb.holds_pending"], polrev: 1 });
    slice = await w.signPortal("tb-slice+jws", { v: 1, iss: "tb:portal", sub: `tb:ins:${INS}`, aud: `tb:ins:${INS}`, iat: now(), exp: now() + 43200, jti: w.api.ulid(), ws: WS, rev: 2, ins: INS, product: "notes", grants: [grant] });
    // the owner switches the declared context and after hooks on (they are listed with enabled:false by default)
    await setCheckMatch({ products: ["notes"] });
    await waitFor(() => w.bridge.ctx.table?.hooks.every((h) => h.enabled !== false) === true, 15000);
    w.hookMode.mode = "allow";
    w.hookMode.answer = answers;
  });
  after(async () => {
    w.hookMode.answer = undefined;
    await w.close();
  });

  describe("F1: companion calls and the hook chain", () => {
    test("a before hook that denies refuses a companion call hook_denied; the op never reaches the target app", async () => {
      // positive control: with the hook allowing, the same call reaches the app
      let m = mark();
      const ok = await companion("notes_list");
      assert.equal(ok.status, 200, ok.text);
      assert.equal(w.appLog.ops.length, m.ops + 1, "allowed: forwarded");
      w.hookMode.mode = "deny";
      try {
        m = mark();
        const r = await companion("notes_list");
        assert.equal(r.status, 403, r.text);
        assert.equal(r.json.error.code, "hook_denied");
        assert.equal(w.appLog.ops.length, m.ops, "denied: the op is not forwarded");
        assert.deepEqual(w.appLog.hooks.slice(m.hooks).map((h) => h.body.phase), ["before"], "the chain stopped at the refusing before hook");
        const seen = w.appLog.hooks.at(-1)?.body.call as { caller: { type: string } } | undefined;
        assert.equal(seen?.caller.type, "app", "the hook saw an app caller");
      } finally {
        w.hookMode.mode = "allow";
      }
    });

    test("an after hook's redaction applies to the app caller's answer", async () => {
      auditAnswer = { redactions: ["/secret"] };
      try {
        const m = mark();
        const r = await companion("notes_list");
        assert.equal(r.status, 200, r.text);
        assert.equal(w.appLog.ops.length, m.ops + 1, "the app answered");
        assert.deepEqual(w.appLog.hooks.slice(m.hooks).map((h) => h.body.phase), ["before", "context", "after"]);
        assert.equal("secret" in r.json.output, false, `redacted: ${r.text}`);
        assert.deepEqual(r.json.output.items, [1, 2], "the rest of the output is kept");
        assert.equal(r.text.includes("s3cret"), false, "the value is nowhere in the answer");
      } finally {
        auditAnswer = {};
      }
    });

    test("an after hook that answers badly withholds the output from the app caller (after_failed)", async () => {
      auditAnswer = { redactions: "not-a-list" };
      try {
        const m = mark();
        const r = await companion("notes_list");
        assert.equal(r.status, 503, r.text);
        assert.equal(r.json.error.code, "after_failed");
        assert.equal(w.appLog.ops.length, m.ops + 1, "the op ran at the app (the hook gap is after the fact)");
        assert.equal(r.text.includes("s3cret"), false, "the output is withheld");
      } finally {
        auditAnswer = {};
      }
    });
  });

  describe("F2: hooks never match standard tb.* ops (MANIFEST §16)", () => {
    before(async () => {
      // a listed, enabled wildcard before hook (no `operations`) that denies everything it is asked about
      await setCheckMatch({ products: ["*"] });
      assert.deepEqual(w.bridge.ctx.table?.hooks.find((h) => h.hookId === "check")?.match, { products: ["*"] });
      w.hookMode.mode = "deny";
    });
    after(async () => {
      w.hookMode.mode = "allow";
      await setCheckMatch({ products: ["notes"] });
    });

    test("an agent call of every agent-audience standard op answers ok and the hook app receives no hook request", async () => {
      // person-audience standard ops are refused for every caller by the gate (audience_not_agent), so they never reach a hook
      const standard = [...(w.bridge.ctx.table?.apps.get(INS as never)?.ops.values() ?? [])].filter((o) => o.standard && o.audience === "agent");
      const ids = standard.map((o) => o.id as string);
      assert.ok(ids.includes("tb.holds_pending") && ids.includes("tb.hold_status"), `agent standard ops: ${ids.join(", ")}`);
      for (const id of ids) {
        const m = mark();
        const r = await agentCall(id, id === "tb.hold_status" ? { holdId: "hold_1" } : {});
        assert.equal(r.result.status, "ok", id);
        assert.equal(w.appLog.hooks.length, m.hooks, `${id}: no hook request`);
        assert.equal(w.appLog.ops.length, m.ops + 1, `${id}: forwarded`);
      }
    });

    test("a companion call of a standard op answers 200 and no hook runs", async () => {
      const m = mark();
      const r = await companion("tb.holds_pending");
      assert.equal(r.status, 200, r.text);
      assert.equal(w.appLog.hooks.length, m.hooks);
      assert.equal(w.appLog.ops.length, m.ops + 1);
    });

    test("positive control: the same deny hook still refuses a normal agent op, and the app is not called", async () => {
      const m = mark();
      await refusedWith(agentCall("notes_list"), "hook_denied", "notes_list");
      assert.equal(w.appLog.hooks.length, m.hooks + 1, "the hook was asked");
      assert.equal(w.appLog.ops.length, m.ops, "not forwarded");
    });

    test("event rule 6 (eventHookMatches) agrees: a wildcard hook covers notes_list, not a standard op", () => {
      const t = w.bridge.ctx.table;
      assert.ok(t);
      const app = target("notes_list").app;
      assert.equal(eventHookMatches(t, app, target("notes_list").op), true);
      assert.equal(eventHookMatches(t, app, target("tb.holds_pending").op), false);
      assert.equal(eventHookMatches(t, app, target("tb.holds_list").op), false, "person-audience standard op");
    });
  });

  describe("F2: a declared but unlisted wildcard hook", () => {
    test("does not refuse a standard op hook_failed; a normal agent op is still refused (positive control)", async () => {
      w.hookMode.mode = "allow";
      const guard = w.bridge.ctx.table?.apps.get(HOOKINS as never);
      assert.ok(guard);
      const before = guard.declaredHooks;
      // declared by the guard manifest, absent from config.hooks
      guard.declaredHooks = [...before, { id: "wild", title: "Wild", phase: "before", order: 9, match: { products: ["*"] } }];
      try {
        const m = mark();
        const r = await agentCall("tb.holds_pending");
        assert.equal(r.result.status, "ok");
        assert.equal(w.appLog.hooks.length, m.hooks, "no hook ran");
        await refusedWith(agentCall("notes_list"), "hook_failed", "notes_list: declared hook not listed");
        const t = w.bridge.ctx.table;
        assert.ok(t);
        assert.equal(eventHookMatches(t, target("tb.holds_pending").app, target("tb.holds_pending").op), false, "events: no summary hook for a standard op");
      } finally {
        guard.declaredHooks = before;
      }
    });
  });
});
