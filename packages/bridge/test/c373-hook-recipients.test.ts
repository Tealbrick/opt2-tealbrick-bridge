/**
 * spec next (unreleased; C373, G-6; BRIDGE "hook recipients", cap `hook_recipients`; CONFORMANCE B34 rows, bridge part):
 * - B34.static_op: an outward static op with places → every hook phase sees `call.target.recipients` read from THIS input
 *   (canonical, de-duplicated, sorted); agent and app callers see the same.
 * - B34.dynamic_op: a dynamic tool whose (cached) resolution names places in `arguments` → the same, on `<op>_call` over MCP and on
 *   the companion path.
 * - B34.known_none / B34.incomplete / B34.absent: `[]`; a bad value or > 64 → `recipientsIncomplete`; a read op, an outward op
 *   without places and a resolution without places → no `recipients` member. No value appears in a bridge log line.
 * The pinned validator (manifest 0.1.30) refuses a manifest that declares op places, so the static ops are placed into the routing
 * table directly (`// spec next`), as c336-hook-tool-secret.test.ts does for secretOutput.
 */
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import type { OperationView } from "@opt2-tealbrick/spec/sdk";
import { CallRouter } from "../src/calls.ts";
import { jsonLogger } from "../src/util.ts";
import { AGT, APP_CODE, BRG, CON, HOOKINS, INS, makeWorld, notesManifest, type World, WS, waitFor } from "./support/world.ts";

const now = () => Math.floor(Date.now() / 1000);
const CANARY = "canary.person@example.com";
const SLACK = [{ pointer: "/channel", kind: "slack" }];

interface HookTarget {
  op: string;
  tool?: string;
  effect: string;
  recipients?: string[];
  recipientsIncomplete?: true;
}

const tools = {
  id: "notes_tools",
  title: "notes_tools",
  description: "Test op notes_tools",
  crud: ["read"],
  effect: "read",
  idempotency: "supported",
  receipt: false,
  audience: "agent",
  dynamic: { mode: "search", crudCeiling: ["read", "create"], effectCeiling: "outward" },
};
const manifest = { ...notesManifest, version: "1.7.3", operations: [...notesManifest.operations, tools] };

describe("C373: hook recipients (B34, bridge part)", () => {
  let w: World;
  const lines: string[] = [];
  let appKey: Awaited<ReturnType<World["api"]["generateKeyPair"]>>;
  let appGrant: string;
  /** places the app's resolution names for a tool (tool names are unique per test: the bridge caches a resolution 5 min) */
  const places: Record<string, unknown> = {};

  before(async () => {
    w = await makeWorld({ real: true, withHook: true, logger: jsonLogger((l) => lines.push(l)) });
    w.updateAppTo(manifest);
    appKey = await w.api.generateKeyPair();
    await w.publish((c) => {
      for (const h of c.hooks) if (h.ins === HOOKINS) delete (h as { enabled?: boolean }).enabled;
    });
    await waitFor(() => w.bridge.ctx.table?.rev === w.rev() && !!w.bridge.ctx.table?.apps.get(INS as never)?.ops.has("notes_tools") && w.bridge.ctx.table?.hooks.every((h) => h.enabled !== false) === true, 15000);
    const claim = await fetch(`${w.internalUrl}/tb/v1/claim`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ code: APP_CODE, instancePublicKey: appKey.publicJwk, manifestDigest: w.bridge.ctx.table?.config.apps[0]?.manifestDigest, version: manifest.version, sdkVersion: "0.1.41" }),
    });
    assert.equal(claim.status, 200, await claim.text());
    appGrant = await w.signPortal("tb-grant+jwt", { iss: "tb:portal", sub: `tb:ins:${INS}`, aud: `tb:ins:${INS}`, iat: now(), exp: now() + 3600, jti: w.api.ulid(), ws: WS, cnf: { brg: BRG }, crud: ["read", "create"], mode: "bound", held: ["money"], caps: {}, wf: ["notes_list", "notes_tools", "notes_send", "notes_send_to"], polrev: 1 });
    w.hookMode.mode = "allow";
    w.hookMode.answer = (hook) => (hook === "enrich" ? { add: {} } : hook === "audit" ? {} : undefined);
    w.bridgeOps.answer = (path, body) => {
      if (path !== "resolve") return undefined;
      const tool = String(body.tool);
      // `*_famsend` tools resolve as write + holdFamily outward (QA-RCP-7: outward by family)
      const cls = tool.endsWith("_famsend") ? { effect: "write", holdFamily: "outward" } : { effect: "outward", holdFamily: "outward" };
      return { tool, crud: ["create"], ...cls, ...(places[tool] !== undefined ? { recipients: places[tool] } : {}) };
    };
  });
  after(async () => {
    w.hookMode.answer = undefined;
    w.bridgeOps.answer = undefined;
    await w.close();
  });

  const targetsSince = (from: number) => w.appLog.hooks.slice(from).map((h) => ({ phase: h.body.phase as string, target: (h.body.call as { target: HookTarget }).target }));
  const app = () => {
    const a = w.bridge.ctx.table?.apps.get(INS as never);
    assert.ok(a);
    return a;
  };
  const agent = { type: "agent" as const, agt: AGT as never, con: CON as never };

  let mcpSession: { token: string; sid: string } | undefined;
  const mcpCall = async (name: string, args: unknown) => {
    if (!mcpSession) {
      const token = await w.agentToken();
      const init = await w.mcp(token, { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "c373" } } });
      mcpSession = { token, sid: init.session as string };
    }
    const r = await w.mcp(mcpSession.token, { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name, arguments: args } }, mcpSession.sid);
    return r.json.result as { isError?: boolean; structuredContent?: { error?: { code?: string } } };
  };
  const companionCall = async (op: string, input: unknown) => {
    const raw = Buffer.from(JSON.stringify({ target: "notes", op, input }));
    const a = await w.api.signAssertion("tb-instance-assert+jwt", { iss: `tb:ins:${INS}`, sub: `tb:ins:${INS}`, aud: `tb:brg:${BRG}`, iat: now(), exp: now() + 60, jti: w.api.ulid() }, appKey, { method: "POST", pathAndQuery: "/tb/v1/call", body: raw });
    return fetch(`${w.internalUrl}/tb/v1/call`, { method: "POST", headers: { "content-type": "application/json", "TB-Assert": a, "TB-Grant": appGrant }, body: raw });
  };
  /** every phase (before, context, after) saw the same recipient members */
  const expectRecipients = (from: number, want: { recipients?: string[]; recipientsIncomplete?: true }) => {
    const seen = targetsSince(from);
    assert.deepEqual(
      seen.map((s) => s.phase),
      ["before", "context", "after"],
    );
    for (const s of seen) {
      assert.deepEqual({ recipients: s.target.recipients, recipientsIncomplete: s.target.recipientsIncomplete }, { recipients: want.recipients, recipientsIncomplete: want.recipientsIncomplete }, s.phase);
      if (want.recipients === undefined) assert.equal("recipients" in s.target, false, `${s.phase}: absent, not undefined`);
      if (want.recipientsIncomplete === undefined) assert.equal("recipientsIncomplete" in s.target, false, `${s.phase}: no incomplete flag`);
    }
  };
  /** a static op with places, placed into the table for the test (the pinned validator refuses the manifest field) */
  const withStaticOp = async (id: string, base: string, recipients: unknown, fn: (op: OperationView) => Promise<void>) => {
    const ops = app().ops as Map<string, OperationView>;
    const op = { ...(ops.get(base) as OperationView), id, ...(recipients !== undefined ? { recipients } : {}) } as unknown as OperationView; // spec next
    ops.set(id, op);
    try {
      await fn(op);
    } finally {
      ops.delete(id);
    }
  };

  test("B34.static_op: agent caller — places in the input, canonical, de-duplicated, sorted, on every phase; app caller sees the same", async () => {
    const input = { to: ["B@Example.com", "a@example.com", "email:a@example.com"], cc: null, people: { lead: "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6" } };
    const want = { recipients: ["buzz:npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6", "email:a@example.com", "email:b@example.com"] };
    await withStaticOp("notes_send_to", "notes_send", [{ pointer: "/to", kind: "email" }, { pointer: "/cc", kind: "email" }, { pointer: "/people/lead", kind: "buzz" }], async (op) => {
      let from = w.appLog.hooks.length;
      const r = await new CallRouter(w.bridge.ctx).route({ caller: agent, target: { app: app(), op }, input: input as never, idempotencyKey: "c373-static-agent-1" });
      assert.equal(r.result.status, "ok");
      expectRecipients(from, want);
      from = w.appLog.hooks.length;
      const c = await new CallRouter(w.bridge.ctx).route({ caller: { type: "app", ins: INS as never, grant: appGrant }, target: { app: app(), op }, input: input as never, idempotencyKey: "c373-static-app-1" });
      assert.equal(c.result.status, "ok");
      expectRecipients(from, want);
    });
  });

  test("B34.dynamic_op: `<op>_call` over MCP and the companion path — places of the cached resolution, values of THIS call", async () => {
    places.chat_send = SLACK;
    let from = w.appLog.hooks.length;
    const r = await mcpCall("notes__notes_tools_call", { tool: "chat_send", arguments: { channel: "u012abcdef", text: "hi" } });
    assert.notEqual(r.isError, true, JSON.stringify(r));
    expectRecipients(from, { recipients: ["slack:U012ABCDEF"] });
    // the same tool again (resolution cached), other arguments → other recipients: the values are never cached
    from = w.appLog.hooks.length;
    const again = await mcpCall("notes__notes_tools_call", { tool: "chat_send", arguments: { channel: "U0SECOND1" } });
    assert.notEqual(again.isError, true, JSON.stringify(again));
    expectRecipients(from, { recipients: ["slack:U0SECOND1"] });
    from = w.appLog.hooks.length;
    const c = await companionCall("notes_tools", { tool: "chat_send", arguments: { channel: "U012ABCDEF" } });
    assert.equal(c.status, 200, await c.clone().text());
    expectRecipients(from, { recipients: ["slack:U012ABCDEF"] });
  });

  test("B34.dynamic_op: outward by holdFamily (effect write), and telegram chat ids as JSON integers", async () => {
    places.tg_famsend = [{ pointer: "/chat_id", kind: "telegram" }];
    const from = w.appLog.hooks.length;
    const r = await mcpCall("notes__notes_tools_call", { tool: "tg_famsend", arguments: { chat_id: -1001234567890 } });
    assert.notEqual(r.isError, true, JSON.stringify(r));
    expectRecipients(from, { recipients: ["telegram:-1001234567890"] });
  });

  test("B34.known_none: places declared, the input names nobody (empty, null, missing) → []", async () => {
    places.chat_quiet = [{ pointer: "/channel", kind: "slack" }, { pointer: "/users", kind: "slack" }];
    for (const args of [{}, { channel: null }, { users: [] }]) {
      const from = w.appLog.hooks.length;
      const r = await mcpCall("notes__notes_tools_call", { tool: "chat_quiet", arguments: args });
      assert.notEqual(r.isError, true, JSON.stringify(r));
      expectRecipients(from, { recipients: [] });
    }
  });

  test("B34.incomplete: a bad value is dropped and flags the list; more than 64 → the first 64 and the flag; malformed places → [] and the flag", async () => {
    await withStaticOp("notes_send_to", "notes_send", [{ pointer: "/to", kind: "email" }], async (op) => {
      const cases: [unknown, { recipients: string[]; recipientsIncomplete: true }][] = [
        [["Name <x@example.com>", "ok@example.com"], { recipients: ["email:ok@example.com"], recipientsIncomplete: true }],
        [42, { recipients: [], recipientsIncomplete: true }],
        ["telegram:123", { recipients: [], recipientsIncomplete: true }],
      ];
      let n = 0;
      for (const [to, want] of cases) {
        const from = w.appLog.hooks.length;
        await new CallRouter(w.bridge.ctx).route({ caller: agent, target: { app: app(), op }, input: { to } as never, idempotencyKey: `c373-incomplete-${n++}` });
        expectRecipients(from, want);
      }
      const many = Array.from({ length: 65 }, (_, i) => `u${String(i).padStart(3, "0")}@example.com`);
      const from = w.appLog.hooks.length;
      await new CallRouter(w.bridge.ctx).route({ caller: agent, target: { app: app(), op }, input: { to: [...many].reverse() } as never, idempotencyKey: "c373-many" });
      expectRecipients(from, { recipients: many.slice(0, 64).map((a) => `email:${a}`), recipientsIncomplete: true });
    });
    places.chat_badplaces = [{ pointer: "channel", kind: "slack" }];
    const from = w.appLog.hooks.length;
    const r = await mcpCall("notes__notes_tools_call", { tool: "chat_badplaces", arguments: { channel: "U012ABCDEF" } });
    assert.notEqual(r.isError, true, JSON.stringify(r));
    expectRecipients(from, { recipients: [], recipientsIncomplete: true });
  });

  test("B34.absent: a read op (even with places), an outward op without places, a resolution without places → no recipients member", async () => {
    await withStaticOp("notes_list_to", "notes_list", [{ pointer: "/to", kind: "email" }], async (op) => {
      const from = w.appLog.hooks.length;
      await new CallRouter(w.bridge.ctx).route({ caller: agent, target: { app: app(), op }, input: { to: "a@example.com" } as never });
      expectRecipients(from, {});
    });
    // the outward op as the manifest declares it (no places), under a fresh id (the fake app always holds notes_send)
    await withStaticOp("notes_send_plain", "notes_send", undefined, async (op) => {
      const from = w.appLog.hooks.length;
      const plain = await new CallRouter(w.bridge.ctx).route({ caller: agent, target: { app: app(), op }, input: { to: "a@example.com" } as never, idempotencyKey: "c373-absent-1" });
      assert.equal(plain.result.status, "ok");
      expectRecipients(from, {});
    });
    const from = w.appLog.hooks.length;
    const r = await mcpCall("notes__notes_tools_call", { tool: "chat_noplaces", arguments: { channel: "U012ABCDEF" } });
    assert.notEqual(r.isError, true, JSON.stringify(r));
    expectRecipients(from, {});
  });

  test("no bridge log line carries a recipient value (ids, codes and digests only)", async () => {
    places.chat_canary = [{ pointer: "/to", kind: "email" }];
    const from = w.appLog.hooks.length;
    const r = await mcpCall("notes__notes_tools_call", { tool: "chat_canary", arguments: { to: CANARY } });
    assert.notEqual(r.isError, true, JSON.stringify(r));
    expectRecipients(from, { recipients: [`email:${CANARY}`] });
    assert.ok(lines.length > 0, "the logger saw the call");
    for (const l of lines) assert.equal(l.includes(CANARY), false, l);
  });
});
