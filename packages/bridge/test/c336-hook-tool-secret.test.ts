/**
 * Bridge 0.2.8 / spec 0.1.68 (C336 RQ-2, RQ-3; BRIDGE v0.1.68, caps `hook_tool` and `secret_output`; CONFORMANCE v0.1.68 rows):
 * - B29.hook_target_tool_list / _call / _relay: on each dynamic path (a listed entry and `<op>_call` over MCP, a companion
 *   call of a dynamic op on the internal listener) every hook request carries `call.target.tool` = the resolution's canonical
 *   tool and its crud/effect/holdFamily; a static op carries no `tool`. A resolution that names another tool, or a malformed
 *   one, is refused `dynamic_resolve_failed`.
 * - B29.hook_tool_bypass: case, space and alias variants of a tool are refused (never mapped onto the canonical tool).
 * - C-SO-1 (bridge part): a secretOutput call of an APP caller runs no `after` hook, forwards no idempotency key, and no bridge
 *   log line carries the output. Positive control: the same op without the flag runs the after hook and forwards the key.
 * - C-SO-2 (bridge part): a secretOutput op is not listed for agents, and an agent call is refused `secret_output_app_only`
 *   before anything is forwarded.
 * The pinned validator (manifest 0.1.30) refuses a manifest that declares `secretOutput`, so the secret op is placed into the
 * routing table directly (`// spec 0.1.68`).
 */
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import type { OperationView } from "@opt2-tealbrick/spec/sdk";
import { CallRouter } from "../src/calls.ts";
import { jsonLogger } from "../src/util.ts";
import { AGT, APP_CODE, BRG, CON, HOOKINS, INS, makeWorld, notesManifest, type World, WS, waitFor } from "./support/world.ts";

const CANARY = "CANARY-SECRET-5b9d";
const now = () => Math.floor(Date.now() / 1000);

interface HookTarget {
  instance: string;
  product: string;
  op: string;
  tool?: string;
  crud: string[];
  effect: string;
  holdFamily?: string;
}

const dynOp = (id: string, mode: "list" | "search") => ({
  id,
  title: id,
  description: `Test op ${id}`,
  crud: ["read"],
  effect: "read",
  idempotency: "supported",
  receipt: false,
  audience: "agent",
  dynamic: { mode, crudCeiling: ["read", "create"], effectCeiling: "outward" },
});
const manifest = { ...notesManifest, version: "1.6.8", operations: [...notesManifest.operations, dynOp("notes_engine", "list"), dynOp("notes_tools", "search")] };
const ENTRY = { name: "gb_send", title: "Send", description: "Send a message", inputSchema: { type: "object" }, crud: ["create"], effect: "outward", holdFamily: "first_contact" };
const WANT = { instance: INS, product: "notes", tool: "gb_send", crud: ["create"], effect: "outward", holdFamily: "first_contact" };

describe("C336: hook target tool (B29) and secretOutput ops (C-SO-1/2)", () => {
  let w: World;
  const lines: string[] = [];
  let appKey: Awaited<ReturnType<World["api"]["generateKeyPair"]>>;
  let appGrant: string;
  /** what the app's resolve answers for a requested name (default: the canonical name itself) */
  let resolveAs: (requested: string) => string = (t) => t;

  before(async () => {
    w = await makeWorld({ real: true, withHook: true, logger: jsonLogger((l) => lines.push(l)) });
    w.updateAppTo(manifest);
    appKey = await w.api.generateKeyPair();
    await w.publish((c) => {
      for (const h of c.hooks) if (h.ins === HOOKINS) delete (h as { enabled?: boolean }).enabled;
    });
    await waitFor(() => w.bridge.ctx.table?.rev === w.rev() && !!w.bridge.ctx.table?.apps.get(INS as never)?.ops.has("notes_engine") && w.bridge.ctx.table?.hooks.every((h) => h.enabled !== false) === true, 15000);
    const claim = await fetch(`${w.internalUrl}/tb/v1/claim`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ code: APP_CODE, instancePublicKey: appKey.publicJwk, manifestDigest: w.bridge.ctx.table?.config.apps[0]?.manifestDigest, version: manifest.version, sdkVersion: "0.1.39" }),
    });
    assert.equal(claim.status, 200, await claim.text());
    appGrant = await w.signPortal("tb-grant+jwt", { iss: "tb:portal", sub: `tb:ins:${INS}`, aud: `tb:ins:${INS}`, iat: now(), exp: now() + 3600, jti: w.api.ulid(), ws: WS, cnf: { brg: BRG }, crud: ["read", "create"], mode: "bound", held: ["money"], caps: {}, wf: ["notes_list", "notes_tools"], polrev: 1 });
    w.hookMode.mode = "allow";
    w.hookMode.answer = (hook) => (hook === "enrich" ? { add: {} } : hook === "audit" ? {} : undefined);
    w.bridgeOps.answer = (path, body) => (path === "catalog" ? [ENTRY] : path === "resolve" ? { tool: resolveAs(String(body.tool)), crud: ["create"], effect: "outward", holdFamily: "first_contact" } : undefined);
  });
  after(async () => {
    w.hookMode.answer = undefined;
    w.appOps.override = undefined;
    w.bridgeOps.answer = undefined;
    await w.close();
  });

  const hooksSince = (from: number) => w.appLog.hooks.slice(from).map((h) => ({ phase: h.body.phase as string, target: (h.body.call as { target: HookTarget }).target, body: h.body }));
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
      const init = await w.mcp(token, { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "c336" } } });
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
  const expectTool = (seen: ReturnType<typeof hooksSince>, op: string) => {
    assert.deepEqual(
      seen.map((s) => s.phase),
      ["before", "context", "after"],
    );
    for (const s of seen) assert.deepEqual(s.target, { ...WANT, op }, s.phase);
  };

  test("B29.hook_target_tool_list: a listed dynamic entry over MCP — every hook phase sees target.tool and the entry's resolution", async () => {
    resolveAs = (t) => t;
    const from = w.appLog.hooks.length;
    const r = await mcpCall("notes__gb_send", {});
    assert.notEqual(r.isError, true, JSON.stringify(r));
    expectTool(hooksSince(from), "notes_engine");
  });

  test("B29.hook_target_tool_call: `<op>_call` over MCP — target.tool = the resolved tool", async () => {
    resolveAs = (t) => t;
    const from = w.appLog.hooks.length;
    const r = await mcpCall("notes__notes_tools_call", { tool: "gb_send", arguments: {} });
    assert.notEqual(r.isError, true, JSON.stringify(r));
    expectTool(hooksSince(from), "notes_tools");
  });

  test("B29.hook_target_tool_relay: a companion (app→app) call of a dynamic op on the internal listener — target.tool = the resolved tool", async () => {
    resolveAs = (t) => t;
    const from = w.appLog.hooks.length;
    const r = await companionCall("notes_tools", { tool: "gb_send", arguments: {} });
    assert.equal(r.status, 200, await r.clone().text());
    expectTool(hooksSince(from), "notes_tools");
  });

  test("B29: a static op carries no `tool` on any hook phase", async () => {
    const from = w.appLog.hooks.length;
    const r = await mcpCall("notes__notes_list", {});
    assert.notEqual(r.isError, true, JSON.stringify(r));
    const seen = hooksSince(from);
    assert.equal(seen.length, 3);
    for (const s of seen) assert.equal("tool" in s.target, false, s.phase);
  });

  test("B29: a resolution that names another tool, or a malformed one, is refused dynamic_resolve_failed before any hook or forward", async () => {
    // [requested, the app's answer]: a different canonical name, then names that equal the request but are not canonical
    const long = `g${"x".repeat(63)}`; // 64 chars: over the 63 of spec 0.1.68 (catalog names <= 48, resolved variants such as <tool>__first_contact <= 63)
    for (const [requested, answer] of [["gb_m1", "gb_other"], ["Gb_Upper", "Gb_Upper"], ["gb-dash", "gb-dash"], ["g", "g"], [long, long]] as const) {
      resolveAs = () => answer;
      const from = w.appLog.hooks.length;
      const ops = w.appLog.ops.length;
      const r = await mcpCall("notes__notes_tools_call", { tool: requested, arguments: {} });
      assert.equal(r.isError, true, answer);
      assert.equal(r.structuredContent?.error?.code, "dynamic_resolve_failed", answer);
      assert.equal(w.appLog.hooks.length, from, `${answer}: no hook ran`);
      assert.equal(w.appLog.ops.length, ops, `${answer}: nothing forwarded`);
    }
    resolveAs = (t) => t;
  });

  test("BRIDGE23-1 (spec 0.1.68 {1,62}, C354): a resolved variant of 49 and of 63 chars (a 48-char catalog name + `__first_contact`) passes and is the hook target.tool; 64 chars is refused", async () => {
    const base48 = `g${"m".repeat(47)}`;
    const base46 = base48.slice(0, 46);
    for (const [requested, resolved] of [
      [base46, `${base46}__x`],
      [base48, `${base48}__first_contact`],
    ] as const) {
      assert.ok(resolved.length >= 49 && resolved.length <= 63, String(resolved.length));
      resolveAs = () => resolved;
      const from = w.appLog.hooks.length;
      const r = await mcpCall("notes__notes_tools_call", { tool: requested, arguments: {} });
      assert.notEqual(r.isError, true, `${resolved.length} chars: ${JSON.stringify(r)}`);
      const seen = hooksSince(from);
      assert.deepEqual(
        seen.map((x) => x.phase),
        ["before", "context", "after"],
      );
      for (const x of seen) assert.equal(x.target.tool, resolved, `${resolved.length} chars, ${x.phase}`);
    }
    // a fresh requested name (resolutions are cached per requested name)
    const other48 = `h${"m".repeat(47)}`;
    const name64 = `${other48}__first_contact_`;
    assert.equal(name64.length, 64);
    resolveAs = () => name64;
    const from = w.appLog.hooks.length;
    const r = await mcpCall("notes__notes_tools_call", { tool: other48, arguments: {} });
    assert.equal(r.structuredContent?.error?.code, "dynamic_resolve_failed", "64 chars is refused");
    assert.equal(w.appLog.hooks.length, from, "no hook ran");
    resolveAs = (t) => t;
  });

  test("C354: the variant rule is exact — a suffix needs `__`, a variant of a variant or of another tool is refused", async () => {
    for (const [requested, resolved] of [
      // fresh requested names (resolutions are cached per requested name)
      ["vr_a", "vr_ax"],
      ["vr_b", "vr_b__"],
      ["vr_c", "vr_c_first_contact"],
      ["vr_d", "vr_dd__first_contact"],
      ["vr_e__first_contact", "vr_e__first_contact__again"],
    ] as const) {
      resolveAs = () => resolved;
      const r = await mcpCall("notes__notes_tools_call", { tool: requested, arguments: {} });
      assert.equal(r.structuredContent?.error?.code, "dynamic_resolve_failed", `${requested} → ${resolved}`);
    }
    resolveAs = (t) => t;
  });

  test("B29.hook_tool_bypass: case, space and alias variants of a tool the app maps to its canonical name are refused, never run as it", async () => {
    // an app that canonicalises spellings (case-folds, trims, maps an alias) answers the canonical name: the bridge refuses
    resolveAs = (t) => (t.trim().toLowerCase() === "send" ? "gb_send" : t.trim().toLowerCase());
    for (const variant of ["GB_SEND", "Gb_Send", " gb_send", "gb_send ", "send"]) {
      const from = w.appLog.hooks.length;
      const ops = w.appLog.ops.length;
      const r = await mcpCall("notes__notes_tools_call", { tool: variant, arguments: {} });
      assert.equal(r.structuredContent?.error?.code, "dynamic_resolve_failed", JSON.stringify(variant));
      assert.equal(w.appLog.hooks.length, from, `${JSON.stringify(variant)}: no hook ran`);
      assert.equal(w.appLog.ops.length, ops, `${JSON.stringify(variant)}: nothing forwarded`);
    }
    resolveAs = (t) => t;
  });

  test("C-SO-1 (bridge): an app caller — no after hook, no idempotency key forwarded, the caller gets the output, no log line carries it; control: without the flag both happen", async () => {
    const op = app().ops.get("notes_list") as OperationView;
    w.appOps.override = (name, _body, res) => {
      if (name !== "notes_list") return false;
      res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ status: "ok", output: { token: CANARY } }));
      return true;
    };
    const caller = { type: "app" as const, ins: INS as never, grant: appGrant };
    try {
      let from = w.appLog.hooks.length;
      let ops = w.appLog.ops.length;
      const plain = await new CallRouter(w.bridge.ctx).route({ caller, target: { app: app(), op }, input: {} as never, idempotencyKey: "key_plain_000001" });
      assert.equal(plain.result.status, "ok");
      const plainHooks = hooksSince(from);
      assert.deepEqual(
        plainHooks.map((s) => s.phase),
        ["before", "context", "after"],
      );
      assert.ok(JSON.stringify(plainHooks.at(-1)?.body).includes(CANARY), "control: an after hook of a normal op sees the output");
      assert.equal(w.appLog.ops[ops]?.body.idempotencyKey, "key_plain_000001", "control: a normal op forwards the key");

      const secret = { ...op, secretOutput: true } as unknown as OperationView; // spec 0.1.68
      from = w.appLog.hooks.length;
      ops = w.appLog.ops.length;
      const logFrom = lines.length;
      const r = await new CallRouter(w.bridge.ctx).route({ caller, target: { app: app(), op: secret }, input: {} as never, idempotencyKey: "key_secret_00001" });
      assert.equal(r.result.status, "ok");
      assert.deepEqual(r.result.status === "ok" ? r.result.output : null, { token: CANARY }, "the calling app gets the output unchanged");
      assert.deepEqual(
        hooksSince(from).map((s) => s.phase),
        ["before", "context"],
        "no after hook for a secretOutput op",
      );
      assert.equal(w.appLog.ops.length, ops + 1);
      assert.equal("idempotencyKey" in (w.appLog.ops[ops]?.body ?? {}), false, "no idempotency key reaches the app");
      assert.ok(
        lines.slice(logFrom).some((l) => l.includes('"call.app_initiated"') || l.includes('"bridge.call"')),
        "the call is logged (an empty capture cannot pass)",
      );
      assert.deepEqual(
        lines.filter((l) => l.includes(CANARY)),
        [],
        "no bridge log line carries the output",
      );
      const status = JSON.stringify((await import("../src/portal.ts")).buildStatusReport(w.bridge.ctx));
      assert.equal(status.includes(CANARY), false, "no status field carries the output");
    } finally {
      w.appOps.override = undefined;
    }
  });

  test("C-SO-2 (bridge): a secretOutput op is not listed for agents, and an agent call is refused secret_output_app_only before anything runs", async () => {
    const a = app();
    const base = a.ops.get("notes_list") as OperationView;
    const lease = { ...base, id: "notes_lease", secretOutput: true } as unknown as OperationView; // spec 0.1.68
    (a.ops as Map<string, OperationView>).set("notes_lease", lease);
    try {
      const token = await w.agentToken();
      const init = await w.mcp(token, { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "c336-list" } } });
      w.bridge.ctx.table && (await w.publish());
      await waitFor(() => w.bridge.ctx.table?.rev === w.rev(), 15000);
      (w.bridge.ctx.table?.apps.get(INS as never)?.ops as Map<string, OperationView> | undefined)?.set("notes_lease", lease);
      const list = await w.mcp(token, { jsonrpc: "2.0", id: 2, method: "tools/list" }, init.session as string);
      const names = (list.json.result.tools as { name: string }[]).map((t) => t.name);
      assert.ok(names.includes("notes__notes_list"), "control: the other ops are listed");
      assert.equal(names.includes("notes__notes_lease"), false, "the secretOutput op is not an agent tool");
      const from = w.appLog.hooks.length;
      const ops = w.appLog.ops.length;
      await assert.rejects(
        new CallRouter(w.bridge.ctx).route({ caller: agent, target: { app: app(), op: lease }, input: {} as never }),
        (e: unknown) => (e as { code?: string; status?: number }).code === "secret_output_app_only" && (e as { status?: number }).status === 403,
      );
      assert.equal(w.appLog.hooks.length, from, "no hook ran");
      assert.equal(w.appLog.ops.length, ops, "nothing forwarded");
    } finally {
      (w.bridge.ctx.table?.apps.get(INS as never)?.ops as Map<string, OperationView> | undefined)?.delete("notes_lease");
    }
  });
});
