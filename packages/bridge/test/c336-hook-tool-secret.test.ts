/**
 * Bridge 0.2.10 / spec 0.1.68 (C336 RQ-2, RQ-3; BRIDGE v0.1.68, cap `hook_tool`; CONFORMANCE v0.1.68 rows):
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
import { DYNAMIC_CALL_INPUT_SCHEMA, validateAgainstSchema } from "@opt2-tealbrick/manifest";
import type { OperationView } from "@opt2-tealbrick/spec/sdk";
import { CallRouter } from "../src/calls.ts";
import { buildToolIndex } from "../src/tools.ts";
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

  // The pinned manifest (0.1.30) still refuses a requested dynamic tool over 48 chars at input validation; sdk#51 widens
  // DYNAMIC_CALL_INPUT_SCHEMA to {1,62}. The full-path test runs once the bridge pins that manifest; the resolve rule itself is
  // tested below on the real resolver now.
  const pinnedAccepts63 = validateAgainstSchema(DYNAMIC_CALL_INPUT_SCHEMA, { tool: `g${"m".repeat(47)}__first_contact`, arguments: {} }).ok;
  test(
    "BRIDGE23-1 full path (spec 0.1.68 {1,62}, C354): the agent requests a 49- and a 63-char name (a 48-char tool + `__first_contact`), the app resolves the same name → passes, it is the hook target.tool",
    { skip: pinnedAccepts63 ? false : "needs the manifest re-pin (sdk#51: DYNAMIC_CALL_INPUT_SCHEMA tool up to 63 chars)" },
    async () => {
      resolveAs = (t) => t;
      const base48 = `g${"m".repeat(47)}`;
      for (const name of [`${base48}x`, `${base48}__first_contact`]) {
        const from = w.appLog.hooks.length;
        const r = await mcpCall("notes__notes_tools_call", { tool: name, arguments: {} });
        assert.notEqual(r.isError, true, `${name.length} chars: ${JSON.stringify(r)}`);
        const seen = hooksSince(from);
        assert.deepEqual(
          seen.map((x) => x.phase),
          ["before", "context", "after"],
        );
        for (const x of seen) assert.equal(x.target.tool, name, `${name.length} chars, ${x.phase}`);
      }
    },
  );

  test("BRIDGE23-1 resolver (spec 0.1.68 {1,62}, C354): a 49- and a 63-char resolution equal to the request passes; one that differs (also `<requested>__<suffix>`) or has 64 chars is refused dynamic_resolve_failed", async () => {
    const router = new CallRouter(w.bridge.ctx) as unknown as { resolve(app: unknown, op: string, tool: string): Promise<{ tool: string }> };
    const base48 = `k${"m".repeat(47)}`;
    for (const name of [`${base48}x`, `${base48}__first_contact`]) {
      resolveAs = (t) => t;
      assert.ok(name.length >= 49 && name.length <= 63);
      assert.equal((await router.resolve(app(), "notes_tools", name)).tool, name, `${name.length} chars`);
    }
    const refused = async (requested: string, answer: string) => {
      resolveAs = () => answer;
      await assert.rejects(router.resolve(app(), "notes_tools", requested), (e: unknown) => (e as { code?: string }).code === "dynamic_resolve_failed", `${requested} → ${answer}`);
    };
    const other48 = `q${"m".repeat(47)}`;
    await refused(`${other48}__first_contact_`, `${other48}__first_contact_`); // 64 chars, equal
    await refused(`r${"m".repeat(47)}`, `r${"m".repeat(47)}__first_contact`); // the app swaps in a variant the agent did not request
    await refused("vr_a", "vr_a__first_contact");
    await refused("vr_b", "vr_bx");
    await refused("vr_c__first_contact", "vr_c");
    resolveAs = (t) => t;
  });

  test("QA-P5-3: a cached resolution is dropped when its instance runs another release (digest change) or leaves the table; an unchanged table keeps it", async () => {
    const router = new CallRouter(w.bridge.ctx) as unknown as { resolve(app: unknown, op: string, tool: string): Promise<{ tool: string }> };
    resolveAs = (t) => t;
    const asks = () => w.bridgeOps.seen.filter((x) => x.path === "resolve" && x.body?.tool === "rc_tool").length;
    const t0 = w.bridge.ctx.table;
    assert.ok(t0);
    const n0 = asks();
    await router.resolve(app(), "notes_tools", "rc_tool");
    await router.resolve(app(), "notes_tools", "rc_tool");
    assert.equal(asks(), n0 + 1, "the second resolve is a cache hit");
    // the same table again (a config change that does not touch this instance): still cached
    w.bridge.ctx.emit("table", t0, t0);
    await router.resolve(app(), "notes_tools", "rc_tool");
    assert.equal(asks(), n0 + 1, "an unchanged release keeps the cache");
    // the instance now runs another release: the next resolve asks the app again
    const a0 = app();
    const moved = { ...t0, apps: new Map([...t0.apps].map(([k, v]) => [k, k === a0.entry.ins ? { ...v, digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000" } : v])) };
    w.bridge.ctx.emit("table", moved as never, t0);
    w.bridge.ctx.emit("table", t0, moved as never);
    await router.resolve(app(), "notes_tools", "rc_tool");
    assert.equal(asks(), n0 + 2, "a digest change drops the cached resolution");
    // the instance leaves the table: dropped as well
    const gone = { ...t0, apps: new Map([...t0.apps].filter(([k]) => k !== a0.entry.ins)) };
    w.bridge.ctx.emit("table", gone as never, t0);
    w.bridge.ctx.emit("table", t0, gone as never);
    await router.resolve(app(), "notes_tools", "rc_tool");
    assert.equal(asks(), n0 + 3, "an instance that left resolves again");
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

  test("C-SO-2 (bridge): a secretOutput op is not listed for agents (positive control: the same op without the flag IS listed), and an agent call is refused secret_output_app_only before anything runs", async () => {
    const t = w.bridge.ctx.table;
    assert.ok(t);
    const a = app();
    const base = a.ops.get("notes_list") as OperationView;
    const lease = { ...base, id: "notes_lease", secretOutput: true } as unknown as OperationView; // spec 0.1.68
    const control = { ...base, id: "notes_lease_plain" } as OperationView; // the same op without the flag
    const ops = a.ops as Map<string, OperationView>;
    ops.set("notes_lease", lease);
    ops.set("notes_lease_plain", control);
    try {
      // QA-BRIDGE23-4: the index is built AFTER both ops are in the table (no cached index can hide a missing filter)
      const index = await buildToolIndex(w.bridge.ctx, new CallRouter(w.bridge.ctx), t, AGT as never);
      const names = index.tools.map((x) => x.name);
      assert.ok(names.includes("notes__notes_lease_plain"), "positive control: the same op without secretOutput is listed");
      assert.equal(names.includes("notes__notes_lease"), false, "the secretOutput op is not an agent tool");
      assert.equal(index.routes.has("notes__notes_lease"), false, "and has no route");
      const from = w.appLog.hooks.length;
      const forwarded = w.appLog.ops.length;
      await assert.rejects(
        new CallRouter(w.bridge.ctx).route({ caller: agent, target: { app: a, op: lease }, input: {} as never }),
        (e: unknown) => (e as { code?: string; status?: number }).code === "secret_output_app_only" && (e as { status?: number }).status === 403,
      );
      assert.equal(w.appLog.hooks.length, from, "no hook ran");
      assert.equal(w.appLog.ops.length, forwarded, "nothing forwarded");
    } finally {
      ops.delete("notes_lease");
      ops.delete("notes_lease_plain");
    }
  });
});
