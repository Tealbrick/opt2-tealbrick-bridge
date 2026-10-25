/**
 * Spec 0.1.71 (C330(1), M4b; BRIDGE §7.5, MANIFEST §5.5): `operations[].listing: "lazy"`. A lazy op is visible and callable
 * exactly as a listed one, but tools/list leaves it out; per product the agent gets `<product>__tb_more_search` (answered by
 * the bridge from the agent's own index) and `<product>__tb_more_call` (resolved to the op's own route, then the direct call).
 *
 * The pinned validator (manifest 0.1.30, spec 0.1.57) refuses `listing: "lazy"` (`schema_invalid`), so the end-to-end tests
 * run in the test-double world; the real-crypto world runs them as soon as the pinned validator accepts the value (pin bump
 * to spec >= 0.1.71), and says so while it does not. Mirrors conformance B30.*.
 */
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import { manifestApi } from "@opt2-tealbrick/relay";
import { MORE_CALL_OP, MORE_SEARCH_OP, searchLazy, type ToolDef } from "../src/tools.ts";
import { AGT, BRG, INS, makeWorld, notesManifest, type World, WS, waitFor } from "./support/world.ts";

const lazy = (id: string) => ({ ...((notesManifest.operations as { id: string }[]).find((o) => o.id === id) as Record<string, unknown>), listing: "lazy" });
const archive = {
  id: "notes_archive",
  title: "Archive a note",
  description: "Move an old note to the archive so it no longer shows in lists",
  input: { type: "object" },
  output: { type: "object" },
  crud: ["read"],
  effect: "read",
  idempotency: "none",
  receipt: false,
  audience: "agent",
  listing: "lazy",
};
// hot: notes_list; lazy and visible (grant read+create): notes_create (idempotency required), notes_send (held), notes_archive;
// lazy and NOT visible (no `delete` in the grant): notes_delete
const manifest = {
  ...notesManifest,
  version: "1.3.0",
  operations: [...(notesManifest.operations as { id: string }[]).filter((o) => !["notes_create", "notes_send", "notes_delete"].includes(o.id)), lazy("notes_create"), lazy("notes_send"), lazy("notes_delete"), archive],
};
const SEARCH = `notes__${MORE_SEARCH_OP}`;
const CALL = `notes__${MORE_CALL_OP}`;
const now = () => Math.floor(Date.now() / 1000);

type ToolResult = { isError?: boolean; structuredContent?: Record<string, any> };
async function session(w: World) {
  const token = await w.agentToken();
  const init = await w.mcp(token, { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test" } } });
  return { token, sid: init.session as string };
}
const list = async (w: World, s: { token: string; sid: string }) => {
  const r = await w.mcp(s.token, { jsonrpc: "2.0", id: 2, method: "tools/list" }, s.sid);
  return r.json.result.tools as { name: string; annotations?: Record<string, boolean>; description: string }[];
};
const call = async (w: World, s: { token: string; sid: string }, name: string, args: unknown, meta?: Record<string, unknown>): Promise<ToolResult> => {
  const r = await w.mcp(s.token, { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name, arguments: args, ...(meta ? { _meta: meta } : {}) } }, s.sid);
  return r.json.result as ToolResult;
};
const proofOf = (p: string | undefined) => JSON.parse(Buffer.from(String(p).split(".")[1] as string, "base64url").toString("utf8")) as Record<string, unknown>;

/** does the pinned validator accept a lazy manifest? (false until the pin bump) */
const realAccepts = (): boolean => {
  const v = manifestApi().validateManifest(manifest as never) as { ok: boolean };
  return v.ok;
};

for (const real of [false, true]) {
  const skip = real && !realAccepts() ? "the pinned validator (manifest 0.1.30 / spec 0.1.57) refuses listing lazy; runs after the pin bump to spec >= 0.1.71" : false;
  describe(`listing: "lazy" (${real ? "real manifest crypto" : "test double"})`, { skip }, () => {
    let w: World;
    before(async () => {
      w = await makeWorld({ real, withHook: true });
      w.updateAppTo(manifest);
      await w.publish();
      await waitFor(() => !!w.bridge.ctx.table?.apps.get(INS as never)?.ops.has("notes_archive"), 15000);
    });
    after(async () => {
      await w.close();
    });

    test("B30.lazy_hidden: tools/list has the hot op and the pair, not the lazy ops; tb_more_call's annotations are the widest over the ops it reaches", async () => {
      const tools = await list(w, await session(w));
      const names = tools.map((t) => t.name);
      assert.ok(names.includes("notes__notes_list"), "hot op listed");
      for (const n of ["notes__notes_create", "notes__notes_send", "notes__notes_archive", "notes__notes_delete"]) assert.ok(!names.includes(n), `${n} not listed`);
      assert.ok(names.includes(SEARCH) && names.includes(CALL), "the pair is listed");
      assert.ok(names.includes("notes__tb_hold_status") && names.includes("notes__tb_skills"));
      const s = tools.find((t) => t.name === SEARCH);
      assert.equal(s?.annotations?.readOnlyHint, true);
      assert.match(s?.description ?? "", /3 not listed/, "the count covers only the visible lazy ops");
      assert.ok(!(s?.description ?? "").includes("notes_delete"), "a not-visible op is never named");
      const c = tools.find((t) => t.name === CALL);
      assert.deepEqual(c?.annotations, { readOnlyHint: false, destructiveHint: false, openWorldHint: true }, "notes_send is outward");
      for (const t of tools) assert.ok(!("op" in t) && !("effect" in t), "no internal fields in tools/list");
    });

    test("B30.lazy_search: '*' returns the visible lazy ops with schema and effect; a word ranks its op first; the app gets no call", async () => {
      const s = await session(w);
      const ops = w.appLog.ops.length;
      const seen = w.bridgeOps.seen.length;
      const all = await call(w, s, SEARCH, { query: "*" });
      assert.equal(all.isError, undefined);
      assert.deepEqual(
        all.structuredContent?.tools.map((h: { tool: string }) => h.tool),
        ["notes__notes_archive", "notes__notes_create", "notes__notes_send"],
      );
      assert.equal(all.structuredContent?.total, 3);
      const hit = all.structuredContent?.tools[0];
      assert.deepEqual(Object.keys(hit).sort(), ["description", "effect", "inputSchema", "title", "tool"]);
      assert.equal(hit.effect, "read");
      const one = await call(w, s, SEARCH, { query: "archive old notes", limit: 1 });
      assert.equal(one.structuredContent?.tools[0].tool, "notes__notes_archive");
      assert.equal(one.structuredContent?.tools.length, 1);
      assert.ok(one.structuredContent?.total >= 1);
      const none = await call(w, s, SEARCH, { query: "delete" });
      assert.ok(!none.structuredContent?.tools.some((h: { tool: string }) => h.tool === "notes__notes_delete"), "not visible → not found");
      assert.equal((await call(w, s, SEARCH, {})).structuredContent?.error?.code, "input_invalid");
      assert.equal(w.appLog.ops.length, ops, "search never calls the app");
      assert.equal(w.bridgeOps.seen.length, seen, "nor a bridge op");
    });

    test("B30.lazy_grant: a lazy op the grant does not make visible is not callable (via the pair or by name); the app sees nothing", async () => {
      const s = await session(w);
      const ops = w.appLog.ops.length;
      for (const [name, args] of [[CALL, { tool: "notes__notes_delete", arguments: {} }], [CALL, { tool: "notes_delete", arguments: {} }], ["notes__notes_delete", {}]] as const) {
        const r = await call(w, s, name, args);
        assert.equal(r.isError, true);
        assert.equal(r.structuredContent?.error?.code, "unknown_tool", `${name} ${JSON.stringify(args)}`);
      }
      assert.equal(w.appLog.ops.length, ops);
    });

    test("B30.lazy_call_same_route: through tb_more_call = the direct call (proof op + input digest, hooks name the op, same derived key, held handle)", async () => {
      const s = await session(w);
      const start = w.appLog.ops.length;
      const hooks = w.appLog.hooks.length;
      const via = await call(w, s, CALL, { tool: "notes__notes_create", arguments: { title: "x" } });
      assert.equal(via.isError, undefined, JSON.stringify(via));
      assert.equal(via.structuredContent?.op, "notes_create");
      const direct = await call(w, s, "notes__notes_create", { title: "x" });
      assert.equal(direct.isError, undefined);
      const [a, b] = w.appLog.ops.slice(start);
      assert.equal(a?.op, "notes_create");
      assert.deepEqual(a?.body.input, { title: "x" }, "the app receives `arguments`, never the more_call wrapper");
      assert.equal(typeof a?.body.idempotencyKey, "string");
      assert.equal(a?.body.idempotencyKey, b?.body.idempotencyKey, "the derived key is the direct call's: the app deduplicates both paths");
      const pa = proofOf(a?.proof);
      const pb = proofOf(b?.proof);
      assert.equal(pa.op, "notes_create");
      assert.equal(pa.in, pb.in, "input digest of `arguments`");
      const hookBodies = w.appLog.hooks.slice(hooks).map((h) => JSON.stringify(h.body));
      assert.ok(hookBodies.length >= 2 && hookBodies.every((h) => h.includes("notes_create") && !h.includes(MORE_CALL_OP)), "hooks see the op, never tb_more_call");
      // a client key applies to the op as well
      const keyed = await call(w, s, CALL, { tool: "notes_create", arguments: { title: "y" } }, { "tealbrick/idempotencyKey": "idem-lazy-0001" });
      assert.equal(keyed.isError, undefined);
      assert.equal(w.appLog.ops.at(-1)?.body.idempotencyKey, "idem-lazy-0001");
      // held answer: the same handle as a direct call
      const held = await call(w, s, CALL, { tool: "notes__notes_send", arguments: {} });
      assert.equal(held.isError, false);
      assert.equal(held.structuredContent?.status, "held");
      assert.equal(held.structuredContent?.checkWith, "notes__tb_hold_status");
      assert.equal(w.appLog.ops.at(-1)?.op, "notes_send");
      // bad wrapper input
      assert.equal((await call(w, s, CALL, { arguments: {} })).structuredContent?.error?.code, "input_invalid");
      assert.equal((await call(w, s, CALL, { tool: "notes_create", arguments: "x" })).structuredContent?.error?.code, "input_invalid");
    });

    test("B30.lazy_unknown: unknown op, another product, a standard op, the pair itself → unknown_tool", async () => {
      const s = await session(w);
      const ops = w.appLog.ops.length;
      for (const tool of ["notes__nope", "nope", "guard__guard_status", "notes__tb_hold_status", "tb_hold_status", SEARCH, CALL, "notes__tb_skills"]) {
        const r = await call(w, s, CALL, { tool, arguments: {} });
        assert.equal(r.structuredContent?.error?.code, "unknown_tool", tool);
      }
      assert.equal(w.appLog.ops.length, ops);
    });

    test("B30.lazy_hot_and_direct: a listed op via tb_more_call is allowed; a lazy op by its own name is allowed", async () => {
      const s = await session(w);
      const hot = await call(w, s, CALL, { tool: "notes__notes_list", arguments: { q: "z" } });
      assert.equal(hot.isError, undefined);
      assert.equal(w.appLog.ops.at(-1)?.op, "notes_list");
      assert.deepEqual(w.appLog.ops.at(-1)?.body.input, { q: "z" });
      const direct = await call(w, s, "notes__notes_archive", {});
      assert.equal(direct.isError, undefined);
      assert.equal(w.appLog.ops.at(-1)?.op, "notes_archive");
    });

    test("a read-only grant keeps the pair for notes_archive only; a Bound grant without a lazy op in wf gets no pair", async () => {
      // Core lists a read-only grant: only notes_archive stays lazy-visible, and the pair stays
      const g = await w.signPortal("tb-grant+jwt", { iss: "tb:portal", sub: `tb:agt:${AGT}`, aud: `tb:ins:${INS}`, iat: now(), exp: now() + 3600, jti: w.api.ulid(), ws: WS, cnf: { brg: BRG }, crud: ["read"], mode: "free", held: [], caps: {}, wf: [], polrev: 1 });
      await w.publish((c) => {
        c.grants = [g];
      });
      await waitFor(() => w.bridge.ctx.table?.rev === w.rev(), 15000);
      const s = await session(w);
      const names = (await list(w, s)).map((t) => t.name);
      assert.ok(names.includes(SEARCH));
      const all = await call(w, s, SEARCH, { query: "*" });
      assert.deepEqual(all.structuredContent?.tools.map((h: { tool: string }) => h.tool), ["notes__notes_archive"]);
      assert.equal((await call(w, s, CALL, { tool: "notes_create", arguments: {} })).structuredContent?.error?.code, "unknown_tool", "create left the grant");
      // a Bound grant whose wf names only the hot op: no lazy op is visible, so no pair
      const b = await w.signPortal("tb-grant+jwt", { iss: "tb:portal", sub: `tb:agt:${AGT}`, aud: `tb:ins:${INS}`, iat: now(), exp: now() + 3600, jti: w.api.ulid(), ws: WS, cnf: { brg: BRG }, crud: ["read", "create"], mode: "bound", held: [], caps: {}, wf: ["notes_list"], polrev: 1 });
      await w.publish((c) => {
        c.grants = [b];
      });
      await waitFor(() => w.bridge.ctx.table?.rev === w.rev(), 15000);
      const s2 = await session(w);
      const names2 = (await list(w, s2)).map((t) => t.name);
      assert.ok(names2.includes("notes__notes_list"));
      assert.ok(!names2.includes(SEARCH) && !names2.includes(CALL), "no visible lazy op → no pair");
      assert.equal((await call(w, s2, "notes__notes_archive", {})).structuredContent?.error?.code, "unknown_tool", "outside wf → not callable");
    });
  });
}

// QA-BRIDGE20-1/-2/-3 (spec 0.1.71 review): annotations over every op tb_more_call reaches, tb_* catalog entries, refresh-on-miss
const { input: _dIn, output: _dOut, ...engineBase } = archive;
const qaManifest = {
  ...notesManifest,
  version: "1.4.0",
  operations: [
    ...(notesManifest.operations as { id: string }[]).filter((o) => ["notes_list", "notes_delete", "notes_admin"].includes(o.id)),
    archive,
    // scoped and above the grant: visible only once the owner's row admits it (C283 A1)
    { ...archive, id: "notes_s_lazy", title: "Rename a notebook", crud: ["update"], effect: "write", receipt: true, scopeType: "notebook" },
    { ...engineBase, id: "notes_engine", title: "Engine", listing: undefined, idempotency: "supported", dynamic: { mode: "list", crudCeiling: ["read"], effectCeiling: "read" } },
  ],
};
const entry = (name: string) => ({ name, title: name, description: `Entry ${name}`, inputSchema: { type: "object" }, crud: ["read"], effect: "read" });

describe("lazy tools: QA fixes (test double)", () => {
  let w: World;
  let admitted: string[] = [];
  before(async () => {
    w = await makeWorld({ real: false });
    w.bridgeOps.answer = (path) => {
      if (path === "catalog") return [entry("tb_more_call"), entry("tb_skills"), entry("ok_entry")];
      if (path === "scope-summary") return [{ agent: AGT, label: "1 Notebook", admittedOps: admitted }];
      return undefined;
    };
    w.updateAppTo(qaManifest);
    // probe A1: the agent may delete, the only lazy op it sees is a read
    const g = await w.signPortal("tb-grant+jwt", { iss: "tb:portal", sub: `tb:agt:${AGT}`, aud: `tb:ins:${INS}`, iat: now(), exp: now() + 3600, jti: w.api.ulid(), ws: WS, cnf: { brg: BRG }, crud: ["read", "create", "delete"], mode: "free", held: [], caps: {}, wf: [], polrev: 1 });
    await w.publish((c) => {
      c.grants = [g];
    });
    await waitFor(() => !!w.bridge.ctx.table?.apps.get(INS as never)?.ops.has("notes_s_lazy") && w.bridge.ctx.table?.rev === w.rev(), 15000);
  });
  after(async () => {
    await w.close();
  });

  test("QA-BRIDGE20-1: tb_more_call annotations are the widest over the lazy AND listed ops this agent reaches (a listed destructive op counts)", async () => {
    const s = await session(w);
    const tools = await list(w, s);
    assert.ok(tools.some((t) => t.name === "notes__notes_delete"), "notes_delete is listed (hot)");
    const c = tools.find((t) => t.name === CALL);
    assert.deepEqual(c?.annotations, { readOnlyHint: false, destructiveHint: true, openWorldHint: false });
    assert.equal(tools.find((t) => t.name === SEARCH)?.annotations?.readOnlyHint, true);
    // and it does reach the listed destructive op
    const r = await call(w, s, CALL, { tool: "notes_delete", arguments: {} });
    assert.equal(r.isError, undefined, JSON.stringify(r));
    assert.equal(w.appLog.ops.at(-1)?.op, "notes_delete");
  });

  test("QA-BRIDGE20-2: catalog entries named tb_* are omitted (name_collision); the real pair stays", async () => {
    const s = await session(w);
    const names = (await list(w, s)).map((t) => t.name);
    assert.ok(names.includes("notes__ok_entry"), "an ordinary entry is listed");
    assert.equal(names.filter((n) => n === CALL).length, 1);
    assert.equal(names.filter((n) => n === "notes__tb_skills").length, 1);
    for (const n of ["tb_more_call", "tb_skills"]) assert.equal(w.bridge.ctx.toolsOmitted.get(`${INS}|${n}`)?.code, "name_collision", n);
    const r = await call(w, s, CALL, { tool: "notes_archive", arguments: {} });
    assert.equal(r.isError, undefined);
    assert.equal(w.appLog.ops.at(-1)?.op, "notes_archive", "tb_more_call is the bridge's pair, not the app's entry");
  });

  test("QA-BRIDGE20-3: after the owner admits a scoped lazy op, tb_more_call finds it through refresh-on-miss (as a direct call does)", async () => {
    const s = await session(w);
    assert.equal((await call(w, s, SEARCH, { query: "*" })).structuredContent?.total, 1, "only notes_archive before");
    admitted = ["notes_s_lazy"];
    w.bridge.ctx.scopeSummaryAt.set(INS as never, 0);
    const seen = w.bridgeOps.seen.filter((x) => x.path === "scope-summary").length;
    const r = await call(w, s, CALL, { tool: "notes_s_lazy", arguments: {} });
    assert.equal(r.isError, undefined, JSON.stringify(r));
    assert.equal(w.appLog.ops.at(-1)?.op, "notes_s_lazy");
    assert.equal(w.bridgeOps.seen.filter((x) => x.path === "scope-summary").length, seen + 1, "one scope-summary request");
    // an unknown inner name of a scoped-op-free kind asks nothing
    w.bridge.ctx.scopeSummaryAt.set(INS as never, 0);
    assert.equal((await call(w, s, CALL, { tool: "nope", arguments: {} })).structuredContent?.error?.code, "unknown_tool");
    assert.equal(w.bridgeOps.seen.filter((x) => x.path === "scope-summary").length, seen + 1);
  });
});

test("searchLazy: words, ranking, '*' and limit (BRIDGE §7.5)", () => {
  const d = (op: string, description: string): ToolDef => ({ name: `p__${op}`, op, title: op, description, inputSchema: { type: "object" }, effect: "read" });
  const defs = [d("b_two", "red green"), d("a_one", "red"), d("c_three", "blue")];
  assert.deepEqual(searchLazy(defs, "RED green").tools.map((h) => h.tool), ["p__b_two", "p__a_one"], "two words beat one");
  assert.deepEqual(searchLazy(defs, "red").tools.map((h) => h.tool), ["p__a_one", "p__b_two"], "ties by op id");
  assert.deepEqual(searchLazy(defs, " * ").tools.map((h) => h.tool), ["p__a_one", "p__b_two", "p__c_three"]);
  const lim = searchLazy(defs, "*", 1);
  assert.equal(lim.tools.length, 1);
  assert.equal(lim.total, 3);
  assert.deepEqual(searchLazy(defs, "three").tools.map((h) => h.tool), ["p__c_three"], "op ids match too");
  assert.deepEqual(searchLazy(defs, "?!").tools, [], "no words → no match");
});
