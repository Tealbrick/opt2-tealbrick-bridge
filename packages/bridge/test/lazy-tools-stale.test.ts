/**
 * Spec 0.1.75 BRIDGE §7.5 (C330(1), M4b; QA "lazy listing DELTA"): tb_more_call hints are never stale where it matters.
 *  (a) list_changed whenever the tb_more_call annotations change, even when no tool NAME changes (an owner adds `delete`);
 *  (b) tb_more_call refuses an inner op wider than the hints this session last listed (`tools_stale`), also when the op is
 *      admitted inside the same call (refresh-on-miss); after a fresh tools/list the call runs.
 * Plus the guards the surviving mutants showed untested: money in the annotation matrix, cross-product reach, the
 * neighbour-claim cap gate, "**" as a word, the query limit. Test double with the lazy-tools start option.
 */
import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { after, before, describe, test } from "node:test";
import { freePort } from "./support/sdk-app.ts";
import { AGT, BRG, HOOKINS, hookManifest, INS, makeWorld, notesManifest, type World, WS, waitFor } from "./support/world.ts";

const now = () => Math.floor(Date.now() / 1000);
const op = (id: string, crud: string[], effect: string, extra: Record<string, unknown> = {}) => ({
  id,
  title: id,
  description: `Stale probe op ${id}`,
  input: { type: "object" },
  output: { type: "object" },
  crud,
  effect,
  idempotency: "none",
  receipt: effect !== "read",
  audience: "agent",
  ...extra,
});
const manifest = {
  ...notesManifest,
  version: "2.0.0",
  operations: [
    op("notes_list", ["read"], "read"),
    op("notes_find", ["read"], "read", { listing: "lazy" }),
    op("notes_delete", ["delete"], "destructive", { listing: "lazy", holdFamily: "destructive" }),
    op("notes_pay", ["update"], "money", { listing: "lazy", holdFamily: "money" }),
    op("notes_s_del", ["delete"], "destructive", { listing: "lazy", holdFamily: "destructive", scopeType: "notebook" }),
    op("notes_admin", ["read"], "read", { audience: "person" }),
  ],
};
type R = { isError?: boolean; structuredContent?: Record<string, any> };
const CALL = "notes__tb_more_call";
const SEARCH = "notes__tb_more_search";

describe("lazy tools: stale hints (a)/(b) and mutant gaps (test double)", () => {
  let w: World;
  let admitted: string[] = [];
  const grant = (crud: string[], aud = INS) =>
    w.signPortal("tb-grant+jwt", { iss: "tb:portal", sub: `tb:agt:${AGT}`, aud: `tb:ins:${aud}`, iat: now(), exp: now() + 3600, jti: w.api.ulid(), ws: WS, cnf: { brg: BRG }, crud, mode: "free", held: [], caps: {}, wf: [], polrev: 1 });
  const setGrant = async (crud: string[], withGuard = false) => {
    const gs = [await grant(crud), ...(withGuard ? [await grant(["read"], HOOKINS)] : [])];
    await w.publish((c) => {
      c.grants = gs;
    });
    await waitFor(() => w.bridge.ctx.table?.rev === w.rev(), 15000);
  };
  const open = async () => {
    const token = await w.agentToken();
    const init = await w.mcp(token, { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t" } } });
    return { token, sid: init.session as string };
  };
  const tools = async (s: { token: string; sid: string }) => (await w.mcp(s.token, { jsonrpc: "2.0", id: 2, method: "tools/list" }, s.sid)).json.result.tools as { name: string; annotations?: Record<string, boolean> }[];
  const ann = async (s: { token: string; sid: string }) => (await tools(s)).find((t) => t.name === CALL)?.annotations;
  const call = async (s: { token: string; sid: string }, name: string, args: unknown): Promise<R> => (await w.mcp(s.token, { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name, arguments: args } }, s.sid)).json.result as R;
  const code = (r: R) => r.structuredContent?.error?.code;

  before(async () => {
    w = await makeWorld({ real: false, lazyTools: true, withHook: true });
    w.bridgeOps.answer = (path) => (path === "scope-summary" ? [{ agent: AGT, label: "1 Notebook", admittedOps: admitted }] : undefined);
    w.updateAppTo(manifest);
    await setGrant(["read"]);
    await waitFor(() => !!w.bridge.ctx.table?.apps.get(INS as never)?.ops.has("notes_pay"), 15000);
  });
  after(async () => {
    await w.close();
  });

  test("annotation matrix incl. money: read → read-only; +delete → destructive; +update (money) → openWorld; both → both", async () => {
    for (const [crud, want] of [
      [["read"], { readOnlyHint: true, destructiveHint: false, openWorldHint: false }],
      [["read", "delete"], { readOnlyHint: false, destructiveHint: true, openWorldHint: false }],
      [["read", "update"], { readOnlyHint: false, destructiveHint: false, openWorldHint: true }],
      [["read", "update", "delete"], { readOnlyHint: false, destructiveHint: true, openWorldHint: true }],
    ] as const) {
      await setGrant([...crud]);
      assert.deepEqual(await ann(await open()), want, crud.join("+"));
    }
  });

  test("(a) an owner adds delete: no tool name changes, the hints do → notifications/tools/list_changed", async () => {
    await setGrant(["read"]);
    const s = await open();
    const before = await tools(s);
    const port = (w.bridge.publicServer.address() as { port: number }).port;
    const stream = await fetch(`http://127.0.0.1:${port}/mcp`, { headers: { authorization: `Bearer ${s.token}`, "mcp-session-id": s.sid, accept: "text/event-stream" } });
    const reader = (stream.body as ReadableStream<Uint8Array>).getReader();
    let ev = "";
    const reading = (async () => {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) return;
        ev += new TextDecoder().decode(value);
      }
    })().catch(() => undefined);
    await setGrant(["read", "delete"]);
    await waitFor(() => ev.includes("notifications/tools/list_changed"), 10000);
    await reader.cancel();
    await reading;
    const after = await tools(s);
    assert.deepEqual(after.map((t) => t.name), before.map((t) => t.name), "the names are unchanged");
    assert.notDeepEqual(after.find((t) => t.name === CALL)?.annotations, before.find((t) => t.name === CALL)?.annotations);
  });

  test("(b) listed read-only, then delete is granted: tb_more_call refuses notes_delete (tools_stale) until the session re-lists", async () => {
    await setGrant(["read"]);
    const s = await open();
    assert.equal((await ann(s))?.readOnlyHint, true);
    await setGrant(["read", "delete"]);
    const ops = w.appLog.ops.length;
    const r = await call(s, CALL, { tool: "notes_delete", arguments: {} });
    assert.equal(code(r), "tools_stale", JSON.stringify(r));
    assert.match(String(r.structuredContent?.error?.message), /re-list tools/);
    assert.equal(w.appLog.ops.length, ops, "the app is never called under the old hint");
    // a read op is never refused for staleness
    assert.equal((await call(s, CALL, { tool: "notes_find", arguments: {} })).isError, undefined);
    assert.equal((await ann(s))?.destructiveHint, true, "re-listed");
    const ok = await call(s, CALL, { tool: "notes_delete", arguments: {} });
    assert.equal(ok.isError, undefined, JSON.stringify(ok));
    assert.equal(w.appLog.ops.at(-1)?.op, "notes_delete");
  });

  test("(b) an owner row admits a scoped destructive lazy op inside the call (refresh-on-miss): refused tools_stale, never run", async () => {
    await setGrant(["read"]);
    admitted = [];
    const s = await open();
    assert.equal((await ann(s))?.readOnlyHint, true);
    admitted = ["notes_s_del"];
    w.bridge.ctx.scopeSummaryAt.set(INS as never, 0);
    const ops = w.appLog.ops.length;
    const r = await call(s, CALL, { tool: "notes_s_del", arguments: {} });
    assert.equal(code(r), "tools_stale", JSON.stringify(r));
    assert.equal(w.appLog.ops.length, ops);
    assert.equal((await ann(s))?.destructiveHint, true, "the fresh list shows the admitted destructive op's hint");
    assert.equal((await call(s, CALL, { tool: "notes_s_del", arguments: {} })).isError, undefined);
    admitted = [];
  });

  test("cross-product: another granted product's op is unknown_tool through this product's tb_more_call", async () => {
    await setGrant(["read"], true);
    const s = await open();
    assert.ok((await tools(s)).some((t) => t.name === "guard__guard_status"), "sanity: the second product is granted");
    const ops = w.appLog.ops.length;
    for (const tool of ["guard__guard_status", "guard_status"]) assert.equal(code(await call(s, CALL, { tool, arguments: {} })), "unknown_tool", tool);
    assert.equal(w.appLog.ops.length, ops);
  });

  test('search: "**" is an ordinary word (matches nothing here), a query over 500 chars → input_invalid', async () => {
    await setGrant(["read"]);
    const s = await open();
    const r = await call(s, SEARCH, { query: "**" });
    assert.equal(r.structuredContent?.total, 0);
    assert.equal(code(await call(s, SEARCH, { query: "x".repeat(501) })), "input_invalid");
    assert.ok(((await call(s, SEARCH, { query: "*" })).structuredContent?.total ?? 0) >= 1, '"*" alone lists all');
  });
});

// C354: the neighbour-claim half of the cap gate (the fetch half: lazy-tools.test.ts)
const NINS = "ins_01HK0NBRNBRNBRNBRNBRNBRNBR";
const NCODE = "tbe_brg12neighbourclaimcode01";
const lazyGuard = { ...hookManifest, operations: (hookManifest.operations as Record<string, unknown>[]).map((o) => ({ ...o, listing: "lazy" })) };
for (const lazyTools of [false, true]) {
  describe(`neighbour claim of a lazy manifest (lazyTools ${lazyTools})`, () => {
    let w: World;
    let neighbour: Server;
    let port = 0;
    before(async () => {
      port = await freePort();
      neighbour = createServer((req: IncomingMessage, res: ServerResponse) => {
        if (req.url !== "/tb/v1/manifest") return void res.writeHead(404).end();
        res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(lazyGuard));
      });
      await new Promise<void>((r) => neighbour.listen(port, "127.0.0.1", r));
      w = await makeWorld({ real: false, lazyTools, formDefaultHosts: true, extraOwnInfraOrigins: [`http://127.0.0.1:${port}`] });
      await w.amend((c) => {
        c.enrolCodes.push({ digest: w.api.opaqueDigest(NCODE), kind: "neighbour", ins: NINS as never, product: "guard", exp: now() + 3600 } as never);
      });
      await waitFor(() => w.bridge.ctx.table?.rev === w.rev(), 15000);
    });
    after(async () => {
      await w?.close();
      await new Promise((r) => neighbour?.close(r));
    });
    test(lazyTools ? "with lazy tools: the claim is accepted" : "without lazy tools: 409 bridge_cap_missing naming lazy_tools, nothing recorded", async () => {
      const key = await w.api.generateKeyPair();
      const res = await fetch(`${w.internalUrl}/tb/v1/claim`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ code: NCODE, instancePublicKey: key.publicJwk, manifestDigest: w.api.manifestDigest(lazyGuard as never), version: "1.0.0", sdkVersion: "1.0.0", internalUrl: `http://127.0.0.1:${port}` }) });
      const body = (await res.json()) as { error?: { code?: string; message?: string } };
      const claims = w.bridge.ctx.state.claims.filter((c) => c.ins === NINS).length;
      if (lazyTools) {
        assert.equal(res.status, 200, JSON.stringify(body));
        assert.equal(claims, 1);
      } else {
        assert.equal(res.status, 409);
        assert.equal(body.error?.code, "bridge_cap_missing");
        assert.match(String(body.error?.message), /lazy_tools/);
        assert.equal(claims, 0);
      }
    });
  });
}
