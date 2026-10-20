/**
 * C296 / INC-20261020-03: the tool index was cached for the whole config revision, so dynamic list entries read while the
 * app had no engine yet (an empty catalog, or a failed one) stayed hidden until the next revision. Now an index with
 * dynamic list entries is rebuilt after `dynamicIndexTtlMs`, one whose catalog failed after `incompleteIndexRetryMs`
 * (in the background: the stale index answers at once), sessions get notifications/tools/list_changed when the rebuilt
 * tool set differs, and a refresh that fails keeps the last good entries (review). Fires on bad, quiet on good.
 */
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import { INS, makeWorld, notesManifest, type World, waitFor } from "./support/world.ts";

const op = (id: string, crud: string[], effect: string) => ({ id, title: id, description: `Test op ${id}`, crud, effect, idempotency: "supported", receipt: false, audience: "agent" });
const manifest = {
  ...notesManifest,
  version: "1.4.0",
  operations: [...notesManifest.operations, { ...op("notes_engine", ["read"], "read"), dynamic: { mode: "list", crudCeiling: ["read", "update"], effectCeiling: "write" } }],
};
/** test 2 adds a second list op whose catalog has never answered before */
const manifestB = { ...manifest, version: "1.5.0", operations: [...manifest.operations, { ...op("notes_engine_b", ["read"], "read"), dynamic: { mode: "list", crudCeiling: ["read"], effectCeiling: "read" } }] };
const entry = (name: string) => ({ name, title: name, description: `entry ${name}`, inputSchema: { type: "object" }, crud: ["read"], effect: "read" });
const TTL = 400;
const RETRY = 150;

describe("C296: the tool index follows the app's dynamic catalog within a config revision", () => {
  let w: World;
  let catalog: "empty" | "full" = "empty";
  let shared: { token: string; sid: string } | undefined;
  before(async () => {
    w = await makeWorld({ real: true, limits: { mcp: { dynamicIndexTtlMs: TTL, incompleteIndexRetryMs: RETRY } } });
    w.updateAppTo(manifest);
    await w.publish();
    await waitFor(() => !!w.bridge.ctx.table?.apps.get(INS as never)?.ops.has("notes_engine"), 15000);
    w.bridgeOps.answer = (path, body) => {
      if (path !== "catalog") return [];
      if (body?.op === "notes_engine_b") return [entry("gb_b_one")];
      return catalog === "full" ? [entry("gb_query"), entry("gb_get_page")] : [];
    };
  });
  after(async () => {
    await w.close();
  });

  const session = async () => {
    if (shared) return shared;
    const token = await w.agentToken();
    const init = await w.mcp(token, { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test" } } });
    shared = { token, sid: init.session as string };
    return shared;
  };
  const names = async () => {
    const s = await session();
    const r = await w.mcp(s.token, { jsonrpc: "2.0", id: 2, method: "tools/list" }, s.sid);
    // the first op's entries only (test 2's second op lists notes__gb_b_*, read with its own filter)
    return (r.json.result.tools as { name: string }[]).map((t) => t.name).filter((n) => n.startsWith("notes__gb_") && !n.startsWith("notes__gb_b_"));
  };
  const namesB = async () => {
    const s = await session();
    const r = await w.mcp(s.token, { jsonrpc: "2.0", id: 4, method: "tools/list" }, s.sid);
    return (r.json.result.tools as { name: string }[]).map((t) => t.name).filter((n) => n.startsWith("notes__gb_b_"));
  };
  const catalogCalls = () => w.bridgeOps.seen.filter((s) => s.path === "catalog").length;
  const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
  /** poll tools/list until the engine entries show (the rebuild runs in the background after the first stale answer) */
  const until = async (want: number, tries = 30) => {
    let listed: string[] = [];
    for (let i = 0; i < tries; i++) {
      listed = (await names()).sort();
      if (listed.length === want) return listed;
      await sleep(50);
    }
    return listed;
  };
  /** a new config revision, applied by the bridge (a fresh index) */
  const republish = async () => {
    await w.publish();
    await waitFor(() => w.bridge.ctx.table?.rev === w.rev(), 15000);
  };

  test("an index built while the catalog was empty is rebuilt after the TTL without a new config revision; list_changed is pushed", async () => {
    const rev = w.rev();
    assert.deepEqual(await names(), [], "no engine yet: no entries");
    // the session's event stream
    const s = await session();
    const stream = await fetch(`http://127.0.0.1:${(w.bridge.publicServer.address() as { port: number }).port}/mcp`, { headers: { authorization: `Bearer ${s.token}`, "mcp-session-id": s.sid, accept: "text/event-stream" } });
    assert.equal(stream.status, 200);
    const reader = (stream.body as ReadableStream<Uint8Array>).getReader();
    let events = "";
    const reading = (async () => {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) return;
        events += new TextDecoder().decode(value);
      }
    })().catch(() => undefined);
    catalog = "full";
    assert.deepEqual(await names(), [], "quiet within the TTL: the cached index is kept (no catalog storm)");
    await sleep(TTL + 50);
    assert.deepEqual(await until(2), ["notes__gb_get_page", "notes__gb_query"], "the engine tools appear on the same revision");
    assert.equal(w.rev(), rev, "no config revision was needed");
    await waitFor(() => events.includes("notifications/tools/list_changed"), 5000);
    await reader.cancel();
    await reading;
  });

  test("an index whose catalog failed (no earlier answer) is retried soon (incomplete), not kept for the revision", async () => {
    w.bridgeOps.status = 503; // the new op's app answers with an error while it starts
    let listedB: string[] = [];
    try {
      w.updateAppTo(manifestB);
      await republish();
      await waitFor(() => !!w.bridge.ctx.table?.apps.get(INS as never)?.ops.has("notes_engine_b"), 15000);
      listedB = await namesB();
    } finally {
      w.bridgeOps.status = undefined;
    }
    assert.deepEqual(listedB, [], "no answer yet: no entries for the new op");
    const before = catalogCalls();
    for (let i = 0; i < 40 && listedB.length !== 1; i++) {
      await sleep(RETRY / 2);
      listedB = await namesB();
    }
    assert.deepEqual(listedB, ["notes__gb_b_one"], "listed on the same revision once the app answers");
    assert.ok(catalogCalls() > before, "the catalog was asked again");
  });

  test("review: a refresh past the TTL that fails keeps the last good entries listed and callable", async () => {
    await republish();
    catalog = "full";
    assert.deepEqual(await until(2), ["notes__gb_get_page", "notes__gb_query"]);
    w.bridgeOps.status = 503; // the app hiccups exactly when the index is refreshed
    try {
      await sleep(TTL + 50);
      for (let i = 0; i < 6; i++) {
        assert.deepEqual((await names()).sort(), ["notes__gb_get_page", "notes__gb_query"], "never an empty list because one refresh failed");
        await sleep(60);
      }
      const s = await session();
      const r = await w.mcp(s.token, { jsonrpc: "2.0", id: 9, method: "tools/call", params: { name: "notes__gb_query", arguments: {} } }, s.sid);
      assert.notEqual(r.json.result?.structuredContent?.error?.code, "unknown_tool", "the tool still routes");
    } finally {
      w.bridgeOps.status = undefined;
    }
  });

  test("quiet on good: a complete index with no dynamic entries change is reused within the TTL", async () => {
    await republish();
    catalog = "full";
    await names();
    const before = catalogCalls();
    await names();
    await names();
    assert.equal(catalogCalls(), before, "no extra catalog calls within the TTL");
  });
});
