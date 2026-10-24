/**
 * Bridge 0.2.5 (spec 0.1.50 / SDK-API v0.1.50, C283 A1, manifest 0.1.27): the owner-row filter.
 *
 * An OWNER-set scope row may admit a scoped op above the Portal grant's `crud`; the SDK authorizes every call. The bridge
 * shows and forwards:
 *  (a) tools/list: a STATIC scoped op above grant.crud is listed when the app's `scope_summary` answer names it in
 *      `admittedOps` for that agent (display only);
 *  (b) the dynamic catalog body carries `agent`, and an entry marked `admitted: "owner"` is listed above grant.crud;
 *  (c) gate() is the manifest 0.1.27 gate: scoped ops skip `op.crud ⊆ grant.crud`, UNSCOPED ops keep it.
 * Pause, revoke and expiry still refuse first. Real manifest crypto (the real `gate`, `opVisibleToGrant`).
 */
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import { CallRouter } from "../src/calls.ts";
import { buildStatusReport } from "../src/portal.ts";
import { type AppClient, claimApp } from "./support/app-client.ts";
import { AGT, AGT2, BRG, CON, INS, makeWorld, notesManifest, type World, WS, waitFor } from "./support/world.ts";

const now = () => Math.floor(Date.now() / 1000);
const op = (id: string, crud: string[], effect: string, extra: Record<string, unknown> = {}) => ({
  id,
  title: id,
  description: `Test op ${id}`,
  input: { type: "object" },
  output: { type: "object" },
  crud,
  effect,
  idempotency: "none",
  receipt: effect !== "read",
  audience: "agent",
  ...extra,
});
const scoped = (id: string, crud: string[], effect: string, extra: Record<string, unknown> = {}) => op(id, crud, effect, { scopeType: "notebook", ...extra });

// a dynamic op takes no `input` (its call input is the fixed DynamicCallInput)
const { input: _input, output: _output, ...dynamicBase } = scoped("notes_dyn", ["read"], "read");
const dynamicList = { ...dynamicBase, idempotency: "supported", dynamic: { mode: "list", crudCeiling: ["read", "update"], effectCeiling: "write" } };

// S3-2: dynamic ops WITHOUT a scopeType (the SDK marks `admitted` only for scoped ones): list mode and search mode; and a scoped search op
const dynamicOf = (id: string, mode: "list" | "search", scopeType: boolean) => {
  const { input: _i, output: _o, ...base } = scopeType ? scoped(id, ["read"], "read") : op(id, ["read"], "read");
  return { ...base, idempotency: "supported", dynamic: { mode, crudCeiling: ["read", "update"], effectCeiling: "write" } };
};

const manifest = {
  ...notesManifest,
  version: "1.3.0",
  operations: [
    ...notesManifest.operations,
    scoped("notes_s_read", ["read"], "read"),
    // above the grant (read, create): the owner row may admit it
    scoped("notes_s_update", ["update"], "write"),
    // above the grant and NOT admitted by any owner row
    scoped("notes_s_delete", ["delete"], "destructive", { holdFamily: "destructive" }),
    // above the grant, no scopeType: the Portal grant stays the ceiling, even if the app names it in admittedOps
    op("notes_u_update", ["update"], "write"),
    // a scoped list op: its entries carry their own crud and the SDK's `admitted` mark
    dynamicList,
    dynamicOf("notes_dyn_plain", "list", false),
    dynamicOf("notes_srch_plain", "search", false),
    dynamicOf("notes_srch_s", "search", true),
  ],
};
const entry = (name: string, crud: string[], effect: string, extra: Record<string, unknown> = {}) => ({ name, title: name, description: `Entry ${name}`, inputSchema: { type: "object" }, crud, effect, ...extra });

describe("C283 A1: owner-row filter (bridge 0.2.5)", () => {
  let w: World;
  let client: AppClient;
  let admitted: unknown[] = [];
  let label = "1 Notebook";
  let sources: unknown;
  const CON2 = "con_01HBBBBBBBBBBBBBBBBBBBBBBB";
  before(async () => {
    w = await makeWorld({ real: true });
    w.updateAppTo(manifest);
    await w.publish();
    await waitFor(() => !!w.bridge.ctx.table?.apps.get(INS as never)?.ops.has("notes_dyn"), 15000);
    // a second agent that has NO grant to the app, with a connection (S4-4)
    await w.amend((c) => {
      c.connections.push({ con: CON2 as never, agt: AGT2 as never, method: "key", gen: 1, publicKey: w.agentKey.publicJwk, status: "active" } as never);
    });
    await waitFor(() => w.bridge.ctx.table?.rev === w.rev(), 15000);
    w.bridgeOps.answer = (path, body) => {
      if (path === "scope-summary") return [{ agent: AGT, label, admittedOps: admitted, ...(sources !== undefined ? { sources } : {}) }, { agent: AGT2, label: "none" }];
      if (path === "catalog") {
        // the SDK marks per agent: AGT's owner row admits the update entry, AGT2 has none
        const mark = body?.agent === AGT ? { admitted: "owner" } : {};
        // S3-2: an UNSCOPED dynamic op (list or search) whose catalog marks an entry above the grant anyway (a mark the SDK would not give)
        if (body?.op === "notes_dyn_plain") return [entry("p_read", ["read"], "read"), entry("p_update", ["update"], "write", { admitted: "owner" })];
        if (body?.op === "notes_srch_plain" || body?.op === "notes_srch_s") return [entry("s_read", ["read"], "read"), entry("s_update", ["update"], "write", { admitted: "owner" })];
        return [entry("e_read", ["read"], "read"), entry("e_update", ["update"], "write", mark), entry("e_update_plain", ["update"], "write"), entry("e_delete", ["delete"], "destructive", { holdFamily: "destructive", ...mark })];
      }
      return [];
    };
  });
  after(async () => {
    await w.close();
  });

  // one MCP session for the whole file (a session per call would run into the bridge's request rate limit)
  let shared: { token: string; sid: string } | undefined;
  const session = async () => {
    if (shared) return shared;
    const token = await w.agentToken();
    const init = await w.mcp(token, { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test" } } });
    shared = { token, sid: init.session as string };
    return shared;
  };
  const toolNames = async () => {
    const s = await session();
    const r = await w.mcp(s.token, { jsonrpc: "2.0", id: 2, method: "tools/list" }, s.sid);
    return (r.json.result.tools as { name: string }[]).map((t) => t.name);
  };
  const callTool = async (name: string) => {
    const s = await session();
    const r = await w.mcp(s.token, { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name, arguments: {} } }, s.sid);
    return r.json.result as { isError?: boolean; structuredContent?: { error?: { code?: string } } };
  };
  const app = () => w.bridge.ctx.table?.apps.get(INS as never) as NonNullable<ReturnType<typeof appOrNone>>;
  const appOrNone = () => w.bridge.ctx.table?.apps.get(INS as never);

  test("before the app's scope summary: nothing above the grant is listed (fail closed), the ordinary ops are", async () => {
    const names = await toolNames();
    assert.ok(names.includes("notes__notes_s_read") && names.includes("notes__notes_list"));
    for (const n of ["notes_s_update", "notes_s_delete", "notes_u_update"]) assert.ok(!names.includes(`notes__${n}`), `${n} hidden`);
  });

  test("(a) the scope summary names an op: a scoped op above grant.crud is listed and forwarded; a bounded one is not; an unscoped one is not", async () => {
    admitted = ["notes_s_update", "notes_u_update", "not a valid id", 42];
    client = await claimApp(w);
    assert.equal(client.claimStatus, 200);
    assert.ok([200, 204].includes(await client.status({ scopesRev: 1 })));
    await waitFor(() => w.bridge.ctx.admittedOps.has(`${AGT}|${INS}`), 15000);
    // malformed members are dropped (display input is never trusted further than a well-formed op id)
    assert.deepEqual([...(w.bridge.ctx.admittedOps.get(`${AGT}|${INS}`) ?? [])].sort(), ["notes_s_update", "notes_u_update"]);
    assert.ok(!w.bridge.ctx.admittedOps.has(`${AGT2}|${INS}`), "an agent without admittedOps has none");

    const names = await toolNames();
    assert.ok(names.includes("notes__notes_s_update"), "owner-admitted scoped op above the grant: listed");
    assert.ok(!names.includes("notes__notes_s_delete"), "bounded scoped op above the grant: not listed");
    assert.ok(!names.includes("notes__notes_u_update"), "unscoped op above the grant: not listed, although the app names it");
    assert.ok(names.includes("notes__notes_s_read") && names.includes("notes__notes_list"), "grant-admitted ops are unchanged");

    const before = w.appLog.ops.filter((o) => o.op === "notes_s_update").length;
    const ok = await callTool("notes__notes_s_update");
    assert.equal(ok.isError, undefined, "forwarded to the app (the SDK decides)");
    assert.equal(w.appLog.ops.filter((o) => o.op === "notes_s_update").length, before + 1);
    for (const n of ["notes_s_delete", "notes_u_update"]) {
      const r = await callTool(`notes__${n}`);
      assert.equal(r.isError, true, n);
      assert.equal(r.structuredContent?.error?.code, "unknown_tool", n);
      assert.equal(w.appLog.ops.filter((o) => o.op === n).length, 0, `${n} never reached the app`);
    }
  });

  test("the admitted ops are display input only: never part of the StatusReport", () => {
    const report = buildStatusReport(w.bridge.ctx);
    const mine = report.scopeSummaries.filter((s) => s.ins === INS);
    assert.deepEqual(
      mine.map((s) => [s.agt, s.label]),
      [[AGT, "1 Notebook"], [AGT2, "none"]],
    );
    for (const s of mine) assert.deepEqual(Object.keys(s).sort(), ["agt", "ins", "label"]);
  });

  test("C331 D8 (spec 0.1.65): the app's sources reach the StatusReport cleaned; a change of sources alone pokes Portal; none from an old SDK", async () => {
    const c = (code: number) => String.fromCharCode(code);
    let health = 0;
    const count = () => {
      health += 1;
    };
    w.bridge.ctx.on("health", count);
    try {
      sources = [
        { type: "notebook", id: "nb_1", label: `Team${c(0x200b)} notes${c(0x202e)}${c(7)}`, access: "read" },
        { type: "Notebook", id: "nb_2", label: "bad type", access: "read" },
        { type: "notebook", id: "has space", label: "bad id", access: "read" },
        { type: "notebook", id: "nb_3", label: c(0x200b), access: "read" },
        "text",
        ...Array.from({ length: 30 }, (_, i) => ({ type: "notebook", id: `nb_x${i}`, label: `Book ${i}`, access: "read" })),
      ];
      await settle(["notes_s_update"]);
      const row = buildStatusReport(w.bridge.ctx).scopeSummaries.find((s) => s.ins === INS && s.agt === AGT) as { sources?: { id: string; label: string }[] } | undefined;
      assert.deepEqual(row?.sources?.[0], { type: "notebook", id: "nb_1", label: "Team notes", access: "read" });
      assert.equal(row?.sources?.length, 20 - 4, "the first 20 items are read; malformed ones are dropped, never repaired");
      assert.equal(health, 1, "new sources (same label): one health event");
      sources = undefined;
      await settle(["notes_s_update"]);
      const old = buildStatusReport(w.bridge.ctx).scopeSummaries.find((s) => s.ins === INS && s.agt === AGT);
      assert.deepEqual(Object.keys(old ?? {}).sort(), ["agt", "ins", "label"], "an SDK before 0.1.65 sends no sources: none forwarded");
    } finally {
      w.bridge.ctx.off("health", count);
      sources = undefined;
    }
  });

  test("a new scope summary without the op removes it from tools/list again", async () => {
    admitted = [];
    assert.ok([200, 204].includes(await client.status({ scopesRev: 2 })));
    await waitFor(() => !w.bridge.ctx.admittedOps.has(`${AGT}|${INS}`), 15000);
    assert.ok(!(await toolNames()).includes("notes__notes_s_update"));
    admitted = ["notes_s_update"];
    assert.ok([200, 204].includes(await client.status({ scopesRev: 3 })));
    await waitFor(() => w.bridge.ctx.admittedOps.has(`${AGT}|${INS}`), 15000);
    assert.ok((await toolNames()).includes("notes__notes_s_update"));
  });

  const summaryRequests = () => w.bridgeOps.seen.filter((x) => x.path === "scope-summary").length;
  const stale = () => w.bridge.ctx.scopeSummaryAt.set(INS as never, 0);

  let rev = 100;
  /** the owner's rows now admit exactly `ops`, and the app tells the bridge by a status push (scopesRev changes) */
  const settle = async (ops: string[]) => {
    admitted = ops;
    rev += 1;
    const t0 = Date.now();
    assert.ok([200, 204].includes(await client.status({ scopesRev: rev })));
    // the push started the app's scope-summary request; wait until it has been answered and applied
    await waitFor(() => (w.bridge.ctx.scopeSummaryAt.get(INS as never) ?? 0) >= t0 && w.bridge.ctx.scopeSummaryRuns.size === 0, 15000);
    assert.equal([...(w.bridge.ctx.admittedOps.get(`${AGT}|${INS}`) ?? [])].sort().join(), [...ops].sort().join());
  };

  test("a tools/call of an unlisted scoped op asks the app again (no status push needed); other names never cause a request", async () => {
    await settle([]);
    // the owner widened a row: the app's answer changes, but no push has told the bridge yet
    admitted = ["notes_s_update", "notes_s_delete"];
    stale();
    const n = summaryRequests();
    const r = await callTool("notes__notes_s_delete");
    assert.equal(r.isError, undefined, "listed after the on-demand refresh and forwarded to the app");
    assert.equal(summaryRequests(), n + 1);
    assert.ok(w.appLog.ops.some((o) => o.op === "notes_s_delete"));
    // names that are not a scoped static op of a granted app never cause a request
    stale();
    for (const name of ["notes__nope", "nothing__notes_s_delete", "notes__notes_u_update", "notes", "__x", "notes__notes_dyn"]) {
      assert.equal((await callTool(name)).structuredContent?.error?.code, "unknown_tool", name);
    }
    assert.equal(summaryRequests(), n + 1, "no request for names that cannot be admitted");
  });

  test("the load an agent can cause is bounded: a miss asks the app at most once per bound", async () => {
    await settle([]);
    stale();
    const m = summaryRequests();
    assert.equal((await callTool("notes__notes_s_delete")).structuredContent?.error?.code, "unknown_tool");
    assert.equal(summaryRequests(), m + 1);
    for (let i = 0; i < 5; i++) assert.equal((await callTool("notes__notes_s_delete")).structuredContent?.error?.code, "unknown_tool");
    assert.equal(summaryRequests(), m + 1, "five more misses inside the bound: no further request");
  });

  test("tools/list asks again only when the last answer is old", async () => {
    await settle([]);
    admitted = ["notes_s_update"];
    w.bridge.ctx.scopeSummaryAt.set(INS as never, Date.now());
    const n = summaryRequests();
    assert.ok(!(await toolNames()).includes("notes__notes_s_update"), "a fresh answer is not asked again");
    assert.equal(summaryRequests(), n);
    w.bridge.ctx.scopeSummaryAt.set(INS as never, Date.now() - 31_000);
    assert.ok((await toolNames()).includes("notes__notes_s_update"), "an old answer is asked again");
    assert.equal(summaryRequests(), n + 1);
    admitted = [];
    w.bridge.ctx.scopeSummaryAt.set(INS as never, Date.now() - 31_000);
    assert.ok(!(await toolNames()).includes("notes__notes_s_update"), "and a narrowed row leaves the list");
  });

  test("S3-2: a dynamic SEARCH op shows an admitted entry above the grant only when the op has a scopeType", async () => {
    const search = async (tool: string) => {
      const s = await session();
      const r = await w.mcp(s.token, { jsonrpc: "2.0", id: 9, method: "tools/call", params: { name: tool, arguments: { query: "x" } } }, s.sid);
      return ((r.json.result.structuredContent?.tools ?? []) as { tool: string }[]).map((t) => t.tool).sort();
    };
    assert.deepEqual(await search("notes__notes_srch_plain_search"), ["s_read"], "unscoped search op: the mark is not trusted");
    assert.deepEqual(await search("notes__notes_srch_s_search"), ["s_read", "s_update"], "scoped search op: the admitted entry is shown");
  });

  test("S4-1: Portal is poked (health) only when the labels change, not on every scope-summary answer", async () => {
    await settle(["notes_s_update"]);
    let health = 0;
    const count = () => {
      health += 1;
    };
    w.bridge.ctx.on("health", count);
    try {
      await settle(["notes_s_update"]);
      await settle(["notes_s_update", "notes_s_delete"]);
      assert.equal(health, 0, "same labels: no health event, also when the admitted ops changed");
      label = "2 Notebooks";
      await settle(["notes_s_update"]);
      assert.equal(health, 1, "a new label: one health event");
    } finally {
      w.bridge.ctx.off("health", count);
      label = "1 Notebook";
    }
    await settle(["notes_s_update"]);
  });

  test("S4-2: a failed scope-summary request clears the app's admitted ops (fail closed for display); the labels stay", async () => {
    await settle(["notes_s_update"]);
    assert.ok((await toolNames()).includes("notes__notes_s_update"));
    w.bridgeOps.status = 500;
    try {
      w.bridge.ctx.scopeSummaryAt.set(INS as never, Date.now() - 31_000);
      assert.ok(!(await toolNames()).includes("notes__notes_s_update"), "not listed after the failed request");
      assert.ok(!w.bridge.ctx.admittedOps.has(`${AGT}|${INS}`));
      assert.equal(w.bridge.ctx.scopeSummaries.get(`${AGT}|${INS}`)?.label, "1 Notebook", "the label is kept");
    } finally {
      w.bridgeOps.status = undefined;
    }
    await settle(["notes_s_update"]);
    assert.ok((await toolNames()).includes("notes__notes_s_update"), "listed again after a good answer");
  });

  test("S4-4: an agent without a grant to the app never causes its scope-summary request", async () => {
    const token = await w.agentTokenFor(AGT2, CON2);
    const init = await w.mcp(token, { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test" } } });
    const sid = init.session as string;
    stale();
    const n = summaryRequests();
    const list = await w.mcp(token, { jsonrpc: "2.0", id: 2, method: "tools/list" }, sid);
    assert.ok(!(list.json.result.tools as { name: string }[]).some((t) => t.name.startsWith("notes__")), "no tools of the app");
    for (const name of ["notes__notes_s_delete", "notes__notes_s_update"]) {
      const r = await w.mcp(token, { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name, arguments: {} } }, sid);
      assert.equal(r.json.result.isError, true, name);
      assert.equal(r.json.result.structuredContent?.error?.code, "unknown_tool", name);
    }
    assert.equal(summaryRequests(), n, "no request for an agent without a grant");
  });

  test("(b) the catalog body carries the agent; an entry marked admitted: owner is listed above grant.crud, within the op's ceilings", async () => {
    const names = await toolNames();
    const catalogBodies = w.bridgeOps.seen.filter((s) => s.path === "catalog").map((s) => s.body);
    assert.ok(catalogBodies.length >= 1);
    for (const b of catalogBodies) assert.deepEqual(Object.keys(b).sort(), "query" in b ? ["agent", "op", "query"] : ["agent", "op"], "op and agent (list); with the query (search)");
    for (const b of catalogBodies) assert.equal(b.agent, AGT);
    assert.ok(catalogBodies.some((b) => b.op === "notes_dyn"));
    assert.ok(names.includes("notes__e_read"), "within the grant");
    assert.ok(names.includes("notes__e_update"), "admitted: owner, above the grant, within the op ceiling");
    assert.ok(!names.includes("notes__e_update_plain"), "unmarked, above the grant: omitted");
    assert.ok(!names.includes("notes__e_delete"), "marked, but above the op's crudCeiling: omitted");
    const omitted = [...w.bridge.ctx.toolsOmitted.values()].filter((o) => o.code === "ceiling").map((o) => o.name).sort();
    assert.deepEqual(omitted, ["e_delete", "e_update_plain", "p_update"]);
    // S3-2: the mark counts only for a dynamic op WITH a scopeType
    assert.ok(names.includes("notes__p_read"), "unscoped dynamic list: within the grant, listed");
    assert.ok(!names.includes("notes__p_update"), "unscoped dynamic list: a mark above the grant is not trusted");
  });

  test("the catalog cache is per agent: another agent's marks are never shown to this one", async () => {
    const router = new CallRouter(w.bridge.ctx);
    w.bridgeOps.seen.length = 0;
    const a = await router.catalog(app(), "notes_dyn", AGT as never);
    const b = await router.catalog(app(), "notes_dyn", AGT2 as never);
    const again = await router.catalog(app(), "notes_dyn", AGT as never);
    assert.equal(w.bridgeOps.seen.filter((s) => s.path === "catalog").length, 2, "one request per agent, then cached");
    assert.deepEqual(w.bridgeOps.seen.map((s) => s.body.agent), [AGT, AGT2]);
    assert.equal(a.find((e) => e.name === "e_update")?.admitted, "owner");
    assert.equal(b.find((e) => e.name === "e_update")?.admitted, undefined);
    assert.deepEqual(again, a);
  });

  test("(c) gate: a scoped op above grant.crud is passed on to the SDK; an unscoped op above grant.crud is refused at the bridge", async () => {
    const router = new CallRouter(w.bridge.ctx);
    const target = (id: string) => ({ app: app(), op: app().ops.get(id) as never });
    const caller = { type: "agent" as const, agt: AGT as never, con: CON as never };
    const forwarded = (id: string) => w.appLog.ops.filter((o) => o.op === id).length;
    // scoped, above the grant, NOT in admittedOps: not listed, but gate() still passes it on (the SDK enforces scope_denied)
    const n = forwarded("notes_s_delete");
    const r = await router.route({ caller, target: target("notes_s_delete"), input: {} });
    assert.equal(r.result.status, "ok");
    assert.equal(forwarded("notes_s_delete"), n + 1, "reached the SDK");
    // unscoped, above the grant: refused by the bridge's gate
    const u = forwarded("notes_u_update");
    await assert.rejects(router.route({ caller, target: target("notes_u_update"), input: {} }), (e: { code?: string }) => e.code === "crud_exceeds_grant");
    assert.equal(forwarded("notes_u_update"), u, "never forwarded");
  });
});

describe("C283 A1: pause, revoke and expiry still refuse first (owner row or not)", () => {
  let w: World;
  const grantFor = (extra: Record<string, unknown> = {}) =>
    w.signPortal("tb-grant+jwt", { iss: "tb:portal", sub: `tb:agt:${AGT}`, aud: `tb:ins:${INS}`, iat: now(), exp: now() + 3600, jti: w.api.ulid(), ws: WS, cnf: { brg: BRG }, crud: ["read", "create"], mode: "free", held: [], caps: {}, wf: [], polrev: 1, ...extra });
  const forwarded = (id: string) => w.appLog.ops.filter((o) => o.op === id).length;
  const route = (router: CallRouter) => router.route({ caller: { type: "agent", agt: AGT as never, con: CON as never }, target: { app: w.bridge.ctx.table?.apps.get(INS as never) as never, op: w.bridge.ctx.table?.apps.get(INS as never)?.ops.get("notes_s_update") as never }, input: {} });

  before(async () => {
    w = await makeWorld({ real: true });
    w.updateAppTo(manifest);
    await w.publish();
    await waitFor(() => !!w.bridge.ctx.table?.apps.get(INS as never)?.ops.has("notes_s_update"), 15000);
    w.bridgeOps.answer = (path) => (path === "scope-summary" ? [{ agent: AGT, label: "1 Notebook", admittedOps: ["notes_s_update"] }] : []);
    const client = await claimApp(w);
    assert.ok([200, 204].includes(await client.status({ scopesRev: 1 })));
    await waitFor(() => w.bridge.ctx.admittedOps.has(`${AGT}|${INS}`), 15000);
  });
  after(async () => {
    await w.close();
  });

  test("the owner-admitted op runs while the grant is valid", async () => {
    const router = new CallRouter(w.bridge.ctx);
    const n = forwarded("notes_s_update");
    assert.equal((await route(router)).result.status, "ok");
    assert.equal(forwarded("notes_s_update"), n + 1);
  });

  test("expiry (the grant's own exp): an expired companion grant is refused grant_expired, a valid one passes the same scoped op above its crud", async () => {
    const router = new CallRouter(w.bridge.ctx);
    const a = w.bridge.ctx.table?.apps.get(INS as never);
    const target = { app: a as never, op: a?.ops.get("notes_s_update") as never };
    const companion = (extra: Record<string, unknown> = {}) => grantFor({ sub: `tb:ins:${INS}`, crud: ["read"], mode: "bound", held: ["money"], wf: ["notes_s_update"], ...extra });
    const n = forwarded("notes_s_update");
    assert.equal((await router.route({ caller: { type: "app", ins: INS as never, grant: await companion() }, target, input: {} })).result.status, "ok", "valid grant, op above its crud: passed on to the SDK");
    assert.equal(forwarded("notes_s_update"), n + 1);
    await assert.rejects(router.route({ caller: { type: "app", ins: INS as never, grant: await companion({ iat: now() - 7200, exp: now() - 3600 }) }, target, input: {} }), (e: { code?: string }) => e.code === "grant_expired");
    assert.equal(forwarded("notes_s_update"), n + 1, "the expired grant forwarded nothing");
  });

  test("revoke: a revoked grant is refused and nothing is forwarded; the op is not listed", async () => {
    const g = await grantFor();
    const jti = JSON.parse(Buffer.from(g.split(".")[1] as string, "base64url").toString("utf8")).jti as string;
    await w.publish((c) => {
      c.grants = [g];
      c.revoked = { jtis: [{ jti, exp: now() + 3600 }] } as never;
    });
    await waitFor(() => w.bridge.ctx.table?.rev === w.rev(), 15000);
    const router = new CallRouter(w.bridge.ctx);
    const n = forwarded("notes_s_update");
    await assert.rejects(route(router), (e: { code?: string }) => e.code === "no_grant" || e.code === "grant_revoked");
    assert.equal(forwarded("notes_s_update"), n);
    const token = await w.agentToken();
    const init = await w.mcp(token, { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test" } } });
    const list = await w.mcp(token, { jsonrpc: "2.0", id: 2, method: "tools/list" }, init.session as string);
    assert.ok(!(list.json.result.tools as { name: string }[]).some((t) => t.name === "notes__notes_s_update"));
  });

  test("pause: a paused agent lists nothing and its call is refused paused, with an owner-admitted op", async () => {
    const g = await grantFor();
    await w.publish((c) => {
      c.grants = [g];
      c.pause = { workspace: false, agents: [AGT as never], instances: [] };
    });
    await waitFor(() => w.bridge.ctx.table?.rev === w.rev(), 15000);
    const router = new CallRouter(w.bridge.ctx);
    const n = forwarded("notes_s_update");
    await assert.rejects(route(router), (e: { code?: string }) => e.code === "paused");
    assert.equal(forwarded("notes_s_update"), n);
    const token = await w.agentToken();
    const init = await w.mcp(token, { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test" } } });
    const list = await w.mcp(token, { jsonrpc: "2.0", id: 2, method: "tools/list" }, init.session as string);
    assert.deepEqual(list.json.result.tools, []);
  });

  test("resuming asks the app for its marks again (a pause does not change scopesRev)", async () => {
    const g = await grantFor();
    w.bridgeOps.seen.length = 0;
    await w.publish((c) => {
      c.grants = [g];
    });
    await waitFor(() => w.bridge.ctx.table?.rev === w.rev(), 15000);
    await waitFor(() => w.bridgeOps.seen.some((s) => s.path === "scope-summary"), 15000);
  });
});
