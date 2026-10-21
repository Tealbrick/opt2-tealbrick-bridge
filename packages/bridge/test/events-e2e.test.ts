/**
 * Bridge 0.2.7 (spec 0.1.57, BRIDGE §14.1 and §14.3; C274c/C274d): app events on the wire, against a real bridge.
 *  - `POST /tb/v1/events` on the internal listener: instance assertion (htm, htu, bd), app instance only, whole-request
 *    answers (401, 403, 413, 400, 429 = the companion-call bucket), per-item results;
 *  - `tealbrick/events/{list,poll,stream}` on the agent's EXISTING `/mcp` session and the `notifications/tealbrick/event`
 *    frames on its GET stream (SSE `id:` = event id, no `id:` on other frames), Last-Event-ID, a second `stream` that replaces
 *    the subscription and re-sends the backlog, cursor_invalid, pause, restart;
 *  - G2b: a name only the update candidate declares (the bridge fetches the candidate's manifest), held until the switch;
 *  - rule 6 with the guard app's before hook.
 * The store's rules in detail: events-store.test.ts.
 */
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import { TYP } from "@opt2-tealbrick/spec/credentials";
import type { Ed25519KeyPair } from "@opt2-tealbrick/spec/sdk";
import { issueAccess, revokeLocal, rotateRefresh } from "../src/identity.ts";
import { type Agent, agentSession, ev, eventsManifest, item, listenOn, nOf, op, postEvents } from "./support/events.ts";
import { AGT, AGT2, CON, INS, makeWorld, type World, waitFor } from "./support/world.ts";

const CON2 = "con_01HBBBBBBBBBBBBBBBBBBBBBBB";
const NOTIFY = "notifications/tealbrick/event";
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

interface EvWorld {
  w: World;
  appKey: Ed25519KeyPair;
  svcKey: Ed25519KeyPair;
  digest: string;
}

/** A real bridge whose notes app declares events; the app's key (and a service key) listed; AGT2 has a connection, no grant. */
async function eventsWorld(o: { withHook?: boolean } = {}): Promise<EvWorld> {
  const w = await makeWorld({ real: true, ...o });
  const appKey = await w.api.generateKeyPair();
  const svcKey = await w.api.generateKeyPair();
  const digest = w.updateAppTo(eventsManifest("2.0.0"));
  await w.amend((c) => {
    c.instanceKeys.push({ ins: INS, jwk: appKey.publicJwk } as never, { ins: INS, svc: "engine", jwk: svcKey.publicJwk } as never);
    c.connections.push({ con: CON2, agt: AGT2, method: "key", gen: 1, publicKey: w.agentKey.publicJwk, status: "active" } as never);
  });
  await waitFor(() => w.bridge.ctx.table?.rev === w.rev() && w.bridge.ctx.table?.apps.get(INS as never)?.digest === digest, 15000);
  return { w, appKey, svcKey, digest };
}

const okResult = (r: { status: number; json: any }) => {
  assert.equal(r.status, 200, JSON.stringify(r.json));
  return r.json.results as { key: string; status: string; code?: string; recipients?: number }[];
};

describe("app events on the wire (bridge 0.2.7)", () => {
  let e: EvWorld;
  let a1: Agent;
  before(async () => {
    e = await eventsWorld();
    a1 = await agentSession(e.w, AGT, CON);
  });
  after(async () => {
    await e.w.close();
  });

  test("ingest: per-item results in order; unauthenticated → 401; a companion service → 403; > 512 KiB → 413; no items or > 100 → 400", async () => {
    const items = [item({ n: 1 }), item({ name: "note.unknown" })];
    const r = okResult(await postEvents(e.w, e.appKey, items));
    assert.deepEqual(r.map((x) => [x.key, x.status, x.code ?? null]), [
      [items[0]?.key, "stored", null],
      [items[1]?.key, "refused", "event_undeclared"],
    ]);
    const stranger = await e.w.api.generateKeyPair();
    assert.equal((await postEvents(e.w, stranger, [item()])).status, 401);
    const noAssert = await fetch(`${e.w.internalUrl}/tb/v1/events`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ items: [item()] }) });
    assert.equal(noAssert.status, 401);
    await noAssert.body?.cancel();
    const svc = await postEvents(e.w, e.svcKey, [item()], { svc: "engine" });
    assert.equal(svc.status, 403);
    const huge = Buffer.from(JSON.stringify({ items: [item({ pad: "x".repeat(600 * 1024) })] }));
    assert.equal((await postEvents(e.w, e.appKey, [], { raw: huge })).status, 413);
    assert.equal((await postEvents(e.w, e.appKey, [])).status, 400);
    assert.equal((await postEvents(e.w, e.appKey, Array.from({ length: 101 }, () => item()))).status, 400);
  });

  test("B-EV-1: stream, then the GET stream carries the event within 3 s; SSE id = event.id; other frames carry no id", async () => {
    const head = await a1.rpc("tealbrick/events/poll", { limit: 100 });
    let cursor = head.result.cursor as string | null;
    for (let more = head.result.events.length === 100; more; ) {
      const p = await a1.rpc("tealbrick/events/poll", { cursor, limit: 100 });
      cursor = p.result.cursor;
      more = p.result.events.length === 100;
    }
    const st = await a1.rpc("tealbrick/events/stream", cursor ? { cursor } : {});
    assert.deepEqual(st.result, { cursor, truncated: false });
    const l = a1.listen();
    await l.ready;
    try {
      const t0 = Date.now();
      okResult(await postEvents(e.w, e.appKey, [item({ n: 101, summary: "Hi" })]));
      const f = await l.until((x) => x.msg.method === NOTIFY && nOf(x.msg.params.event) === 101, 3000);
      assert.ok(Date.now() - t0 < 3000);
      assert.equal(f.id, f.msg.params.event.id);
      assert.equal(f.msg.params.event.type, "notes.note.created");
      assert.equal(f.msg.params.event.summary, "Hi");
      assert.equal(f.msg.params.event.origin, f.msg.params.event.id);
      // a list_changed on the same stream has no id: (Last-Event-ID always names the last event)
      await a1.rpc("tools/list");
      await e.w.publish((c) => {
        c.grants = [];
      });
      await waitFor(() => e.w.bridge.ctx.table?.rev === e.w.rev(), 15000);
      await l.until((x) => x.msg.method === "notifications/tools/list_changed", 5000);
      for (const x of l.frames) assert.equal(x.id !== undefined, x.msg.method === NOTIFY, JSON.stringify(x));
    } finally {
      l.close();
      await e.w.publish();
      await waitFor(() => e.w.bridge.ctx.table?.rev === e.w.rev(), 15000);
    }
  });

  test("Last-Event-ID resumes the subscription; a second stream call replaces it and re-sends the backlog after its cursor", async () => {
    const c0 = (await a1.rpc("tealbrick/events/poll", { cursor: "7ZZZZZZZZZZZZZZZZZZZZZZZZZ" })).result.cursor;
    assert.equal(c0, "7ZZZZZZZZZZZZZZZZZZZZZZZZZ", "a ULID newer than every row: nothing yet, not an error");
    const start = await a1.rpc("tealbrick/events/poll", { limit: 100 });
    let cursor = start.result.cursor as string | null;
    for (let more = start.result.events.length === 100; more; ) {
      const p = await a1.rpc("tealbrick/events/poll", { cursor, limit: 100 });
      cursor = p.result.cursor;
      more = p.result.events.length === 100;
    }
    await a1.rpc("tealbrick/events/stream", { cursor });
    const l1 = a1.listen();
    await l1.ready;
    okResult(await postEvents(e.w, e.appKey, [item({ n: 201 }), item({ n: 202 })]));
    const f1 = await l1.until((x) => x.msg.method === NOTIFY && nOf(x.msg.params.event) === 201);
    await l1.until((x) => x.msg.method === NOTIFY && nOf(x.msg.params.event) === 202);
    l1.close();
    await sleep(100);
    // while no GET is open nothing is lost
    okResult(await postEvents(e.w, e.appKey, [item({ n: 203 })]));
    await sleep(200);
    const l2 = a1.listen(f1.id);
    try {
      await l2.until((x) => x.msg.method === NOTIFY && nOf(x.msg.params.event) === 203);
      const got = l2.frames.filter((x) => x.msg.method === NOTIFY).map((x) => nOf(x.msg.params.event));
      assert.deepEqual(got, [202, 203], "resumed after Last-Event-ID, without a new stream call");
      // a second stream call on the same session: the subscription is replaced and the backlog after ITS cursor framed again
      const r = await a1.rpc("tealbrick/events/stream", { cursor });
      assert.equal(r.result.cursor, cursor);
      await waitFor(() => l2.frames.filter((x) => x.msg.method === NOTIFY).length >= 5, 3000);
      assert.deepEqual(
        l2.frames.filter((x) => x.msg.method === NOTIFY).map((x) => nOf(x.msg.params.event)),
        [202, 203, 201, 202, 203],
      );
    } finally {
      l2.close();
    }
  });

  test("cursor_invalid: a cursor this bridge did not issue → JSON-RPC -32602 with data.code; for poll and stream", async () => {
    for (const method of ["tealbrick/events/poll", "tealbrick/events/stream"]) {
      for (const cursor of ["not-a-ulid", 42, "01hzzzzzzzzzzzzzzzzzzzzzzz"]) {
        const r = await a1.rpc(method, { cursor });
        assert.equal(r.error?.code, -32602, `${method} ${JSON.stringify(cursor)}: ${JSON.stringify(r)}`);
        assert.deepEqual(r.error?.data, { code: "cursor_invalid" });
      }
    }
    // limit is clamped to 1..100
    okResult(await postEvents(e.w, e.appKey, [item({ n: 301 }), item({ n: 302 })]));
    const p = await a1.rpc("tealbrick/events/poll", { limit: 0 });
    assert.equal(p.result.events.length, 1);
  });

  test("B-EV-2 on the wire: an agent with no grant gets no list entry and nothing in its poll", async () => {
    const a2 = await agentSession(e.w, AGT2, CON2);
    okResult(await postEvents(e.w, e.appKey, [item({ n: 401 })]));
    const l = await a2.rpc("tealbrick/events/list");
    assert.deepEqual(l.result, { types: [] });
    const p = await a2.rpc("tealbrick/events/poll", {});
    assert.deepEqual(p.result.events, []);
    const mine = await a1.rpc("tealbrick/events/list");
    assert.deepEqual(
      mine.result.types.map((x: { type: string }) => x.type),
      ["notes.note.created", "notes.note.pinged", "notes.note.shared", "notes.note.edited", "tb.hold.decided"],
    );
  });

  test("agent pause: poll and stream answer paused (cursor unchanged); the subscription stays and frames start on resume", async () => {
    const c = "01HZZZZZZZZZZZZZZZZZZZZZZZ";
    const cur = (await a1.rpc("tealbrick/events/poll", { cursor: c })).result.cursor;
    await e.w.publish((cfg) => {
      cfg.pause.agents = [AGT as never];
    });
    await waitFor(() => e.w.bridge.ctx.table?.pausedAgents.has(AGT as never) === true, 15000);
    try {
      assert.deepEqual((await a1.rpc("tealbrick/events/poll", { cursor: cur })).result, { events: [], cursor: cur, truncated: false, paused: true });
      const st = await a1.rpc("tealbrick/events/stream", { cursor: cur });
      assert.deepEqual(st.result, { cursor: cur, truncated: false, paused: true });
      const l = a1.listen();
      await l.ready;
      try {
        okResult(await postEvents(e.w, e.appKey, [item({ n: 501 })]));
        await sleep(700);
        assert.equal(l.frames.filter((x) => x.msg.method === NOTIFY).length, 0, "nothing while paused");
        await e.w.publish();
        await waitFor(() => e.w.bridge.ctx.table?.rev === e.w.rev(), 15000);
        await l.until((x) => x.msg.method === NOTIFY && nOf(x.msg.params.event) === 501, 3000);
      } finally {
        l.close();
      }
    } finally {
      await e.w.publish();
      await waitFor(() => e.w.bridge.ctx.table?.rev === e.w.rev(), 15000);
    }
  });

  test("a restart keeps the log; ids keep increasing above the last one", async () => {
    okResult(await postEvents(e.w, e.appKey, [item({ n: 601 })]));
    const before = e.w.bridge.ctx.events?.rows(AGT) ?? [];
    const last = before.at(-1)?.id as string;
    await e.w.restart();
    await waitFor(() => e.w.bridge.ctx.table?.rev === e.w.rev() && !!e.w.bridge.ctx.table?.apps.get(INS as never)?.manifest, 15000);
    const after = e.w.bridge.ctx.events?.rows(AGT) ?? [];
    assert.deepEqual(after.map((r) => r.id), before.map((r) => r.id));
    a1 = await agentSession(e.w, AGT, CON);
    okResult(await postEvents(e.w, e.appKey, [item({ n: 602 })]));
    const p = await a1.rpc("tealbrick/events/poll", { cursor: last });
    assert.deepEqual(p.result.events.map(nOf), [602]);
    assert.ok(p.result.events[0].id > last);
  });

  test("the rate limit is the companion-call bucket of the instance: a burst past it → 429 with Retry-After", async () => {
    let limited: { status: number; headers: Headers } | undefined;
    for (let i = 0; i < 45 && !limited; i++) {
      const r = await postEvents(e.w, e.appKey, [item({ n: 700 + i })]);
      if (r.status === 429) limited = r;
      else assert.equal(r.status, 200);
    }
    assert.ok(limited, "no 429 within 45 requests");
    assert.ok(Number(limited.headers.get("retry-after")) >= 1);
  });
});

describe("G2b: a name only the update candidate declares (bridge 0.2.7)", () => {
  let e: EvWorld;
  before(async () => {
    e = await eventsWorld();
  });
  after(async () => {
    await e.w.close();
  });

  test("the bridge fetches the candidate's manifest, stores the event HELD, and releases it with a new id at the switch; a rollback drops it", async () => {
    const a1 = await agentSession(e.w, AGT, CON);
    const mCand = eventsManifest("3.0.0", [op("notes_archive", ["read"], "read")], [ev("note.archived", "notes_archive")]);
    const cand = e.w.updateAppTo(mCand);
    await e.w.publish((c) => {
      const a = c.apps[0] as unknown as Record<string, unknown>;
      a.manifestDigest = e.digest;
      a.version = "2.0.0";
      a.candidateManifestDigest = cand;
      a.candidateVersion = "3.0.0";
    });
    await waitFor(() => e.w.bridge.ctx.table?.rev === e.w.rev(), 15000);
    assert.equal(e.w.bridge.ctx.table?.apps.get(INS as never)?.digest, e.digest, "the serving manifest is the one the bridge holds");
    const r = okResult(await postEvents(e.w, e.appKey, [item({ name: "note.archived", n: 1 }), item({ n: 2 })]));
    assert.deepEqual(r.map((x) => [x.status, x.recipients]), [
      ["stored", 1],
      ["stored", 1],
    ]);
    const p0 = await a1.rpc("tealbrick/events/poll", {});
    assert.deepEqual(p0.result.events.map(nOf), [2], "held while the attempt runs");
    // the switch: the candidate becomes the serving release
    await e.w.publish();
    await waitFor(() => e.w.bridge.ctx.table?.rev === e.w.rev() && e.w.bridge.ctx.table?.apps.get(INS as never)?.digest === cand, 15000);
    const p1 = await a1.rpc("tealbrick/events/poll", { cursor: p0.result.cursor });
    assert.deepEqual(p1.result.events.map(nOf), [1]);
    assert.notEqual(p1.result.events[0].id, p1.result.events[0].origin);
    // a second attempt that is rolled back: its held rows are dropped
    const mCand2 = eventsManifest("4.0.0", [op("notes_archive", ["read"], "read"), op("notes_flag", ["read"], "read")], [ev("note.archived", "notes_archive"), ev("note.flagged", "notes_flag")]);
    const cand2 = e.w.updateAppTo(mCand2);
    await e.w.publish((c) => {
      const a = c.apps[0] as unknown as Record<string, unknown>;
      a.manifestDigest = cand;
      a.version = "3.0.0";
      a.candidateManifestDigest = cand2;
      a.candidateVersion = "4.0.0";
    });
    await waitFor(() => e.w.bridge.ctx.table?.rev === e.w.rev(), 15000);
    okResult(await postEvents(e.w, e.appKey, [item({ name: "note.flagged", n: 3 })]));
    assert.equal(e.w.bridge.ctx.events?.rows(AGT).filter((x) => x.held).length, 1);
    await e.w.amend((c) => {
      const a = c.apps[0] as unknown as Record<string, unknown>;
      a.manifestDigest = cand;
      a.version = "3.0.0";
    });
    await waitFor(() => e.w.bridge.ctx.table?.rev === e.w.rev(), 15000);
    assert.equal(e.w.bridge.ctx.events?.rows(AGT).filter((x) => x.held).length, 0);
    const p2 = await a1.rpc("tealbrick/events/poll", { cursor: p1.result.cursor });
    assert.deepEqual(p2.result.events, []);
  });
});

describe("rule 6 on the wire: the guard app's before hook strips the summary (bridge 0.2.7)", () => {
  let e: EvWorld;
  before(async () => {
    e = await eventsWorld({ withHook: true });
  });
  after(async () => {
    await e.w.close();
  });

  test("B-EV-9: hook enabled → no summary; every hook switched off by the owner → with it", async () => {
    const a1 = await agentSession(e.w, AGT, CON);
    okResult(await postEvents(e.w, e.appKey, [item({ n: 1, summary: "Body text" })]));
    const p1 = await a1.rpc("tealbrick/events/poll", {});
    assert.equal(p1.result.events[0].summary, undefined);
    await e.w.publish((c) => {
      for (const h of c.hooks) h.enabled = false;
    });
    await waitFor(() => e.w.bridge.ctx.table?.rev === e.w.rev(), 15000);
    okResult(await postEvents(e.w, e.appKey, [item({ n: 2, summary: "Body text" })]));
    const p2 = await a1.rpc("tealbrick/events/poll", { cursor: p1.result.cursor });
    assert.equal(p2.result.events[0].summary, "Body text");
  });
});

describe("review round 1 (bridge#16) S1: an open stream is re-authorized before every flush (bridge 0.2.7)", () => {
  let e: EvWorld;
  const CON3 = "con_01HCCCCCCCCCCCCCCCCCCCCCCC";
  const CON4 = "con_01HDDDDDDDDDDDDDDDDDDDDDDD";
  const CON5 = "con_01HEEEEEEEEEEEEEEEEEEEEEEE";
  const CON6 = "con_01HFFFFFFFFFFFFFFFFFFFFFFF";
  before(async () => {
    e = await eventsWorld();
    await e.w.amend((c) => {
      for (const con of [CON3, CON4, CON5, CON6]) c.connections.push({ con, agt: AGT, method: "key", gen: 1, publicKey: e.w.agentKey.publicJwk, status: "active" } as never);
    });
    await waitFor(() => e.w.bridge.ctx.table?.connections.has(CON6 as never) === true, 15000);
  });
  after(async () => {
    await e.w.close();
  });

  const openStream = async (con: string, token?: string) => {
    const a = await agentSession(e.w, AGT, con, token);
    const st = await a.rpc("tealbrick/events/stream", { cursor: "7ZZZZZZZZZZZZZZZZZZZZZZZZY" });
    assert.ok(st.result, JSON.stringify(st));
    // from the current end: a fresh poll cursor
    let cursor: string | null = null;
    for (;;) {
      const p = await a.rpc("tealbrick/events/poll", { ...(cursor ? { cursor } : {}), limit: 100 });
      cursor = p.result.cursor;
      if (p.result.events.length < 100) break;
    }
    await a.rpc("tealbrick/events/stream", cursor ? { cursor } : {});
    const l = a.listen();
    await l.ready;
    return { a, l };
  };

  test("C274f: event A delivered; the connection is revoked by a config swap mid-stream; event B → no frame, no summary text of B on the socket, the stream and session are ended", async () => {
    const { a, l } = await openStream(CON3);
    try {
      okResult(await postEvents(e.w, e.appKey, [item({ n: 1, summary: "summary-of-A" })]));
      await l.until((x) => x.msg.method === NOTIFY && nOf(x.msg.params.event) === 1);
      await e.w.amend((c) => {
        (c.connections.find((x) => x.con === CON3) as unknown as Record<string, unknown>).status = "revoked";
      });
      await waitFor(() => e.w.bridge.ctx.table?.rev === e.w.rev(), 15000);
      okResult(await postEvents(e.w, e.appKey, [item({ n: 2, summary: "SECRET-summary-of-B" })]));
      await waitFor(() => l.ended(), 3000);
      await sleep(300);
      assert.ok(!l.frames.some((x) => x.msg.method === NOTIFY && nOf(x.msg.params.event) === 2), "no frame for B");
      assert.ok(!l.raw().includes("SECRET-summary-of-B"), "no summary text of B on the socket");
      assert.ok(l.raw().includes("summary-of-A"), "A was delivered before");
      const after = await e.w.mcp(a.token, { jsonrpc: "2.0", id: 99, method: "tealbrick/events/poll", params: {} }, a.sid);
      assert.equal(after.status, 401, "the old token no longer authenticates");
    } finally {
      l.close();
    }
  });

  test("C274f (round 2): a Portal gen rotation closes the old stream at once (no frame, no summary of B); the session and its subscription stay; a current-gen GET with Last-Event-ID resumes with B exactly once", async () => {
    const { a, l } = await openStream(CON4);
    try {
      okResult(await postEvents(e.w, e.appKey, [item({ n: 11, summary: "summary-of-A" })]));
      const fa = await l.until((x) => x.msg.method === NOTIFY && nOf(x.msg.params.event) === 11);
      await e.w.amend((c) => {
        (c.connections.find((x) => x.con === CON4) as unknown as Record<string, unknown>).gen = 2;
      });
      await waitFor(() => e.w.bridge.ctx.table?.rev === e.w.rev(), 15000);
      await waitFor(() => l.ended(), 3000);
      okResult(await postEvents(e.w, e.appKey, [item({ n: 12, summary: "SECRET-summary-of-B" })]));
      await sleep(300);
      assert.ok(!l.raw().includes("SECRET-summary-of-B"));
      // a token of the current gen on the SAME session: the subscription is still there
      const fresh = await e.w.agentTokenFor(AGT, CON4);
      const r = await e.w.mcp(fresh, { jsonrpc: "2.0", id: 7, method: "ping" }, a.sid);
      assert.equal(r.status, 200, "the session survived the rotation");
      const l3 = listenOn(e.w, fresh, a.sid, fa.id);
      try {
        await l3.until((x) => x.msg.method === NOTIFY && nOf(x.msg.params.event) === 12);
        await sleep(300);
        assert.deepEqual(l3.frames.filter((x) => x.msg.method === NOTIFY).map((x) => nOf(x.msg.params.event)), [12], "B once, A not again");
      } finally {
        l3.close();
      }
    } finally {
      l.close();
    }
  });

  test("round 2: a pairing refresh mid-stream closes the old-gen stream; session + subscription kept; the new token's GET with Last-Event-ID resumes with no loss and no duplicate", async () => {
    const ctx = e.w.bridge.ctx;
    const PCON = "con_01HPPPPPPPPPPPPPPPPPPPPPPP";
    const refresh = "tbr_round2pairingrefresh";
    const now = Math.floor(Date.now() / 1000);
    ctx.state.connections.set(PCON as never, { con: PCON, agt: AGT, refreshDigest: ctx.api.opaqueDigest(refresh), gen: 1, previousDigest: null, previousUntil: null, previousUsed: false, expiresAt: now + 3600, clientName: "pairing-test", createdAt: now, reported: false } as never);
    const t1 = await issueAccess(ctx, AGT as never, PCON as never, 1);
    const { a, l } = await openStream(PCON, t1);
    try {
      okResult(await postEvents(e.w, e.appKey, [item({ n: 21, summary: "first" })]));
      const fa = await l.until((x) => x.msg.method === NOTIFY && nOf(x.msg.params.event) === 21);
      const { rec } = rotateRefresh(ctx, refresh); // gen 2 (what /oauth/token does)
      assert.equal(rec.gen, 2);
      const t2 = await issueAccess(ctx, AGT as never, PCON as never, rec.gen);
      okResult(await postEvents(e.w, e.appKey, [item({ n: 22, summary: "SECRET-second" }), item({ n: 23 })]));
      await waitFor(() => l.ended(), 3000);
      assert.ok(!l.raw().includes("SECRET-second"), "nothing to the old-gen stream");
      const l2 = listenOn(e.w, t2, a.sid, fa.id);
      try {
        await l2.until((x) => x.msg.method === NOTIFY && nOf(x.msg.params.event) === 23);
        await sleep(300);
        assert.deepEqual(l2.frames.filter((x) => x.msg.method === NOTIFY).map((x) => nOf(x.msg.params.event)), [22, 23]);
      } finally {
        l2.close();
      }
      // the old token cannot open a stream any more
      const old = await fetch(`${e.w.publicUrl}/mcp`, { headers: { authorization: `Bearer ${t1}`, "mcp-session-id": a.sid, accept: "text/event-stream" } });
      assert.equal(old.status, 401);
      await old.body?.cancel();
    } finally {
      l.close();
      ctx.state.connections.delete(PCON as never);
    }
  });

  for (const how of ["revokeLocal", "a connection state change without a table event"] as const) {
    test(`round 2: a flush already queued when the connection is revoked (${how}) writes no frame`, async () => {
      const ctx = e.w.bridge.ctx;
      const con = how === "revokeLocal" ? CON5 : CON6;
      const { l } = await openStream(con);
      try {
        const t = ctx.table as NonNullable<typeof ctx.table>;
        const app = t.apps.get(INS as never);
        assert.ok(app && ctx.events);
        const { agents } = ctx.events.ingest(t, app, [item({ n: 31, summary: "SECRET-queued" })]);
        ctx.emit("events-stored", agents); // the flush is now queued (setImmediate)
        if (how === "revokeLocal") revokeLocal(ctx, con as never, "client_revoke");
        else (t.connections.get(con as never) as unknown as Record<string, unknown>).status = "revoked";
        await sleep(500);
        assert.ok(!l.raw().includes("SECRET-queued"));
        assert.ok(!l.frames.some((x) => x.msg.method === NOTIFY && nOf(x.msg.params.event) === 31));
        await waitFor(() => l.ended(), 3000);
      } finally {
        l.close();
      }
    });
  }

  test("a stream ends at its token's expiry (the client reconnects with a fresh token and Last-Event-ID)", async () => {
    const ctx = e.w.bridge.ctx;
    const id = ctx.identity;
    assert.ok(id && ctx.table);
    const now = Math.floor(Date.now() / 1000);
    const short = await ctx.api.signJws(TYP.agentSession, { iss: ctx.bridgeRef, sub: `tb:agt:${AGT}`, aud: ctx.bridgeRef, iat: now, exp: now + 3, jti: ctx.api.ulid(), ws: ctx.table.ws, con: CON, gen: 1 } as never, id.key);
    const { l } = await openStream(CON, short);
    try {
      await waitFor(() => l.ended(), 6000);
      okResult(await postEvents(e.w, e.appKey, [item({ n: 3, summary: "after-expiry" })]));
      await sleep(300);
      assert.ok(!l.raw().includes("after-expiry"));
    } finally {
      l.close();
    }
  });
});

describe("review round 1 (bridge#16) S2: event-log failures never take the bridge down (bridge 0.2.7)", () => {
  let e: EvWorld;
  before(async () => {
    e = await eventsWorld();
  });
  after(async () => {
    await e.w.close();
  });

  test("a storage failure (READONLY) → ingest 503 at once; after 5 min unhealthy the cap goes (methods -32601, reports without events); 3 good probes bring it back", async () => {
    const store = e.w.bridge.ctx.events;
    assert.ok(store);
    const real = store.now;
    let clock = real();
    store.now = () => clock;
    try {
      const a1 = await agentSession(e.w, AGT, CON);
      store.exec("PRAGMA query_only = 1");
      assert.equal((await postEvents(e.w, e.appKey, [item({ n: 1 })])).status, 503);
      assert.equal((await postEvents(e.w, e.appKey, [item({ n: 1 })])).status, 503, "unhealthy: refused before the store");
      assert.ok((await a1.rpc("tealbrick/events/list")).result, "inside the window the cap and the methods stay");
      clock += 5 * 60_000;
      store.probe();
      assert.equal((await a1.rpc("tealbrick/events/list")).error?.code, -32601);
      await waitFor(() => !(e.w.acks.at(-1)?.bridge.caps ?? []).includes("events"), 15000);
      // config applies still work while the store is down
      await e.w.publish();
      await waitFor(() => e.w.bridge.ctx.table?.rev === e.w.rev(), 15000);
      store.exec("PRAGMA query_only = 0");
      for (let i = 0; i < 3; i++) {
        clock += 60_000;
        assert.equal(store.probe(), true);
      }
      await waitFor(() => (e.w.acks.at(-1)?.bridge.caps ?? []).includes("events"), 15000);
      okResult(await postEvents(e.w, e.appKey, [item({ n: 2 })]));
      assert.ok((await a1.rpc("tealbrick/events/list")).result);
    } finally {
      store.now = real;
    }
  });

  test("a corrupt events.db at boot is moved aside; the bridge starts with a fresh log and declares events", async () => {
    const { writeFileSync, readdirSync } = await import("node:fs");
    const { join } = await import("node:path");
    await e.w.bridge.stop();
    const dir = join(e.w.dataDir, "bridge");
    for (const f of ["events.db-wal", "events.db-shm"]) writeFileSync(join(dir, f), "");
    writeFileSync(join(dir, "events.db"), "garbage ".repeat(1000));
    await e.w.restart();
    await waitFor(() => e.w.bridge.ctx.table?.rev === e.w.rev() && !!e.w.bridge.ctx.table?.apps.get(INS as never)?.manifest, 15000);
    assert.ok(readdirSync(dir).some((f) => f.startsWith("events.db.corrupt-")));
    assert.equal(e.w.bridge.ctx.events?.healthy, true);
    okResult(await postEvents(e.w, e.appKey, [item({ n: 3 })]));
    const acks = e.w.acks.length;
    await waitFor(() => e.w.acks.length > acks, 15000);
    assert.ok((e.w.acks.at(-1)?.bridge.caps ?? []).includes("events"));
  });
});
