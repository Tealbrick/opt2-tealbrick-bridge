/**
 * Person-op relay (spec 0.1.64, BRIDGE §15, C326): a real bridge pulls queued person ops from a fake Core, forwards each one
 * ONCE to the (fake) app's `POST /tb/v1/person-op` and posts the app's answer back. Conformance rows:
 *   R-PO-1 cap declared ⇔ relay implemented (also caps.test.ts: probe, and no cap in standalone slices)
 *   R-PO-2 unknown `ins` → 409 result, no forward
 *   R-PO-3 body bytes forwarded unchanged (digest equal)
 *   R-PO-4 no body/JWS in logs
 *   R-PO-5 one forward per pop, no retry
 *   R-PO-6 -1 vs 0 mapping
 */
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { createServer, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { after, before, describe, test } from "node:test";
import { PERSON_OP_RELAY } from "@opt2-tealbrick/spec/routes";
import { forwardFailureStatus, MIN_POLL_INTERVAL_MS, RELAY_CONCURRENCY } from "../src/person-ops.ts";
import { buildStatusReport } from "../src/portal.ts";
import { jsonLogger } from "../src/util.ts";
import { INS, makeWorld, type World, waitFor } from "./support/world.ts";

const rnd = (n = 18): string => randomBytes(n).toString("base64url");
const sha256 = (b: Buffer): string => createHash("sha256").update(b).digest("hex");
let seq = 0;
const nextPop = (): string => `pop_01HPOPTEST${String(++seq).padStart(16, "0")}`;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** queue one row in the fake Core; returns its pop and K14 */
function enqueue(w: World, o: { ins?: string; body?: string; jws?: string; op?: string; pop?: string } = {}): { pop: string; jws: string; body: string } {
  const pop = o.pop ?? nextPop();
  const jws = o.jws ?? `${rnd(12)}.${rnd(40)}.${rnd(32)}`;
  const body = o.body ?? "{}";
  w.personOps.queue.push({ id: pop as never, ins: (o.ins ?? INS) as never, op: o.op ?? "items_list", jws: jws as never, body, expiresAt: new Date(Date.now() + 20_000).toISOString() as never });
  return { pop, jws, body };
}
async function resultOf(w: World, pop: string, ms = 15000) {
  await waitFor(() => w.personOps.results.some((r) => r.pop === pop), ms);
  return w.personOps.results.find((r) => r.pop === pop) as { pop: string; status: number; body: string };
}
/** a local origin that refuses connections (listened once, then closed) */
async function closedOrigin(): Promise<string> {
  const s = createServer();
  await new Promise<void>((r) => s.listen(0, "127.0.0.1", r));
  const port = (s.address() as AddressInfo).port;
  await new Promise((r) => s.close(r));
  return `http://127.0.0.1:${port}`;
}

describe("person-op relay (BRIDGE §15)", () => {
  let w: World;
  let dead: string;
  const lines: string[] = [];
  before(async () => {
    dead = await closedOrigin();
    w = await makeWorld({ logger: jsonLogger((l) => lines.push(l)), extraOwnInfraOrigins: [dead] });
    await waitFor(() => w.bridge.ctx.table?.rev === w.rev() && w.personOps.polls.length > 0, 15000);
  });
  after(async () => {
    await w.close();
  });

  test("R-PO-1: the status report declares person_ops", () => {
    assert.ok((buildStatusReport(w.bridge.ctx).bridge.caps ?? []).includes("person_ops"));
  });

  test("R-PO-2: an ins that is not in the config → result 409 instance_unknown, nothing forwarded", async () => {
    const from = w.personOpApp.seen.length;
    const { pop } = enqueue(w, { ins: "ins_01HUNKNOWNUNKNOWNUNKNOWN00" });
    const r = await resultOf(w, pop);
    assert.equal(r.status, 409);
    assert.equal((JSON.parse(r.body) as { error: { code: string } }).error.code, "instance_unknown");
    await sleep(200);
    assert.equal(w.personOpApp.seen.length, from, "no forward");
  });

  test("R-PO-3: the body bytes reach the app unchanged (non-ASCII, spacing, number text), with the K14 header", async () => {
    const body = '{"text":"Grüße — ✓ 😀 \\u2028","n" : 1.50,  "nested":{"a":[1,2.0e3]}}';
    const from = w.personOpApp.seen.length;
    const { pop, jws } = enqueue(w, { body });
    const r = await resultOf(w, pop);
    assert.deepEqual(r, { pop, status: 200, body: '{"ok":true}' });
    assert.equal(w.personOpApp.seen.length, from + 1);
    const seen = w.personOpApp.seen[from];
    assert.ok(seen);
    assert.equal(sha256(seen.raw), sha256(Buffer.from(body, "utf8")), "digest of the forwarded bytes = digest of Core's string");
    assert.equal(seen.raw.toString("utf8"), body);
    assert.equal(seen.headers["tb-person-op"], jws);
    assert.equal(seen.headers["content-type"], "application/json");
  });

  test("the app's status and body text pass through (an app error is the app's answer)", async () => {
    const answer = '{"error":{"code":"item_not_open","message":"decided already"}}';
    w.personOpApp.handler = (_req, res) => void res.writeHead(409, { "content-type": "application/json" }).end(answer);
    try {
      const { pop } = enqueue(w, { op: "item_decide" });
      assert.deepEqual(await resultOf(w, pop), { pop, status: 409, body: answer });
    } finally {
      w.personOpApp.handler = undefined;
    }
  });

  test("pause does not stop the relay (owner access by design)", async () => {
    await w.publish((c) => {
      c.pause = { workspace: true, agents: [], instances: [INS as never] };
    });
    await waitFor(() => w.bridge.ctx.table?.rev === w.rev(), 15000);
    const { pop } = enqueue(w);
    assert.equal((await resultOf(w, pop)).status, 200);
    await w.publish();
    await waitFor(() => w.bridge.ctx.table?.rev === w.rev(), 15000);
  });

  test("R-PO-6: connection refused → -1 (not delivered), exactly one attempt", async () => {
    const ctx = w.bridge.ctx as unknown as { fetch: typeof fetch };
    const original = ctx.fetch;
    let attempts = 0;
    ctx.fetch = ((input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) => {
      if (String(input).endsWith("/tb/v1/person-op")) attempts += 1;
      return original(input, init);
    }) as typeof fetch;
    try {
      await w.publish((c) => {
        (c.apps[0] as { internalUrl: string }).internalUrl = dead;
      });
      await waitFor(() => w.bridge.ctx.table?.rev === w.rev(), 15000);
      const { pop } = enqueue(w);
      assert.deepEqual(await resultOf(w, pop), { pop, status: -1, body: "" });
      assert.equal(attempts, 1, "no retry of the forward");
      // an internalUrl outside the allow-list (BSD-07) is never contacted: -1 as well
      await w.publish((c) => {
        (c.apps[0] as { internalUrl: string }).internalUrl = "http://127.0.0.1:1";
      });
      await waitFor(() => w.bridge.ctx.table?.rev === w.rev(), 15000);
      assert.equal(w.bridge.ctx.table?.apps.get(INS as never)?.refused, true);
      const second = enqueue(w);
      assert.equal((await resultOf(w, second.pop)).status, -1);
      assert.equal(attempts, 1, "a refused internalUrl is not contacted");
    } finally {
      ctx.fetch = original;
      await w.publish();
      await waitFor(() => w.bridge.ctx.table?.rev === w.rev() && w.bridge.ctx.table?.apps.get(INS as never)?.down === false, 15000);
    }
  });

  test("R-PO-6: an answer that breaks off after sending, or a redirect → 0 (outcome unknown); one request each", async () => {
    for (const handler of [
      (req: { socket: { destroy(): void } }) => req.socket.destroy(),
      (_req: unknown, res: ServerResponse) => void res.writeHead(302, { location: "/elsewhere" }).end(),
    ]) {
      w.personOpApp.handler = handler as never;
      const from = w.personOpApp.seen.length;
      try {
        const { pop } = enqueue(w);
        assert.deepEqual(await resultOf(w, pop), { pop, status: 0, body: "" });
        await sleep(200);
        assert.equal(w.personOpApp.seen.length, from + 1, "the app got the request once; no retry");
      } finally {
        w.personOpApp.handler = undefined;
      }
    }
  });

  test("R-PO-6: no answer within bridgeForwardS → 0, the app saw one request", async () => {
    const held: ServerResponse[] = [];
    w.personOpApp.handler = (_req, res) => void held.push(res);
    const from = w.personOpApp.seen.length;
    try {
      const t0 = Date.now();
      const { pop } = enqueue(w);
      assert.deepEqual(await resultOf(w, pop, 20000), { pop, status: 0, body: "" });
      assert.ok(Date.now() - t0 >= PERSON_OP_RELAY.bridgeForwardS * 1000 - 200, "after the forward timeout");
      assert.equal(w.personOpApp.seen.length, from + 1);
    } finally {
      w.personOpApp.handler = undefined;
      for (const res of held) res.destroy();
    }
  });

  test("an answer over maxOutputBytes → 0; exactly maxOutputBytes passes", async () => {
    const pad = (n: number) => `{"p":"${"x".repeat(n - 8)}"}`;
    for (const [size, want] of [[PERSON_OP_RELAY.maxOutputBytes + 1, 0], [PERSON_OP_RELAY.maxOutputBytes, 200]] as const) {
      const answer = pad(size);
      assert.equal(Buffer.byteLength(answer), size);
      w.personOpApp.handler = (_req, res) => void res.writeHead(200, { "content-type": "application/json" }).end(answer);
      try {
        const { pop } = enqueue(w);
        const r = await resultOf(w, pop);
        assert.equal(r.status, want, `answer of ${size} bytes`);
        assert.equal(r.body, want === 0 ? "" : answer);
      } finally {
        w.personOpApp.handler = undefined;
      }
    }
  });

  test("R-PO-5: a pop handed out again is not forwarded again", async () => {
    const from = w.personOpApp.seen.length;
    const first = enqueue(w);
    await resultOf(w, first.pop);
    const results = w.personOps.results.length;
    enqueue(w, { pop: first.pop });
    await waitFor(() => w.personOps.queue.length === 0, 5000);
    await sleep(500);
    assert.equal(w.personOpApp.seen.length, from + 1);
    assert.equal(w.personOps.results.length, results, "no second result");
  });

  test("the result post is retried once on a network error, never more; the forward is not repeated", async () => {
    let from = w.personOpApp.seen.length;
    w.personOps.dropResults = 1;
    const a = enqueue(w);
    assert.equal((await resultOf(w, a.pop)).status, 200, "the second result post arrived");
    assert.equal(w.personOps.results.filter((r) => r.pop === a.pop).length, 1);
    assert.equal(w.personOpApp.seen.length, from + 1);
    from = w.personOpApp.seen.length;
    w.personOps.dropResults = 2;
    const b = enqueue(w);
    await waitFor(() => w.personOps.dropResults === 0, 10000);
    await sleep(500);
    assert.ok(!w.personOps.results.some((r) => r.pop === b.pop), "two failed posts: no third");
    assert.equal(w.personOpApp.seen.length, from + 1);
  });

  test(`at most ${RELAY_CONCURRENCY} forwards run at once; the rest follow`, async () => {
    const held: ServerResponse[] = [];
    let open = 0;
    let peak = 0;
    w.personOpApp.handler = (_req, res) => {
      open += 1;
      peak = Math.max(peak, open);
      held.push(res);
    };
    const from = w.personOpApp.seen.length;
    try {
      const pops = Array.from({ length: RELAY_CONCURRENCY + 2 }, () => enqueue(w).pop);
      await waitFor(() => w.personOpApp.seen.length - from === RELAY_CONCURRENCY, 5000);
      await sleep(400);
      assert.equal(w.personOpApp.seen.length - from, RELAY_CONCURRENCY);
      w.personOpApp.handler = (_req, res) => void res.writeHead(200, { "content-type": "application/json" }).end("{}");
      for (const res of held.splice(0)) {
        open -= 1;
        res.writeHead(200, { "content-type": "application/json" }).end("{}");
      }
      for (const pop of pops) assert.equal((await resultOf(w, pop)).status, 200);
      assert.equal(peak, RELAY_CONCURRENCY);
    } finally {
      w.personOpApp.handler = undefined;
      for (const res of held) res.destroy();
    }
  });

  test("R-PO-4: no log line holds the body, the K14 or the app's answer; the relayed line is meta only", async () => {
    const marker = rnd(24);
    const answer = `{"secret":"${rnd(24)}"}`;
    w.personOpApp.handler = (_req, res) => void res.writeHead(200, { "content-type": "application/json" }).end(answer);
    const before = lines.length;
    try {
      const { pop, jws, body } = enqueue(w, { body: `{"note":"${marker}"}` });
      await resultOf(w, pop);
      await waitFor(() => lines.slice(before).some((l) => l.includes(pop)), 5000);
      const planted = [marker, jws, ...jws.split("."), answer, body];
      assert.deepEqual(lines.filter((l) => planted.some((p) => l.includes(p))), [], "no planted value in any line");
      const relayed = lines.slice(before).map((l) => JSON.parse(l) as Record<string, unknown>).find((l) => l.event === "bridge.person_op.relayed" && l.pop === pop);
      assert.ok(relayed);
      const { ts: _ts, level: _level, event: _event, ms, ...rest } = relayed;
      assert.equal(typeof ms, "number");
      assert.deepEqual(rest, { pop, ins: INS, op: "items_list", status: 200 });
    } finally {
      w.personOpApp.handler = undefined;
    }
  });

  test("no tight loop: empty batches are paced; 429 waits for Retry-After; errors back off", async () => {
    let from = w.personOps.polls.length;
    await sleep(3000);
    const empty = w.personOps.polls.slice(from);
    assert.ok(empty.length >= 2 && empty.length <= Math.ceil(3000 / MIN_POLL_INTERVAL_MS) + 1, `empty polls in 3 s: ${empty.length}`);
    w.personOps.pollStatus = 429;
    w.personOps.retryAfter = "2";
    try {
      from = w.personOps.polls.length;
      await waitFor(() => w.personOps.polls.length - from >= 2, 10000);
      const [p1, p2] = w.personOps.polls.slice(from) as [number, number];
      assert.ok(p2 - p1 >= 1900, `429 Retry-After 2: next pull after ${p2 - p1} ms`);
      w.personOps.pollStatus = 500;
      w.personOps.retryAfter = undefined;
      from = w.personOps.polls.length;
      await sleep(3000);
      assert.ok(w.personOps.polls.length - from <= 3, `500s in 3 s: ${w.personOps.polls.length - from} pulls`);
    } finally {
      w.personOps.pollStatus = undefined;
    }
    // recovers: a row is relayed again after the errors
    const { pop } = enqueue(w);
    assert.equal((await resultOf(w, pop, 40000)).status, 200);
  });
});

describe("person-op relay: standalone bridges never pull (no K14 issuer)", () => {
  let w: World;
  before(async () => {
    w = await makeWorld({ real: true });
    await waitFor(() => w.bridge.ctx.table?.rev === w.rev() && w.personOps.polls.length > 0, 15000);
  });
  after(async () => {
    await w.close();
  });

  test("a final standalone config stops the relay and drops the cap; a restart in standalone never pulls", async () => {
    const id = w.bridge.ctx.identity;
    assert.ok(id);
    const owner = await w.api.generateKeyPair();
    const standalone = { issuer: w.bridge.ctx.bridgeRef, kid: w.api.thumbprint(id.key.publicJwk), ownerKeys: [owner.publicJwk] };
    await w.publish((c) => {
      (c as { standalone?: unknown }).standalone = standalone;
    });
    await waitFor(() => w.bridge.ctx.table?.standalone === true, 15000);
    assert.ok(!(buildStatusReport(w.bridge.ctx).bridge.caps ?? []).includes("person_ops"));
    await sleep(300);
    const n = w.personOps.polls.length;
    const { pop } = enqueue(w);
    await sleep(2500);
    assert.equal(w.personOps.polls.length, n, "no pull after the switch");
    assert.ok(!w.personOps.results.some((r) => r.pop === pop));
    await w.restart();
    await waitFor(() => w.bridge.ctx.table?.standalone === true, 15000);
    await sleep(2000);
    assert.equal(w.personOps.polls.length, n, "no pull after a restart in standalone mode");
  });
});

describe("forwardFailureStatus: -1 only for failures before the request was sent", () => {
  const failure = (code: string) => Object.assign(new TypeError("fetch failed"), { cause: { code } });
  test("connect refused, DNS, connect timeout, TLS → -1", () => {
    for (const code of ["ECONNREFUSED", "ENOTFOUND", "EAI_AGAIN", "EHOSTUNREACH", "UND_ERR_CONNECT_TIMEOUT", "CERT_HAS_EXPIRED", "ERR_TLS_CERT_ALTNAME_INVALID", "UNABLE_TO_VERIFY_LEAF_SIGNATURE", "DEPTH_ZERO_SELF_SIGNED_CERT", "EPROTO"]) {
      assert.equal(forwardFailureStatus(failure(code)), -1, code);
    }
  });
  test("reset, socket closed, timeout, redirect, unknown → 0", () => {
    for (const e of [failure("ECONNRESET"), failure("UND_ERR_SOCKET"), new DOMException("The operation timed out.", "TimeoutError"), new TypeError("fetch failed", { cause: new Error("unexpected redirect") }), new Error("x"), undefined]) {
      assert.equal(forwardFailureStatus(e), 0, String(e));
    }
  });
});
