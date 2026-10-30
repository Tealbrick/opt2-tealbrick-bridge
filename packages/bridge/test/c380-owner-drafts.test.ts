/**
 * Bridge 0.2.14 / spec 0.1.89 (C380, DESIGN-C380 §5 step 4, cap `owner_drafts`): the three owner-draft relays, against a fake Core.
 * Each guard has a quiet case and a firing case with the exact code and status. The bridge decides nothing else: Core's checks are
 * tested in portal-core.
 */
import assert from "node:assert/strict";
import type { ServerResponse } from "node:http";
import { after, before, beforeEach, describe, test } from "node:test";
import type { Ed25519KeyPair } from "@opt2-tealbrick/spec/sdk";
import { BRIDGE_CAPS_DECLARED, bridgeCaps } from "../src/caps.ts";
import { OWNER_DRAFT_ANSWER_MAX_BYTES, OWNER_DRAFT_BODY_MAX_BYTES, OWNER_DRAFT_CORE_TIMEOUT_MS, OWNER_DRAFT_PATHS, relayOwnerDraft } from "../src/owner-drafts.ts";
import { jsonLogger, TokenBucket } from "../src/util.ts";
import { type AppClient, claimApp } from "./support/app-client.ts";
import { BRG, INS, makeWorld, type World, WS, waitFor } from "./support/world.ts";

const now = () => Math.floor(Date.now() / 1000);
const KEY = "pln_01M66TESTPLAN";
const STEPS = [{ opId: "agents.pause", agt: "agt_01HAAAAAAAAAAAAAAAAAAAAAAA" }];
const REQUEST = { key: KEY, title: "Governance: stop request", planDigest: "sha256:aa", expiresInSec: 3600, steps: STEPS };
const SVC_CODE = "tbe_ownerdraftservicecode";
const CORE = { request: "/api/v1/bridge/owner-drafts/request", get: "/api/v1/bridge/owner-drafts/get", withdraw: "/api/v1/bridge/owner-drafts/withdraw" };

const json = (res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}) => {
  res.writeHead(status, { "content-type": "application/json", ...headers }).end(JSON.stringify(body));
};
const coreRefuses = (code: string, status: number) => ({ error: { code, message: code, requestId: "req_core" }, status });

let w: World;
let appKey: Ed25519KeyPair;
const logs: string[] = [];

interface Sent {
  status: number;
  json: Record<string, any> | undefined;
  retryAfter: string | null;
}

const assertion = (ins: string, key: Ed25519KeyPair, path: string, raw: Buffer | undefined, o: { svc?: string } = {}) =>
  w.api.signAssertion("tb-instance-assert+jwt", { iss: `tb:ins:${ins}`, sub: `tb:ins:${ins}`, aud: `tb:brg:${BRG}`, iat: now(), exp: now() + 60, jti: w.api.ulid(), ...(o.svc ? { svc: o.svc } : {}) }, key, { method: "POST", pathAndQuery: path, ...(raw ? { body: raw } : {}) });

async function send(path: string, token: string, raw: Buffer<ArrayBuffer>): Promise<Sent> {
  const r = await fetch(`${w.internalUrl}${path}`, { method: "POST", headers: { "content-type": "application/json", "TB-Assert": token }, body: raw });
  const text = await r.text();
  return { status: r.status, json: text ? (JSON.parse(text) as Record<string, any>) : undefined, retryAfter: r.headers.get("retry-after") };
}

async function post(path: string, body: unknown, o: { key?: Ed25519KeyPair; svc?: string } = {}): Promise<Sent> {
  const raw = Buffer.from(typeof body === "string" ? body : JSON.stringify(body));
  return send(path, await assertion(INS, o.key ?? appKey, path, raw, o.svc ? { svc: o.svc } : {}), raw);
}

const code = (r: Sent) => r.json?.error?.code;
const refused = (r: Sent, status: number, c: string) => {
  assert.equal(r.status, status, JSON.stringify(r.json));
  assert.equal(code(r), c);
};
/** a refusal the bridge decided: Core was not asked */
async function notForwarded(run: () => Promise<Sent>, status: number, c: string, pointer?: string) {
  const before = w.core.seen.length;
  const r = await run();
  refused(r, status, c);
  if (pointer !== undefined) assert.equal(r.json?.error?.details?.pointer, pointer);
  assert.equal(w.core.seen.length, before, "Core is not asked");
}

describe("owner-draft relays (C380)", () => {
  before(async () => {
    w = await makeWorld({ real: true, logger: jsonLogger((l) => logs.push(l)) });
    await waitFor(() => w.bridge.ctx.table?.rev === w.rev() && w.bridge.ctx.table?.apps.get(INS as never)?.down === false, 15000);
    appKey = await w.api.generateKeyPair();
    await w.amend((c) => {
      c.enrolCodes.push({ digest: w.api.opaqueDigest(SVC_CODE), kind: "service", ins: INS, service: "engine", product: "notes", exp: now() + 3600 } as never);
    });
    await waitFor(() => w.bridge.ctx.table?.rev === w.rev(), 15000);
    const a: AppClient = await claimApp(w, { key: appKey });
    assert.equal(a.claimStatus, 200);
  });
  after(async () => {
    await w.close();
  });
  beforeEach(() => {
    w.core.answer = (path, _body, res) => json(res, 200, { draftId: "drf_1", state: "open", reviewUrl: "https://portal.test/d/1", at: path });
  });

  test("the paths and the limits are the frozen ones", () => {
    assert.deepEqual(OWNER_DRAFT_PATHS, { request: "/tb/v1/owner-drafts", get: "/tb/v1/owner-drafts/get", withdraw: "/tb/v1/owner-drafts/withdraw" });
    assert.equal(OWNER_DRAFT_CORE_TIMEOUT_MS, 15_000);
  });

  // ── pending-claim key: must run before the key is listed ──
  test("a key Core has not listed (pending claim) passes assertCaller but is refused 401 unauthenticated; a listed key is not", async () => {
    await notForwarded(() => post(OWNER_DRAFT_PATHS.request, REQUEST), 401, "unauthenticated");
    await w.amend((c) => {
      c.instanceKeys.push({ ins: INS, jwk: appKey.publicJwk } as never);
    });
    await waitFor(() => w.bridge.ctx.table?.rev === w.rev() && !!w.bridge.ctx.table?.instanceKeys.has(`${INS}|`), 15000);
    const ok = await post(OWNER_DRAFT_PATHS.request, REQUEST);
    assert.equal(ok.status, 200, JSON.stringify(ok.json));
  });

  // ── the three relays ──
  for (const [kind, body] of [["request", REQUEST], ["get", { key: KEY }], ["withdraw", { key: KEY }]] as const) {
    test(`${kind}: forwarded with the verified ins, Core's status and body unchanged`, async () => {
      const r = await post(OWNER_DRAFT_PATHS[kind], body);
      assert.equal(r.status, 200);
      assert.deepEqual(r.json, { draftId: "drf_1", state: "open", reviewUrl: "https://portal.test/d/1", at: CORE[kind] });
      const seen = w.core.seen[w.core.seen.length - 1];
      assert.equal(seen?.path, CORE[kind]);
      assert.deepEqual(seen?.body, { ...body, ins: INS });
      assert.equal(w.rejectedBridgeAssertions(), 0, "the bridge assertion verified at the fake Core");
    });
  }

  // ── what the caller sends ──
  test("a body member ins is refused 400 input_invalid /ins: the asking instance comes from the assertion only", async () => {
    await notForwarded(() => post(OWNER_DRAFT_PATHS.request, { ...REQUEST, ins: "ins_01HOTHEROTHEROTHEROTHEROTH" }), 400, "input_invalid", "/ins");
  });
  test("a body that is not an object, or a bad key, is refused 400 input_invalid", async () => {
    await notForwarded(() => post(OWNER_DRAFT_PATHS.get, "not json"), 400, "input_invalid");
    await notForwarded(() => post(OWNER_DRAFT_PATHS.get, "[1]"), 400, "input_invalid", "");
    await notForwarded(() => post(OWNER_DRAFT_PATHS.get, {}), 400, "input_invalid", "/key");
    await notForwarded(() => post(OWNER_DRAFT_PATHS.get, { key: "bad key\n" }), 400, "input_invalid", "/key");
    await notForwarded(() => post(OWNER_DRAFT_PATHS.get, { key: `pln_${"x".repeat(125)}` }), 400, "input_invalid", "/key");
    await notForwarded(() => post(OWNER_DRAFT_PATHS.get, { key: "other_key" }), 400, "input_invalid", "/key");
  });
  test("a body over the limit is refused 413 and the request key limit fits 100 steps", async () => {
    const steps = Array.from({ length: 100 }, () => STEPS[0]);
    assert.ok(Buffer.byteLength(JSON.stringify({ ...REQUEST, steps })) < OWNER_DRAFT_BODY_MAX_BYTES);
    const before = w.core.seen.length;
    const raw = Buffer.alloc(OWNER_DRAFT_BODY_MAX_BYTES + 1, 0x20);
    const r = await fetch(`${w.internalUrl}${OWNER_DRAFT_PATHS.request}`, { method: "POST", headers: { "TB-Assert": "x.y.z" }, body: raw });
    assert.equal(r.status, 413);
    assert.equal(w.core.seen.length, before);
  });

  // ── who is asking ──
  test("no, bad, re-used or misbound assertions are refused 401 unauthenticated", async () => {
    const raw = Buffer.from(JSON.stringify(REQUEST));
    await notForwarded(() => send(OWNER_DRAFT_PATHS.request, "", raw), 401, "unauthenticated");
    const stranger = await w.api.generateKeyPair();
    await notForwarded(async () => send(OWNER_DRAFT_PATHS.request, await assertion(INS, stranger, OWNER_DRAFT_PATHS.request, raw), raw), 401, "unauthenticated");
    // bound to path and body
    await notForwarded(async () => send(OWNER_DRAFT_PATHS.request, await assertion(INS, appKey, OWNER_DRAFT_PATHS.withdraw, raw), raw), 401, "unauthenticated");
    await notForwarded(async () => send(OWNER_DRAFT_PATHS.request, await assertion(INS, appKey, OWNER_DRAFT_PATHS.request, Buffer.from("{}")), raw), 401, "unauthenticated");
    // one use
    const token = await assertion(INS, appKey, OWNER_DRAFT_PATHS.request, raw);
    assert.equal((await send(OWNER_DRAFT_PATHS.request, token, raw)).status, 200);
    await notForwarded(() => send(OWNER_DRAFT_PATHS.request, token, raw), 401, "unauthenticated");
  });
  test("a companion service is refused 401 unauthenticated", async () => {
    const svcKey = await w.api.generateKeyPair();
    const c = await claimApp(w, { code: SVC_CODE, service: "engine", key: svcKey });
    assert.equal(c.claimStatus, 200);
    await notForwarded(() => post(OWNER_DRAFT_PATHS.request, REQUEST, { key: svcKey, svc: "engine" }), 401, "unauthenticated");
  });
  test("other methods are not routes: 404 not_found", async () => {
    const r = await fetch(`${w.internalUrl}${OWNER_DRAFT_PATHS.request}`);
    assert.equal(r.status, 404);
    assert.equal(((await r.json()) as { error: { code: string } }).error.code, "not_found");
  });

  // ── state of the bridge ──
  test("a paused instance and a paused workspace are refused 403 paused on all three; a pause lifted is quiet", async () => {
    const pauses: ((p: { instances: unknown[]; workspace: boolean }) => void)[] = [
      (p) => {
        p.instances = [INS];
      },
      (p) => {
        p.workspace = true;
      },
    ];
    for (const pause of pauses) {
      await w.publish((c) => pause(c.pause));
      await waitFor(() => w.bridge.ctx.table?.rev === w.rev(), 15000);
      await notForwarded(() => post(OWNER_DRAFT_PATHS.request, REQUEST), 403, "paused");
      await notForwarded(() => post(OWNER_DRAFT_PATHS.get, { key: KEY }), 403, "paused");
      await notForwarded(() => post(OWNER_DRAFT_PATHS.withdraw, { key: KEY }), 403, "paused");
    }
    await w.publish();
    await waitFor(() => w.bridge.ctx.table?.rev === w.rev(), 15000);
    assert.equal((await post(OWNER_DRAFT_PATHS.get, { key: KEY })).status, 200);
  });
  test("draining: 503 temporarily_unavailable with Retry-After, nothing asked; not draining is quiet", async () => {
    w.bridge.ctx.draining = true;
    try {
      const before = w.core.seen.length;
      const r = await post(OWNER_DRAFT_PATHS.request, REQUEST);
      refused(r, 503, "temporarily_unavailable");
      assert.equal(r.retryAfter, "2");
      assert.equal(w.core.seen.length, before);
    } finally {
      w.bridge.ctx.draining = false;
    }
    assert.equal((await post(OWNER_DRAFT_PATHS.request, REQUEST)).retryAfter, null);
  });
  test("an expired config is refused 503 config_expired", async () => {
    const t = w.bridge.ctx.table;
    assert.ok(t);
    const exp = t.exp;
    t.exp = now() - 1;
    try {
      await notForwarded(() => post(OWNER_DRAFT_PATHS.request, REQUEST), 503, "config_expired");
    } finally {
      t.exp = exp;
    }
  });

  // ── what Core answers ──
  test("Core's refusals pass through with their status: flag off, no consent, conflict, limit with Retry-After", async () => {
    const pass = async (c: string, status: number, headers: Record<string, string> = {}) => {
      w.core.answer = (_p, _b, res) => {
        const { status: _s, ...body } = coreRefuses(c, status);
        json(res, status, body, headers);
      };
      const r = await post(OWNER_DRAFT_PATHS.request, REQUEST);
      refused(r, status, c);
      assert.equal(r.json?.error?.requestId, "req_core", "unchanged");
      return r;
    };
    await pass("not_found", 404);
    await pass("unauthenticated", 401);
    await pass("consent_required", 403);
    await pass("draft_conflict", 409);
    assert.equal((await pass("rate_limited", 429, { "retry-after": "17" })).retryAfter, "17");
    assert.equal((await pass("internal", 500)).retryAfter, null);
  });
  test("no readable answer from Core: 503 portal_unavailable with Retry-After, never an invented state", async () => {
    const unusable: ((res: ServerResponse) => void)[] = [
      (res) => void res.socket?.destroy(),
      (res) => void res.writeHead(502, { "content-type": "text/html" }).end("<html>bad gateway</html>"),
      (res) => void res.writeHead(200, { "content-type": "application/json" }).end("[]"),
      (res) => void res.writeHead(200, { "content-type": "application/json" }).end(`{"pad":"${"x".repeat(OWNER_DRAFT_ANSWER_MAX_BYTES)}"}`),
    ];
    for (const u of unusable) {
      w.core.answer = (_p, _b, res) => u(res);
      const r = await post(OWNER_DRAFT_PATHS.request, REQUEST);
      refused(r, 503, "portal_unavailable");
      assert.equal(r.retryAfter, "5");
    }
  });
  test("a get answer with 100 long step outputs passes (above the request limit)", async () => {
    const steps = Array.from({ length: 100 }, (_, i) => ({ status: "applied", output: { removed: Array.from({ length: 50 }, (_x, j) => `edge_${i}_${j}_${"x".repeat(40)}`) } }));
    assert.ok(Buffer.byteLength(JSON.stringify(steps)) > OWNER_DRAFT_BODY_MAX_BYTES);
    w.core.answer = (_p, _b, res) => json(res, 200, { state: "applied", steps, receiptId: "rcp_1" });
    const r = await post(OWNER_DRAFT_PATHS.get, { key: KEY });
    assert.equal(r.status, 200);
    assert.equal(r.json?.steps?.length, 100);
  });
  test("Core does not answer in time: 503 portal_unavailable", async () => {
    let held: ServerResponse | undefined;
    w.core.answer = (_p, _b, res) => {
      held = res;
    };
    const fake = { writeHead: () => fake, end: () => fake } as never;
    await assert.rejects(relayOwnerDraft(w.bridge.ctx, "get", { ins: INS as never, svc: undefined }, new TokenBucket(1, 1), Buffer.from(JSON.stringify({ key: KEY })), fake, "req", 50), (e: unknown) => (e as { code?: string; status?: number }).code === "portal_unavailable" && (e as { status?: number }).status === 503);
    held?.socket?.destroy();
  });

  // ── logs ──
  test("the log has ids and codes: no title, digest or step", async () => {
    const planted = { ...REQUEST, title: "PLANTED-TITLE-someone-was-fired", planDigest: "sha256:PLANTEDDIGEST", steps: [{ opId: "agents.offboard", agt: "agt_PLANTEDAGENT" }] };
    const before = logs.length;
    assert.equal((await post(OWNER_DRAFT_PATHS.request, planted)).status, 200);
    await waitFor(() => logs.slice(before).some((l) => l.includes("bridge.owner_draft.relayed")), 5000);
    const lines = logs.slice(before).join("\n");
    assert.match(lines, /"kind":"request"/);
    assert.match(lines, /"status":200/);
    for (const secret of ["PLANTED-TITLE", "PLANTEDDIGEST", "agents.offboard", "PLANTEDAGENT", "https://portal.test"]) assert.ok(!lines.includes(secret), secret);
  });

  // ── the bucket ── (last: it empties the instance's bucket)
  test("the app bucket: 429 rate_limited with Retry-After, shared with the other app-initiated calls", async () => {
    let limited: Sent | undefined;
    let asked = 0;
    for (let i = 0; i < 80 && !limited; i++) {
      asked = w.core.seen.length;
      const r = await post(OWNER_DRAFT_PATHS.get, { key: KEY });
      if (r.status === 429) limited = r;
    }
    assert.ok(limited, "the bucket fires");
    refused(limited, 429, "rate_limited");
    assert.ok(Number(limited.retryAfter) >= 1);
    assert.equal(w.core.seen.length, asked, "Core is not asked");
    // the same bucket as a companion call
    const raw = Buffer.from(JSON.stringify({ target: "notes", op: "notes_list", input: {} }));
    const path = "/tb/v1/call";
    const token = await assertion(INS, appKey, path, raw);
    const r = await fetch(`${w.internalUrl}${path}`, { method: "POST", headers: { "content-type": "application/json", "TB-Assert": token, "TB-Grant": "x.y.z" }, body: raw });
    assert.equal(r.status, 429);
  });
});

describe("standalone bridge: no Portal, no owner drafts", () => {
  let key: Ed25519KeyPair;
  before(async () => {
    w = await makeWorld({ real: true });
    await waitFor(() => w.bridge.ctx.table?.rev === w.rev(), 15000);
    key = await w.api.generateKeyPair();
    await w.amend((c) => {
      c.instanceKeys.push({ ins: INS, jwk: key.publicJwk } as never);
    });
    await waitFor(() => w.bridge.ctx.table?.rev === w.rev(), 15000);
  });
  after(async () => {
    await w.close();
  });

  test("before: the cap is reported and the relay runs", async () => {
    assert.ok(bridgeCaps(w.bridge.ctx).includes("owner_drafts"));
    w.core.answer = (_p, _b, res) => json(res, 200, { draftId: "drf_1", state: "open" });
    assert.equal((await post(OWNER_DRAFT_PATHS.request, REQUEST, { key })).status, 200);
  });
  test("after leaving Portal: 409 owner_drafts_unsupported, Core not asked, and re-minted slices do not carry the cap", async () => {
    const owner = await w.api.generateKeyPair();
    const id = w.bridge.ctx.identity;
    const t0 = w.bridge.ctx.table;
    assert.ok(id && t0);
    const standalone = { issuer: w.bridge.ctx.bridgeRef, kid: w.api.thumbprint(id.key.publicJwk), ownerKeys: [owner.publicJwk] };
    const finalSlices = new Map<string, string>();
    for (const a of t0.config.apps) {
      const claims = JSON.parse(Buffer.from(a.slice.split(".")[1] as string, "base64url").toString("utf8")) as Record<string, unknown>;
      finalSlices.set(a.ins, await w.signPortal("tb-slice+jws", { ...claims, iat: now(), jti: w.api.ulid(), rev: Number(claims.rev ?? 1) + 1, standalone, ws: WS, bridge: { id: BRG, keys: [id.key.publicJwk], caps: ["owner_drafts"] } }));
    }
    await w.publish((c) => {
      (c as { standalone?: unknown }).standalone = standalone;
      for (const a of c.apps) a.slice = (finalSlices.get(a.ins) ?? a.slice) as never;
    });
    await waitFor(() => w.bridge.ctx.table?.standalone === true && w.bridge.ctx.table?.config.iss === w.bridge.ctx.bridgeRef, 15000);
    await notForwarded(() => post(OWNER_DRAFT_PATHS.request, REQUEST, { key }), 409, "owner_drafts_unsupported");
    assert.ok(BRIDGE_CAPS_DECLARED.includes("owner_drafts"), "the build still has the code");
    assert.ok(!bridgeCaps(w.bridge.ctx).includes("owner_drafts"));
    const slice = w.bridge.ctx.table?.config.apps.find((a) => a.ins === INS)?.slice as string;
    const claims = JSON.parse(Buffer.from(slice.split(".")[1] as string, "base64url").toString("utf8")) as { bridge?: { caps?: string[] } };
    assert.ok(!claims.bridge?.caps?.includes("owner_drafts"));
    assert.ok(claims.bridge?.caps?.includes("acting_agents"), "other caps stay");
  });
});
