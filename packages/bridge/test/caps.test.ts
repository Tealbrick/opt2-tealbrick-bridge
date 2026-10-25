/**
 * Bridge 0.2.5 (spec 0.1.54, C292 / C292a): `StatusReport.bridge.caps`. The bridge declares ONLY what it implements:
 * `owner_rows` = the C283 A1 owner-row filter; `events` (bridge 0.2.7, spec 0.1.57) = all of BRIDGE §14 (app events); `person_ops`
 * (spec 0.1.64) = the person-op relay, BRIDGE §15. Core copies the set into the slices; a standalone bridge writes it into
 * the slices it re-mints itself, without `person_ops` (the relay does not run there). Caps are advisory and never widen access.
 *
 * The cap list is a constant in caps.ts, tied to its feature by a probe per entry (below): a cap whose behaviour is
 * missing fails its probe, and a cap without a probe fails the coverage test. A build without the A1 code path would
 * fail the `owner_rows` probe while its constant still said `owner_rows`, so the change that removes A1 has to remove
 * the entry.
 */
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { after, before, describe, test } from "node:test";
import { fileURLToPath } from "node:url";
import { BRIDGE_CAPS } from "@opt2-tealbrick/spec/bridge";
import { BRIDGE_CAPS_DECLARED } from "../src/caps.ts";
import { buildStatusReport } from "../src/portal.ts";
import { trustFor } from "../src/table.ts";
import { visibleOps } from "../src/tools.ts";
import { claimApp } from "./support/app-client.ts";
import { AGT, BRG, INS, makeWorld, type World, WS, waitFor } from "./support/world.ts";

const now = () => Math.floor(Date.now() / 1000);

/** one probe per cap: true when the build really has the behaviour the cap names */
const PROBES: Record<string, (w: World) => Promise<void>> = {
  // BRIDGE §14: the ingest route answers (an unauthenticated batch is refused 401, not 404), the event log is open, and the
  // three methods answer on an MCP session (not -32601); the full behaviour is events-store.test.ts and events-e2e.test.ts
  events: async (w) => {
    assert.ok(w.bridge.ctx.events, "the event log is open");
    const r = await fetch(`${w.internalUrl}/tb/v1/events`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ items: [] }) });
    await r.body?.cancel();
    assert.equal(r.status, 401);
    const token = await w.agentToken();
    const init = await w.mcp(token, { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "caps" } } });
    for (const method of ["tealbrick/events/list", "tealbrick/events/poll", "tealbrick/events/stream"]) {
      const a = await w.mcp(token, { jsonrpc: "2.0", id: 2, method, params: {} }, init.session ?? undefined);
      assert.ok(a.json?.result && !a.json.error, `${method}: ${JSON.stringify(a.json)}`);
    }
  },
  // BRIDGE §15: a row queued in Core is pulled, forwarded once to the app with its K14, and the app's answer is posted back;
  // the full behaviour is person-ops.test.ts
  person_ops: async (w) => {
    // spec 0.1.70 (C354): only an app that declares app cap person_op gets person ops
    assert.equal((await claimApp(w, { claim: { caps: ["person_op"] } })).claimStatus, 200);
    const pop = "pop_01HCAPSPROBE0000000000000";
    const from = w.personOpApp.seen.length;
    w.personOps.queue.push({ id: pop as never, ins: INS as never, op: "items_list", jws: "aGVhZA.Ym9keQ.c2ln" as never, body: "{}", expiresAt: new Date(Date.now() + 20_000).toISOString() as never });
    await waitFor(() => w.personOps.results.some((r) => r.pop === pop), 15000);
    assert.deepEqual(w.personOps.results.find((r) => r.pop === pop), { pop, status: 200, body: '{"ok":true}' });
    assert.equal(w.personOpApp.seen.length - from, 1);
    assert.equal(w.personOpApp.seen[from]?.headers["tb-person-op"], "aGVhZA.Ym9keQ.c2ln");
  },
  owner_rows: async (w) => {
    const t = w.bridge.ctx.table;
    const app = t?.apps.get(INS as never);
    assert.ok(t && app);
    const scoped: Record<string, unknown> = { standard: false, id: "p_scoped", title: "p", description: "p", crud: ["update"], effect: "write", idempotency: "none", receipt: true, audience: "agent", scopeType: "notebook" };
    const { scopeType: _scopeType, ...unscopedBase } = scoped;
    const unscoped: Record<string, unknown> = { ...unscopedBase, id: "p_unscoped" };
    const probeApp = { ...app, ops: new Map([["p_scoped", scoped], ["p_unscoped", unscoped]]) } as never;
    const token = await w.signPortal("tb-grant+jwt", { iss: "tb:portal", sub: `tb:agt:${AGT}`, aud: `tb:ins:${INS}`, iat: now(), exp: now() + 3600, jti: w.api.ulid(), ws: WS, cnf: { brg: BRG }, crud: ["read"], mode: "free", held: [], caps: {}, wf: [], polrev: 1 });
    const v = w.api.verifyGrant(token, trustFor(t, INS as never, now()));
    assert.ok("claims" in v && v.ok);
    // (1) without the app's mark an op above the grant is not listed; with it, only the SCOPED one is
    assert.deepEqual(visibleOps(w.bridge.ctx, probeApp, v.claims).map((o) => o.id), []);
    assert.deepEqual(visibleOps(w.bridge.ctx, probeApp, v.claims, new Set(["p_scoped", "p_unscoped"])).map((o) => o.id), ["p_scoped"]);
    // (2) gate() passes the scoped op above grant.crud on to the SDK and keeps the ceiling for the unscoped one
    const gate = (op: unknown) => w.bridge.ctx.api.gate({ paused: { workspace: false, agent: false, connection: false, instance: false }, grant: token, trust: trustFor(t, INS as never, now()), op, declaredScopeTypes: ["notebook"] } as never);
    assert.equal(gate(scoped).decision, "pass");
    assert.equal(gate(unscoped).reason, "crud_exceeds_grant");
  },
};

describe("StatusReport.bridge.caps (spec 0.1.54, C292)", () => {
  let w: World;
  before(async () => {
    w = await makeWorld({ real: true });
    await waitFor(() => w.acks.length > 0 && w.bridge.ctx.table?.rev === w.rev(), 15000);
  });
  after(async () => {
    await w.close();
  });

  test("the bridge declares exactly owner_rows, events and person_ops, and only values the spec knows", () => {
    assert.deepEqual([...BRIDGE_CAPS_DECLARED], ["owner_rows", "events", "person_ops"]);
    for (const c of BRIDGE_CAPS_DECLARED) assert.ok((BRIDGE_CAPS as readonly string[]).includes(c), `${c} is in the spec BRIDGE_CAPS`);
  });

  test("every status report carries the caps: the ones Portal received and a freshly built one", async () => {
    // a second revision and a health change produce more reports
    await w.publish();
    await waitFor(() => w.acks.some((a) => a.rev === w.rev()), 15000);
    assert.ok(w.acks.length >= 2, `reports received: ${w.acks.length}`);
    for (const a of w.acks) assert.deepEqual(a.bridge.caps, ["owner_rows", "events", "person_ops"], `report rev ${a.rev}`);
    assert.deepEqual(buildStatusReport(w.bridge.ctx).bridge.caps, ["owner_rows", "events", "person_ops"]);
    // a copy: changing a report never changes what the next one says
    (buildStatusReport(w.bridge.ctx).bridge.caps as string[]).push("x");
    assert.deepEqual(buildStatusReport(w.bridge.ctx).bridge.caps, ["owner_rows", "events", "person_ops"]);
  });

  test("every declared cap has a probe, and the probe passes (the behaviour the cap names exists in this build)", async () => {
    assert.deepEqual([...BRIDGE_CAPS_DECLARED].sort(), Object.keys(PROBES).sort(), "a cap without a probe, or a probe without a cap");
    for (const c of BRIDGE_CAPS_DECLARED) await (PROBES[c] as (w: World) => Promise<void>)(w);
  });

  test("the cap strings appear in one place only (caps.ts); no other source file names a capability", () => {
    const dir = fileURLToPath(new URL("../src/", import.meta.url));
    for (const f of readdirSync(dir).filter((n) => n.endsWith(".ts") && n !== "caps.ts")) {
      const text = readFileSync(`${dir}${f}`, "utf8");
      assert.ok(!/["'](owner_rows|events|person_ops)["']/.test(text), `${f} must take the caps from caps.ts`);
    }
  });
});

describe("standalone bridge: slice.bridge.caps from its own set (spec 0.1.54)", () => {
  let w: World;
  before(async () => {
    w = await makeWorld({ real: true });
    await waitFor(() => w.bridge.ctx.table?.rev === w.rev(), 15000);
  });
  after(async () => {
    await w.close();
  });

  test("a re-minted slice carries caps = the bridge's own set without person_ops, whatever the Portal-signed slice said", async () => {
    const owner = await w.api.generateKeyPair();
    const id = w.bridge.ctx.identity;
    assert.ok(id);
    const standalone = { issuer: w.bridge.ctx.bridgeRef, kid: w.api.thumbprint(id.key.publicJwk), ownerKeys: [owner.publicJwk] };
    const t0 = w.bridge.ctx.table;
    assert.ok(t0);
    const finalSlices = new Map<string, string>();
    for (const a of t0.config.apps) {
      const claims = JSON.parse(Buffer.from(a.slice.split(".")[1] as string, "base64url").toString("utf8")) as Record<string, unknown>;
      // Core's slice claims `caps: []` here (an older set); the standalone bridge overrides it
      finalSlices.set(a.ins, await w.signPortal("tb-slice+jws", { ...claims, iat: now(), jti: w.api.ulid(), rev: Number(claims.rev ?? 1) + 1, standalone, bridge: { id: BRG, keys: [id.key.publicJwk], caps: ["old_cap"] } }));
    }
    await w.publish((c) => {
      (c as { standalone?: unknown }).standalone = standalone;
      for (const a of c.apps) a.slice = (finalSlices.get(a.ins) ?? a.slice) as never;
    });
    await waitFor(() => w.bridge.ctx.table?.standalone === true && w.bridge.ctx.table?.config.iss === w.bridge.ctx.bridgeRef, 15000);
    const slice = w.bridge.ctx.table?.config.apps.find((a) => a.ins === INS)?.slice as string;
    const claims = JSON.parse(Buffer.from(slice.split(".")[1] as string, "base64url").toString("utf8")) as { bridge?: { id?: string; keys?: unknown[]; caps?: string[] } };
    assert.deepEqual(claims.bridge?.caps, ["owner_rows", "events"]);
    assert.equal(claims.bridge?.id, BRG, "the rest of the bridge member is kept");
    assert.equal(claims.bridge?.keys?.length, 1);
  });
});
