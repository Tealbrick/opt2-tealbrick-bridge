/**
 * Bridge 0.1.31 (C219, spec 0.1.39): AppStatus.preUpdateSnapshot reaches StatusReport.apps[] when it is null or a
 * well-formed PreUpdateSnapshotRef {file, sha256, createdAt, from, to}; any malformed member drops the whole snapshot;
 * absent stays absent (L24). L34: a change of the snapshot ref emits exactly one health event; no change emits none.
 */
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import type { PreUpdateSnapshotRef } from "@opt2-tealbrick/spec/bridge";
import { buildStatusReport } from "../src/portal.ts";
import { upgradeFields } from "../src/status-fields.ts";
import type { Logger } from "../src/util.ts";
import { APP_CODE, BRG, INS, makeWorld, type World, waitFor } from "./support/world.ts";

const now = () => Math.floor(Date.now() / 1000);
// the exact shape miniapp-sdk 0.1.25 sends (failed.ts / server.ts): file tb-preupdate-to-<version>.tar.gz, bare lower-case hex sha256
const snap: PreUpdateSnapshotRef = {
  file: "tb-preupdate-to-1.2.0.tar.gz",
  sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  createdAt: "2026-10-17T09:15:30.123Z",
  from: "1.1.0",
  to: "1.2.0",
};

describe("0.1.31 upgradeFields: preUpdateSnapshot shape check", () => {
  test("well-formed is forwarded unchanged; from null (data from before SDK 0.1.25) is allowed", () => {
    assert.deepEqual(upgradeFields({ preUpdateSnapshot: snap }), { preUpdateSnapshot: snap });
    assert.deepEqual(upgradeFields({ preUpdateSnapshot: { ...snap, from: null } }), { preUpdateSnapshot: { ...snap, from: null } });
    assert.deepEqual(upgradeFields({ preUpdateSnapshot: { ...snap, createdAt: "2026-10-17T09:15:30Z", to: "2.0.0-rc.1", file: "tb-preupdate-to-2.0.0-rc.1.tar.gz" } }).preUpdateSnapshot?.to, "2.0.0-rc.1");
  });

  test("null is forwarded as null", () => {
    assert.deepEqual(upgradeFields({ preUpdateSnapshot: null }), { preUpdateSnapshot: null });
    assert.ok("preUpdateSnapshot" in upgradeFields({ preUpdateSnapshot: null }));
  });

  test("absent stays absent", () => {
    assert.deepEqual(upgradeFields({}), {});
    assert.ok(!("preUpdateSnapshot" in upgradeFields({ schemaVersion: { app: 1, sdk: 1 } })));
    assert.ok(!("preUpdateSnapshot" in upgradeFields({ preUpdateSnapshot: undefined })));
    assert.ok(!("preUpdateSnapshot" in upgradeFields(undefined)));
  });

  test("each malformed member drops the whole snapshot (the other members still pass)", () => {
    const bad: Record<string, unknown[]> = {
      file: ["a/b.tar.gz", "../x.tar.gz", "..", "a..b", "a b", "a\u0000b", "", `${"a".repeat(201)}`, 7, null, undefined],
      sha256: ["sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "0123", `${snap.sha256}0`, snap.sha256.toUpperCase(), `${snap.sha256.slice(0, 63)}g`, 7, null, undefined],
      createdAt: ["now", "2026-10-17 09:15:30Z", "2026-10-17T09:15:30+07:00", "2026-10-17", 7, null, undefined],
      from: ["1.0", "v1.0.0", "<script>", 1, undefined],
      to: ["1.0", "v1.0.0", "", null, 1, undefined],
    };
    for (const [key, values] of Object.entries(bad)) {
      for (const v of values) {
        const ref: Record<string, unknown> = { ...snap };
        if (v === undefined) delete ref[key];
        else ref[key] = v;
        const out = upgradeFields({ preUpdateSnapshot: ref, minCompatibleCode: "1.0.0", schemaVersion: { app: 1, sdk: 2 } });
        assert.ok(!("preUpdateSnapshot" in out), `${key}=${String(v)} drops the snapshot`);
        assert.equal(out.minCompatibleCode, "1.0.0");
        assert.deepEqual(out.schemaVersion, { app: 1, sdk: 2 });
      }
    }
    for (const notRef of ["x", 3, true, [], [snap], {}]) assert.ok(!("preUpdateSnapshot" in upgradeFields({ preUpdateSnapshot: notRef })), JSON.stringify(notRef));
  });

  test("members beyond the five are never copied (bytes and schema of the SDK-internal snapshot stay out)", () => {
    const out = upgradeFields({ preUpdateSnapshot: { ...snap, bytes: 123, schema: { app: 1, sdk: 1 }, path: "/data/backup" } });
    assert.deepEqual(out, { preUpdateSnapshot: snap });
    assert.deepEqual(Object.keys(out.preUpdateSnapshot ?? {}), ["file", "sha256", "createdAt", "from", "to"]);
  });
});

describe("0.1.31: the snapshot ref in the status report and one health event per change (L34)", () => {
  let w: World;
  const lines: { level: string; event: string }[] = [];
  const logger: Logger = {
    info: (event) => lines.push({ level: "info", event }),
    warn: (event) => lines.push({ level: "warn", event }),
    error: (event) => lines.push({ level: "error", event }),
  };
  let health = 0;
  before(async () => {
    w = await makeWorld({ real: true, logger });
    await waitFor(() => w.bridge.ctx.table?.rev === w.rev(), 15000);
    w.bridge.ctx.on("health", () => health++);
  });
  after(async () => {
    await w.close();
  });

  test("forwarded / dropped / null / absent in the report; exactly one health event per change, none without a change", async () => {
    const api = w.api;
    const appKey = await api.generateKeyPair();
    const claim = await fetch(`${w.internalUrl}/tb/v1/claim`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ code: APP_CODE, instancePublicKey: appKey.publicJwk, manifestDigest: w.bridge.ctx.table?.config.apps[0]?.manifestDigest, version: "1.0.0", sdkVersion: "0.1.25" }),
    });
    assert.equal(claim.status, 200);
    await claim.body?.cancel();
    const status = async (extra: Record<string, unknown>) => {
      const pathAndQuery = "/tb/v1/status?wait=0";
      const body = Buffer.from(JSON.stringify({ readiness: "degraded", version: "1.0.0", sdkVersion: "0.1.25", scopesRev: 0, sliceRevision: -1, keysRev: -1, pendingHolds: 0, ...extra }));
      const assertion = await api.signAssertion("tb-instance-assert+jwt", { iss: `tb:ins:${INS}`, sub: `tb:ins:${INS}`, aud: `tb:brg:${BRG}`, iat: now(), exp: now() + 60, jti: api.ulid() }, appKey, { method: "POST", pathAndQuery, body });
      const r = await fetch(`${w.internalUrl}${pathAndQuery}`, { method: "POST", headers: { "content-type": "application/json", "TB-Assert": assertion }, body });
      await r.body?.cancel();
      assert.ok(r.status === 200 || r.status === 204, `status accepted (${r.status})`);
    };
    const app = () => (buildStatusReport(w.bridge.ctx).apps.find((a) => a.ins === INS) ?? {}) as Record<string, unknown>;
    const emits = async (extra: Record<string, unknown>) => {
      const before = health;
      await status(extra);
      return health - before;
    };

    // baseline: the first report emits; its scope_summary refresh emits only when the labels change; let it settle first
    const first = health;
    lines.length = 0;
    await status({});
    // S4-1: the scope-summary refresh emits health only when the labels change (this app has none), so wait for it to have finished
    await waitFor(() => health - first >= 1 && w.bridge.ctx.scopeSummaryRuns.size === 0 && w.bridge.ctx.scopeSummaryAt.has(INS as never), 15000);
    assert.ok(!("preUpdateSnapshot" in app()), "absent stays absent");
    assert.equal(await emits({}), 0, "no change → no health event");

    // appears → one event; the report carries it
    assert.equal(await emits({ preUpdateSnapshot: snap }), 1, "snapshot appears");
    assert.deepEqual(app().preUpdateSnapshot, snap);
    assert.equal(await emits({ preUpdateSnapshot: snap }), 0, "same snapshot → no event");
    assert.equal(await emits({ preUpdateSnapshot: { ...snap } }), 0, "same snapshot again → no event");

    // changes (a new file and sha256 after the next update) → one event each
    const next = { ...snap, file: "tb-preupdate-to-1.3.0.tar.gz", sha256: "f".repeat(64), createdAt: "2026-10-17T10:00:00.000Z", from: "1.2.0", to: "1.3.0" };
    assert.equal(await emits({ preUpdateSnapshot: next }), 1, "snapshot changes");
    assert.deepEqual(app().preUpdateSnapshot, next);
    assert.equal(await emits({ preUpdateSnapshot: next }), 0, "same changed snapshot");
    // the health event pokes the status loop: Portal gets the ref without waiting for the 5 min period
    const sentRef = (r: { apps: unknown[] }) => JSON.stringify(((r.apps as { ins: string }[]).find((a) => a.ins === INS) as Record<string, unknown> | undefined)?.preUpdateSnapshot);
    await waitFor(() => w.acks.some((r) => sentRef(r) === JSON.stringify(next)), 15000);

    // → null: a change (a ref existed, now it is null) → one event; null is forwarded as null
    assert.equal(await emits({ preUpdateSnapshot: null }), 1, "snapshot → null");
    assert.ok("preUpdateSnapshot" in app() && app().preUpdateSnapshot === null, "null forwarded as null");
    assert.equal(await emits({ preUpdateSnapshot: null }), 0, "null → null is quiet");

    // → ref again, then malformed: the drop is a change of the forwarded view (one event), the ref is gone from the report
    assert.equal(await emits({ preUpdateSnapshot: snap }), 1, "null → ref");
    assert.equal(await emits({ preUpdateSnapshot: { ...snap, sha256: "sha256:abc" } }), 1, "ref → malformed (dropped)");
    assert.ok(!("preUpdateSnapshot" in app()), "malformed snapshot dropped from the report");
    // malformed → malformed (different junk) and malformed → absent forward nothing both times → quiet
    assert.equal(await emits({ preUpdateSnapshot: { ...snap, file: "../x" } }), 0, "malformed → malformed is quiet");
    assert.equal(await emits({}), 0, "malformed → absent is quiet (nothing was forwarded)");
    assert.ok(!("preUpdateSnapshot" in app()), "absent again");
  });
});
