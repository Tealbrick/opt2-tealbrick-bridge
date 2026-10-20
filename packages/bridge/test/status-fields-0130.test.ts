/**
 * Bridge 0.1.30 (C213 US-2, spec 0.1.39): AppStatus schemaVersion / minCompatibleCode / failure reach
 * StatusReport.apps[] only when well-formed; malformed is dropped per field; absent stays absent (L24).
 * L34: a change in any forwarded field emits exactly one health event (one Portal report poke); a repeat or a change
 * that the shape check drops emits none.
 */
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import type { BootFailure } from "@opt2-tealbrick/spec/bridge";
import { buildStatusReport } from "../src/portal.ts";
import { BOOT_PHASES, type BootPhase, upgradeFields } from "../src/status-fields.ts";
import type { Logger } from "../src/util.ts";
import { APP_CODE, BRG, INS, makeWorld, type World, waitFor } from "./support/world.ts";

const now = () => Math.floor(Date.now() / 1000);
const failure = { phase: "app_migrations", code: "migration_failed", reason: "migration_failed", file: "0003_bad.sql", at: "2026-10-16T14:46:23.400Z" };

// L1 compile-time check (tsc runs over test/ in `typecheck`): BOOT_PHASES's element type IS the spec union, both ways.
type Equal<A, B> = (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2 ? true : false;
const phaseTypeIsSpec: Equal<BootPhase, BootFailure["phase"]> = true;
const SPEC_PHASES = ["restore", "open", "schema", "lock", "snapshot", "sdk_migrations", "app_migrations"] as const satisfies readonly BootFailure["phase"][];
const listCoversSpec: Equal<(typeof SPEC_PHASES)[number], BootFailure["phase"]> = true;

describe("0.1.30 upgradeFields: shape check per field", () => {
  test("BOOT_PHASES equals the spec 0.1.39 BootFailure phase union", () => {
    assert.ok(phaseTypeIsSpec && listCoversSpec);
    assert.deepEqual([...BOOT_PHASES].sort(), [...SPEC_PHASES].sort());
  });

  test("well-formed members are forwarded unchanged", () => {
    assert.deepEqual(upgradeFields({ schemaVersion: { app: 2, sdk: 5 }, minCompatibleCode: "1.2.3-rc.1", failure }), {
      schemaVersion: { app: 2, sdk: 5 },
      minCompatibleCode: "1.2.3-rc.1",
      failure,
    });
    assert.deepEqual(upgradeFields({ minCompatibleCode: null }), { minCompatibleCode: null }, "null = unknown is forwarded");
    assert.deepEqual(upgradeFields({ schemaVersion: { app: 0, sdk: 0 } }), { schemaVersion: { app: 0, sdk: 0 } });
    for (const phase of SPEC_PHASES) assert.equal(upgradeFields({ failure: { ...failure, phase } }).failure?.phase, phase);
  });

  test("absent stays absent; extra members are never copied", () => {
    assert.deepEqual(upgradeFields({}), {});
    assert.deepEqual(upgradeFields(undefined), {});
    assert.deepEqual(upgradeFields("x"), {});
    const out = upgradeFields({ schemaVersion: { app: 1, sdk: 1, extra: 9 }, failure: { ...failure, sql: "DROP TABLE x" }, preUpdateSnapshot: { file: "a" } });
    assert.deepEqual(out, { schemaVersion: { app: 1, sdk: 1 }, failure });
  });

  test("schemaVersion malformed → dropped (the other members still pass)", () => {
    for (const sv of [{ app: -1, sdk: 1 }, { app: 1.5, sdk: 1 }, { app: 1 }, { app: "1", sdk: 1 }, { app: 1, sdk: Number.MAX_SAFE_INTEGER + 1 }, [1, 1], null, 3]) {
      const out = upgradeFields({ schemaVersion: sv, minCompatibleCode: "1.0.0" });
      assert.ok(!("schemaVersion" in out), JSON.stringify(sv));
      assert.equal(out.minCompatibleCode, "1.0.0");
    }
  });

  test("minCompatibleCode malformed → dropped", () => {
    for (const mc of ["<script>", "1.0", "v1.0.0", "1.0.0-", " 1.0.0", 1, {}, undefined]) {
      const out = upgradeFields({ minCompatibleCode: mc, schemaVersion: { app: 1, sdk: 1 } });
      assert.ok(!("minCompatibleCode" in out), String(mc));
      assert.deepEqual(out.schemaVersion, { app: 1, sdk: 1 });
    }
  });

  test("failure: a bad required member drops the whole failure; a bad optional member drops only that member", () => {
    for (const bad of [{ phase: "evil" }, { phase: undefined }, { code: "Not Code" }, { code: 7 }, { at: "now" }, { at: "2026-10-16 14:46:23Z" }, { at: undefined }]) {
      assert.ok(!("failure" in upgradeFields({ failure: { ...failure, ...bad } })), JSON.stringify(bad));
    }
    assert.ok(!("failure" in upgradeFields({ failure: "migration_failed" })));
    const { reason: _r, file: _f, ...required } = failure;
    assert.deepEqual(upgradeFields({ failure: { ...failure, reason: "Some Text", file: "../../etc/passwd" } }).failure, required);
    assert.deepEqual(upgradeFields({ failure: { ...failure, file: "0003_bad.sh" } }).failure, { ...required, reason: failure.reason });
    assert.deepEqual(upgradeFields({ failure: required }).failure, required, "optional members absent stay absent");
  });
});

describe("0.1.30: forwarded members in the status report and one health event per change (L34)", () => {
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

  test("forwarded when well-formed, dropped when malformed, absent stays absent; exactly one health event per change", async () => {
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
    /** the health events one status report causes (the emit is synchronous inside the status request) */
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
    for (const k of ["schemaVersion", "minCompatibleCode", "failure"]) assert.ok(!(k in app()), `absent ${k} stays absent`);
    assert.equal(await emits({}), 0, "no change → no health event");

    // each member on its own: a change emits exactly once, the repeat emits nothing
    const base = { schemaVersion: { app: 1, sdk: 5 } };
    assert.equal(await emits(base), 1, "schemaVersion appears");
    assert.deepEqual(app().schemaVersion, { app: 1, sdk: 5 });
    assert.equal(await emits(base), 0, "same schemaVersion");
    assert.equal(await emits({ schemaVersion: { app: 2, sdk: 5 } }), 1, "schemaVersion changes");
    assert.equal(await emits({ schemaVersion: { app: 2, sdk: 5 }, minCompatibleCode: "1.0.0" }), 1, "minCompatibleCode appears");
    assert.equal(app().minCompatibleCode, "1.0.0");
    assert.equal(await emits({ schemaVersion: { app: 2, sdk: 5 }, minCompatibleCode: null }), 1, "minCompatibleCode → null");
    assert.equal(app().minCompatibleCode, null);
    const acks = w.acks.length;
    assert.equal(await emits({ schemaVersion: { app: 2, sdk: 5 }, minCompatibleCode: null, failure }), 1, "failure appears");
    assert.deepEqual(app().failure, failure);
    // the health event pokes the status loop: Portal gets the failure without waiting for the 5 min period
    await waitFor(() => w.acks.slice(acks).some((r) => JSON.stringify(r.apps.find((a) => a.ins === INS)?.failure) === JSON.stringify(failure)), 15000);
    assert.equal(await emits({ schemaVersion: { app: 2, sdk: 5 }, minCompatibleCode: null, failure: { ...failure, phase: "sdk_migrations" } }), 1, "failure changes");
    assert.equal(await emits({ schemaVersion: { app: 2, sdk: 5 }, minCompatibleCode: null, failure: { ...failure, phase: "sdk_migrations" } }), 0, "same failure");

    // malformed per field: each drop is a change of the forwarded view (one event), the field is gone from the report
    assert.equal(await emits({ schemaVersion: { app: -1, sdk: 5 }, minCompatibleCode: null, failure: { ...failure, phase: "sdk_migrations" } }), 1);
    assert.ok(!("schemaVersion" in app()), "malformed schemaVersion dropped");
    assert.equal(await emits({ schemaVersion: { app: -1, sdk: 5 }, minCompatibleCode: "<script>", failure: { ...failure, phase: "sdk_migrations" } }), 1);
    assert.ok(!("minCompatibleCode" in app()), "malformed minCompatibleCode dropped");
    assert.equal(await emits({ schemaVersion: { app: -1, sdk: 5 }, minCompatibleCode: "<script>", failure: { ...failure, phase: "evil" } }), 1);
    assert.ok(!("failure" in app()), "malformed failure dropped");
    // one malformed value replaced by another malformed value: the forwarded view does not change → no event
    assert.equal(await emits({ schemaVersion: { app: 1.5, sdk: 5 }, minCompatibleCode: "1.0", failure: { ...failure, at: "now" } }), 0, "malformed → malformed is quiet");
    assert.equal(await emits({}), 0, "malformed → absent is quiet (nothing was forwarded)");
    for (const k of ["schemaVersion", "minCompatibleCode", "failure"]) assert.ok(!(k in app()), `${k} absent again`);
  });
});
