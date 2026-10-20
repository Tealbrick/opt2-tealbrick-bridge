/**
 * Bridge 0.1.33 (spec 0.1.51, G2b, INC-20261019-04): while Core runs a health-gated update attempt, `apps[]` carries
 * `candidateManifestDigest` + `candidateVersion` next to the SERVING `manifestDigest`. A bridge that restarts mid-attempt
 * (the service already runs the new image) must accept EITHER digest in every place that compares digests: the routing table
 * (boot, new config, previous-manifest cache), the retry of a down app, and the claim. It uses and REPORTS the manifest the
 * service serves, never reports manifest_mismatch for the candidate; a digest equal to neither still refuses manifest_mismatch.
 */
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import { buildStatusReport } from "../src/portal.ts";
import { type AppRuntime, buildTable } from "../src/table.ts";
import { APP_CODE, INS, makeWorld, notesManifest, type World, waitFor } from "./support/world.ts";

const v = (version: string) => ({ ...notesManifest, version });
// The world boots with notesManifest in its manifest cache. The attempt below goes OLD (serving) -> CAND (candidate), neither
// of which is cached, so every config of these tests needs a manifest fetch (a cache hit would hide what the service serves).
const OLD = v("1.1.0");
const CAND = v("1.1.1");
const THIRD = v("1.1.2");

const mismatches = (w: World) => buildStatusReport(w.bridge.ctx).rejected.filter((r) => r.kind === "manifest" && r.code === "manifest_mismatch");
const app = (w: World) => w.bridge.ctx.table?.apps.get(INS as never);
const reported = (w: World) => buildStatusReport(w.bridge.ctx).apps.find((a) => a.ins === INS)?.manifestDigest;
type Entry = NonNullable<World["bridge"]["ctx"]["table"]>["config"]["apps"][number];

/** Core mid-attempt: serving OLD (manifestDigest), candidate CAND; `served` is what the service answers on /tb/v1/manifest. */
async function midAttempt(w: World, served: Record<string, unknown>, o: { candidateVersion?: boolean } = {}): Promise<{ dOld: string; dNew: string }> {
  const dOld = w.api.manifestDigest(OLD as never);
  const dNew = w.api.manifestDigest(CAND as never);
  w.updateAppTo(served); // the service answers with `served`
  await w.amend((c) => {
    c.apps[0] = { ...(c.apps[0] as Entry), version: "1.1.0", manifestDigest: dOld as never, candidateManifestDigest: dNew, ...(o.candidateVersion === false ? {} : { candidateVersion: "1.1.1" }) } as never;
  });
  await waitFor(() => w.bridge.ctx.table?.rev === w.rev(), 15000);
  return { dOld, dNew };
}

function world(): { get: () => World } {
  let w: World;
  before(async () => {
    w = await makeWorld({ real: true });
  });
  after(async () => {
    await w.close();
  });
  return { get: () => w };
}

describe("G2b: table build accepts the candidate digest (serves candidate)", () => {
  const h = world();
  test("the service serves the CANDIDATE manifest: app up, the served manifest is used, no rejection, the digest that RUNS is reported", async () => {
    const w = h.get();
    const { dNew } = await midAttempt(w, CAND);
    assert.equal(app(w)?.down, false);
    assert.equal(app(w)?.manifest?.version, "1.1.1");
    assert.deepEqual(mismatches(w), [], "no manifest_mismatch for the candidate");
    assert.equal(reported(w), dNew);
  });
});

describe("G2b: table build with the OLD manifest served", () => {
  const h = world();
  test("the service still serves the OLD manifest: app up, the serving digest is reported", async () => {
    const w = h.get();
    const { dOld } = await midAttempt(w, OLD);
    assert.equal(app(w)?.down, false);
    assert.equal(app(w)?.manifest?.version, "1.1.0");
    assert.deepEqual(mismatches(w), []);
    assert.equal(reported(w), dOld);
  });
});

describe("G2b: table build with a THIRD digest served", () => {
  const h = world();
  test("a digest equal to neither is refused manifest_mismatch as before", async () => {
    const w = h.get();
    await midAttempt(w, THIRD);
    assert.equal(app(w)?.down, true);
    await waitFor(() => mismatches(w).some((r) => r.ins === INS), 15000); // reported to Core (again on every retry)
    assert.equal(reported(w), null);
  });
});

describe("G2b: both fields or neither", () => {
  const h = world();
  test("a candidate digest without candidateVersion is ignored: the candidate manifest is refused manifest_mismatch", async () => {
    const w = h.get();
    await midAttempt(w, CAND, { candidateVersion: false });
    assert.equal(app(w)?.down, true);
    await waitFor(() => mismatches(w).some((r) => r.ins === INS), 15000);
  });
});

describe("G2b: the previous-manifest cache is looked up by both digests", () => {
  const h = world();
  const build = async (w: World, previous: NonNullable<World["bridge"]["ctx"]["table"]>, entry: Record<string, unknown>) => {
    let fetched = 0;
    const t = w.bridge.ctx.table;
    assert.ok(t);
    const next = await buildTable({
      api: w.api,
      config: { ...t.config, rev: t.config.rev + 1, apps: [{ ...(t.config.apps[0] as Entry), ...entry } as never] },
      jws: t.jws,
      bridgeId: t.bridgeId,
      ownKeys: t.bridgeKeys,
      issuers: t.issuers,
      previous,
      fetchManifest: async () => {
        fetched++;
        throw new Error("must come from the cache");
      },
      now: Math.floor(Date.now() / 1000),
      reject: () => {},
    });
    return { app: next.apps.get(INS as never), fetched };
  };
  /** a previous table whose app holds the manifest of `digest` */
  const previousHolding = (w: World, digest: string): NonNullable<World["bridge"]["ctx"]["table"]> => {
    const t = w.bridge.ctx.table;
    assert.ok(t);
    const a = t.apps.get(INS as never) as AppRuntime;
    return { ...t, apps: new Map([[INS as never, { ...a, digest: digest as never, manifest: CAND as never }]]) } as never;
  };

  test("held under the candidate digest: the config that lists it as the serving digest reuses it, no fetch", async () => {
    const w = h.get();
    const dNew = w.api.manifestDigest(CAND as never);
    const r = await build(w, previousHolding(w, dNew), { version: "1.1.1", manifestDigest: dNew });
    assert.equal(r.fetched, 0);
    assert.equal(r.app?.down, false);
    assert.equal(r.app?.digest, dNew);
  });

  test("held under the candidate digest: the config that lists old serving + candidate reuses it, no fetch", async () => {
    const w = h.get();
    const dOld = w.api.manifestDigest(OLD as never);
    const dNew = w.api.manifestDigest(CAND as never);
    const r = await build(w, previousHolding(w, dNew), { version: "1.1.0", manifestDigest: dOld, candidateManifestDigest: dNew, candidateVersion: "1.1.1" });
    assert.equal(r.fetched, 0, "found through the candidate digest");
    assert.equal(r.app?.down, false);
    assert.equal(r.app?.digest, dNew);
  });

  test("held under a digest the config does not list: nothing is reused (fetch)", async () => {
    const w = h.get();
    const dOld = w.api.manifestDigest(OLD as never);
    const dNew = w.api.manifestDigest(CAND as never);
    const r = await build(w, previousHolding(w, w.api.manifestDigest(THIRD as never)), { version: "1.1.0", manifestDigest: dOld, candidateManifestDigest: dNew, candidateVersion: "1.1.1" });
    assert.equal(r.fetched, 1);
    assert.equal(r.app?.down, true);
  });
});

describe("G2b: the retry of a down app accepts the candidate", () => {
  const h = world();
  test("the service is down (restarting) at config time, then serves the candidate: the retry recovers it, no manifest_mismatch", async () => {
    const w = h.get();
    const dOld = w.api.manifestDigest(OLD as never);
    const dNew = w.api.manifestDigest(CAND as never);
    // the service serves CAND but fails its next 2 manifest fetches (a restart in progress)
    w.updateAppTo(CAND, 2);
    await w.amend((c) => {
      c.apps[0] = { ...(c.apps[0] as Entry), version: "1.1.0", manifestDigest: dOld as never, candidateManifestDigest: dNew, candidateVersion: "1.1.1" } as never;
    });
    await waitFor(() => w.bridge.ctx.table?.rev === w.rev(), 15000);
    await waitFor(() => app(w)?.down === false, 20000);
    assert.equal(app(w)?.manifest?.version, "1.1.1");
    assert.equal(reported(w), dNew);
    assert.deepEqual(mismatches(w), []);
  });
});

describe("G2b: the retry keeps refusing a third digest", () => {
  const h = world();
  test("a third digest is refused on every retry", async () => {
    const w = h.get();
    await midAttempt(w, THIRD);
    await new Promise((r) => setTimeout(r, 3500)); // at least one retry tick
    assert.equal(app(w)?.down, true);
    await waitFor(() => mismatches(w).some((r) => r.ins === INS), 15000);
  });
});

describe("G2b: restart mid-attempt", () => {
  const h = world();
  test("the bridge restarts while the service already serves the candidate: the stored config is applied at boot, the app is up, no rejection", async () => {
    const w = h.get();
    const { dNew } = await midAttempt(w, CAND);
    await w.restart();
    await waitFor(() => app(w)?.down === false, 20000);
    assert.equal(app(w)?.manifest?.version, "1.1.1");
    assert.deepEqual(mismatches(w), []);
    assert.equal(reported(w), dNew);
  });
});

describe("G2b: the claim accepts the candidate digest", () => {
  const h = world();
  const claim = (w: World, manifestDigest: string, key: unknown) =>
    fetch(`${w.internalUrl}/tb/v1/claim`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ code: APP_CODE, instancePublicKey: key, manifestDigest, version: "1.1.1", sdkVersion: "0.1.2" }),
    });

  test("a digest equal to neither is refused manifest_mismatch (the code is kept); the candidate digest claims and is recorded", async () => {
    const w = h.get();
    const { dNew } = await midAttempt(w, CAND);
    const appKey = await w.api.generateKeyPair();
    const bad = await claim(w, w.api.manifestDigest(THIRD as never), appKey.publicJwk);
    assert.equal(bad.status, 409);
    assert.equal((await bad.json()).error.code, "manifest_mismatch");
    const ok = await claim(w, dNew, appKey.publicJwk);
    assert.equal(ok.status, 200, "the candidate digest is accepted");
    assert.equal((await ok.json()).ins, INS);
    assert.equal(w.bridge.ctx.state.claims.find((c) => c.ins === INS)?.manifestDigest, dNew, "the claim is recorded as usual");
  });
});

describe("G2b: the claim with the serving digest still works mid-attempt", () => {
  const h = world();
  test("serving digest accepted", async () => {
    const w = h.get();
    const { dOld } = await midAttempt(w, OLD);
    const appKey = await w.api.generateKeyPair();
    const r = await fetch(`${w.internalUrl}/tb/v1/claim`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ code: APP_CODE, instancePublicKey: appKey.publicJwk, manifestDigest: dOld, version: "1.1.0", sdkVersion: "0.1.2" }),
    });
    assert.equal(r.status, 200);
  });
});
