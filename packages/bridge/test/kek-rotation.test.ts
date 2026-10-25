/**
 * BRG-05: KEK rotation (TB_KEK_PREVIOUS) with real manifest crypto and real files in a temp dir.
 * BRG-25: the `format` marker of 0.1.12–0.1.25 is neither read nor written; the key store uses the shared record path.
 */
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, test } from "node:test";
import { type ManifestApi, manifestApi } from "@opt2-tealbrick/relay";
import { BridgeState, keksFromEnv } from "../src/state.ts";
import { AGT, BRG, CON, INS, makeWorld, WS, waitFor } from "./support/world.ts";

const K1 = "a1".repeat(32);
const K2 = "b2".repeat(32);
const K3 = "c3".repeat(32);
const now = () => Math.floor(Date.now() / 1000);
const api = manifestApi();
const kekId = (hex: string) => api.kekFromEnv(hex).id;

/** every sealed record a bridge can hold, plus the 0.1.25 `format` marker */
const ALL = ["claims", "connections", "enrol-refused", "identity", "jtis", "keys", "models", "reports", "standalone"].map((n) => `${n}.sealed.json`);

const keks = (current: string, previous?: string) => keksFromEnv({ TB_KEK: current, ...(previous ? { TB_KEK_PREVIOUS: previous } : {}) }, api);

function tempData(): { data: string; dir: string; done: () => void } {
  const data = mkdtempSync(join(tmpdir(), "tb-kek-"));
  return { data, dir: join(data, "bridge"), done: () => rmSync(data, { recursive: true, force: true }) };
}

/** Writes EVERY record kind under `kek` (as a running bridge would), plus a 0.1.25 format marker. */
async function writeFullState(data: string, kek: string): Promise<void> {
  const st = new BridgeState(data, api, keks(kek));
  st.load();
  const key = await api.generateKeyPair();
  await st.saveIdentity({ bridgeId: BRG as never, workspaceId: WS as never, key, portalKeys: [], enrolCodeDigest: "sha256:00" as never, configPath: "/c", ackPath: "/a" });
  st.connections.set(CON as never, { con: CON, agt: AGT, refreshDigest: "sha256:rd", gen: 1, previousDigest: null, previousUntil: null, previousUsed: false, expiresAt: now() + 3600, clientName: "c", createdAt: now(), reported: true } as never);
  st.saveConnections();
  st.claims = [{ kind: "instance", ins: INS, codeDigest: "sha256:cd", reported: false } as never];
  st.saveClaims();
  assert.ok(st.useJti("J1", now() + 600));
  st.setKey("OPENAI", "value-1");
  // v0.1.63: S11 model-role bindings are a sealed record too
  st.saveBindings([{ role: "reasoning", provider: "openai", model: "m-1", keyName: "OPENAI", dataPolicy: "standard" }]);
  st.standalone = { pausedWorkspace: false, pausedAgents: [], revokedConnections: [], rev: 3 };
  st.saveStandalone();
  st.reports = { revoked: [{ con: CON as never, reason: "client_revoke" }], pairingJtis: {} };
  st.saveReports();
  st.saveRefusedEnrolCode("sha256:refused" as never);
  // the marker 0.1.12–0.1.25 wrote next to the identity (BRG-25: no reader)
  writeFileSync(join(data, "bridge", "format.sealed.json"), JSON.stringify(api.seal(Buffer.from(JSON.stringify({ v: 2 })), api.kekFromEnv(kek), "tb:seal:bridge-state:format")));
}

/** Loads with the given keys and returns what a bridge reads back. */
async function readBack(data: string, k: ReturnType<typeof keks>) {
  const st = new BridgeState(data, api, k);
  const resealed = st.load();
  const id = await st.loadIdentity();
  return { resealed, st, id, refused: st.loadRefusedEnrolCode() };
}

function assertFullState(r: Awaited<ReturnType<typeof readBack>>): void {
  assert.equal(r.id?.bridgeId, BRG);
  assert.equal(r.st.connections.get(CON as never)?.gen, 1);
  assert.equal(r.st.claims[0]?.ins, INS);
  assert.ok(r.st.usedJtis.has("J1"));
  assert.equal(r.st.keyStore.values.OPENAI, "value-1");
  assert.equal(r.st.bindings[0]?.model, "m-1");
  assert.equal(r.st.standalone?.rev, 3);
  assert.equal(r.st.reports.revoked[0]?.con, CON);
  assert.equal(r.refused, "sha256:refused");
}

const kekOf = (dir: string, f: string) => (JSON.parse(readFileSync(join(dir, f), "utf8")) as { kek: string }).kek;
const snapshot = (dir: string) => Object.fromEntries(readdirSync(dir).sort().map((f) => [f, `${readFileSync(join(dir, f), "utf8")}|${statSync(join(dir, f)).mtimeMs}`]));

describe("BRG-05: KEK rotation reseals every record", () => {
  test("rotate (TB_KEK=K2, TB_KEK_PREVIOUS=K1) -> restart with K2 only -> every record readable; the 0.1.25 marker is gone", async () => {
    const t = tempData();
    try {
      await writeFullState(t.data, K1);
      for (const f of ALL) assert.equal(kekOf(t.dir, f), kekId(K1), `${f} starts under K1`);
      const rotated = await readBack(t.data, keks(K2, K1));
      assert.equal(rotated.resealed, ALL.length, "all 9 records resealed (identity, enrol-refused, keys and models included)");
      assertFullState(rotated);
      for (const f of ALL) assert.equal(kekOf(t.dir, f), kekId(K2), `${f} is under K2`);
      assert.ok(!existsSync(join(t.dir, "format.sealed.json")), "the stale format marker is removed (nothing reads it)");
      // the old key is gone: K2 alone opens everything, and a later identity save (key-set re-pin) works
      const after = await readBack(t.data, keks(K2));
      assert.equal(after.resealed, 0);
      assertFullState(after);
      assert.ok(after.id);
      await after.st.saveIdentity({ ...after.id, pinnedKeySet: { seq: 2, kss: "x.y.z" } as never });
      assert.equal((await new BridgeState(t.data, api, keks(K2)).loadIdentity())?.pinnedKeySet?.seq, 2);
      assert.ok(!existsSync(join(t.dir, "format.sealed.json")), "0.1.26 never writes the format marker");
      // and K1 alone no longer opens the state: plain error, nothing written
      const before = snapshot(t.dir);
      assert.throws(() => new BridgeState(t.data, api, keks(K1)).load(), /sealed under another key than TB_KEK; set the key it was sealed with \(state unchanged\)/);
      assert.deepEqual(snapshot(t.dir), before);
    } finally {
      t.done();
    }
  });

  test("a wrong TB_KEK is refused with a plain error and nothing is overwritten (L7)", async () => {
    const t = tempData();
    try {
      await writeFullState(t.data, K1);
      const before = snapshot(t.dir);
      assert.throws(() => new BridgeState(t.data, api, keks(K3)).load(), (e: Error & { code?: string }) => e.code === "kek_mismatch" && /sealed under another key than TB_KEK;/.test(e.message));
      assert.throws(() => new BridgeState(t.data, api, keks(K3, K2)).load(), /sealed under another key than TB_KEK or TB_KEK_PREVIOUS; set the key it was sealed with \(state unchanged\)/);
      await assert.rejects(new BridgeState(t.data, api, keks(K3)).loadIdentity(), /identity\.sealed\.json is sealed under another key/);
      assert.deepEqual(snapshot(t.dir), before, "every file byte-identical, no temp files");
      // a damaged record during a rotation: phase 1 opens ALL records before the first write, so nothing moves
      const blob = JSON.parse(readFileSync(join(t.dir, "reports.sealed.json"), "utf8")) as { ct: string };
      blob.ct = `${blob.ct.slice(0, -2)}AA`;
      writeFileSync(join(t.dir, "reports.sealed.json"), JSON.stringify(blob));
      const damaged = snapshot(t.dir);
      assert.throws(() => new BridgeState(t.data, api, keks(K2, K1)).load(), /reports\.sealed\.json cannot be opened with its key \(edited or damaged; state unchanged\)/);
      assert.deepEqual(snapshot(t.dir), damaged, "no record was resealed");
      for (const f of ALL) assert.equal(kekOf(t.dir, f), kekId(K1));
    } finally {
      t.done();
    }
  });

  test("a crash in the middle of a reseal: the next start recovers (each record atomic: tmp + fsync + rename)", async () => {
    const t = tempData();
    try {
      await writeFullState(t.data, K1);
      // the process dies after the 3rd record was resealed (the 4th seal never returns)
      let seals = 0;
      const crashing: ManifestApi = {
        ...api,
        seal: (pt, kek, aad) => {
          seals += 1;
          if (seals === 4) throw new Error("simulated crash");
          return api.seal(pt, kek, aad);
        },
      };
      assert.throws(() => new BridgeState(t.data, crashing, keks(K2, K1)).load(), /simulated crash/);
      const kekIds = ALL.map((f) => kekOf(t.dir, f));
      assert.equal(kekIds.filter((k) => k === kekId(K2)).length, 3, "three records under K2");
      assert.equal(kekIds.filter((k) => k === kekId(K1)).length, ALL.length - 3, "the rest still under K1");
      assert.ok(!readdirSync(t.dir).some((f) => f.includes(".tmp-")), "the failed write left no temp file");
      // a hard crash between write and rename leaves a temp file: it is never read
      writeFileSync(join(t.dir, "claims.sealed.json.tmp-0123456789ab"), "{torn");
      const resumed = await readBack(t.data, keks(K2, K1));
      assert.equal(resumed.resealed, ALL.length - 3, "only the records left under K1 are resealed");
      assertFullState(resumed);
      const done = await readBack(t.data, keks(K2));
      assertFullState(done);
    } finally {
      t.done();
    }
  });

  test("L34 quiet case: no TB_KEK_PREVIOUS = no reseal writes; TB_KEK_PREVIOUS with nothing left = no writes either", async () => {
    const t = tempData();
    try {
      await writeFullState(t.data, K1);
      const before = snapshot(t.dir);
      const plain = await readBack(t.data, keks(K1));
      assert.equal(plain.resealed, 0);
      assertFullState(plain);
      assert.deepEqual(snapshot(t.dir), before, "no file rewritten (content and mtime), the 0.1.25 marker untouched");
      // after a finished rotation the leftover TB_KEK_PREVIOUS changes nothing
      assert.equal((await readBack(t.data, keks(K2, K1))).resealed, ALL.length);
      const rotated = snapshot(t.dir);
      const again = await readBack(t.data, keks(K2, K1));
      assert.equal(again.resealed, 0);
      assert.deepEqual(snapshot(t.dir), rotated);
    } finally {
      t.done();
    }
  });
});

describe("BRG-05: a running bridge rotates its KEK across restarts (real world)", () => {
  test("K1 -> (K2 + previous K1) -> K2 only: identity, OAuth client ids and a later key-set re-pin keep working", async () => {
    const w = await makeWorld({ real: true, env: { TB_KEK: K1 } });
    try {
      await waitFor(() => w.bridge.ctx.table?.rev === w.rev(), 15000);
      const reg = await fetch(`${w.publicUrl}/oauth/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ redirect_uris: ["https://client.example/cb"], client_name: "kek" }) });
      assert.equal(reg.status, 201);
      const clientId = ((await reg.json()) as { client_id: string }).client_id;
      const authorize = () => fetch(`${w.publicUrl}/oauth/authorize?response_type=code&client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent("https://client.example/cb")}&code_challenge=${"a".repeat(43)}&code_challenge_method=S256&state=s`);
      // a known client gets the connect page (200); an unknown one the "Unknown app" page (400)
      const known = async () => {
        const r = await authorize();
        const text = await r.text();
        assert.ok(r.status === 200 ? text.includes("Connect an agent") : text.includes("Unknown app"), `status ${r.status} matches its page`);
        return r.status === 200;
      };
      assert.ok(await known(), "client id valid under K1");
      const sealedFiles = () => readdirSync(join(w.dataDir, "bridge")).filter((n) => n.endsWith(".sealed.json"));
      assert.ok(sealedFiles().includes("identity.sealed.json"));
      for (const f of sealedFiles()) assert.equal(kekOf(join(w.dataDir, "bridge"), f), kekId(K1), `${f} starts under K1`);

      w.setEnv("TB_KEK", K2);
      w.setEnv("TB_KEK_PREVIOUS", K1);
      await w.restart();
      await waitFor(() => w.bridge.ctx.table?.rev === w.rev(), 15000);
      for (const f of sealedFiles()) assert.equal(kekOf(join(w.dataDir, "bridge"), f), kekId(K2), `${f} resealed`);
      assert.ok(await known(), "a client id sealed under K1 is still accepted while TB_KEK_PREVIOUS is set");

      w.setEnv("TB_KEK_PREVIOUS", "");
      await w.restart();
      await waitFor(() => w.bridge.ctx.table?.rev === w.rev(), 15000);
      assert.equal(w.bridge.ctx.identity?.bridgeId, BRG, "identity opens with K2 alone");
      // DCR is stateless (the client id lives at the client): after the window, a client registered before the
      // rotation registers again; existing connections (refresh tokens) do not use the client id
      assert.ok(!(await known()), "a pre-rotation client id is unknown once TB_KEK_PREVIOUS is dropped");
      await w.keySet.bump({ seq: 2 });
      await w.publish();
      await waitFor(() => w.bridge.ctx.identity?.pinnedKeySet?.seq === 2 && w.bridge.ctx.table?.rev === w.rev(), 15000);
      await w.restart();
      await waitFor(() => w.bridge.ctx.table?.rev === w.rev(), 15000);
      assert.equal(w.bridge.ctx.identity?.pinnedKeySet?.seq, 2, "re-pinned identity saved and reloaded under K2");
      assert.ok(!existsSync(join(w.dataDir, "bridge", "format.sealed.json")), "no format marker is written");
    } finally {
      await w.close();
    }
  });
});
