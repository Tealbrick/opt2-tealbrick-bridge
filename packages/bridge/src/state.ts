/**
 * Persistent bridge state on ONE volume (BRIDGE §1.2): S1 identity, S2 last good config, S3 sealed key
 * store, S4 pairing connections, S5 pending claims, S6 used one-time jtis, S9 standalone overlay, S11 model-role
 * bindings + the owner's "Own hosts" (v0.1.63, BRIDGE §15.1 / §15.3; one `keysRev` with S3).
 *
 * Integrity (C62 BSD-03): every record except S2 is sealed with TB_KEK (AES-256-GCM, AAD = purpose + file),
 * so a planted or edited file is refused instead of trusted; S2 is a Portal-signed JWS and is verified on
 * boot. Plaintext state (bridges before 0.1.12) is refused by ONE check at boot (C133: earlier opt2 dev formats are
 * not read; such a bridge is re-enrolled).
 * KEK rotation (BRG-05): with TB_KEK_PREVIOUS set, `load()` first opens every record sealed under the previous KEK,
 * then reseals each one under TB_KEK. After that start, TB_KEK_PREVIOUS can be dropped.
 * Writes are crash-safe (BSD-13): unique temp name, file fsync, rename, directory fsync, temp removed on error.
 */
import { randomBytes } from "node:crypto";
import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeSync } from "node:fs";
import { join } from "node:path";
import type { Kek, ManifestApi } from "@opt2-tealbrick/relay";
import type { ClaimRecord, PairingConnectionRecord } from "@opt2-tealbrick/spec/bridge";
import type { AgentId, BridgeId, ConnectionId, Ed25519PublicJwk, InstanceId, PortalKeyEntry, SealedBlob, Sha256Digest, WorkspaceId } from "@opt2-tealbrick/spec/credentials";
import type { DataPolicy, ModelRole } from "@opt2-tealbrick/spec/models";
import type { Ed25519KeyPair, PinnedKeySet } from "@opt2-tealbrick/spec/sdk";

const isPinned = (v: unknown): v is PinnedKeySet =>
  !!v && typeof v === "object" && Number.isInteger((v as PinnedKeySet).seq) && typeof (v as PinnedKeySet).kss === "string";

import { BridgeError, nowS } from "./util.ts";

export interface Identity {
  bridgeId: BridgeId;
  workspaceId: WorkspaceId;
  key: Ed25519KeyPair;
  portalKeys: PortalKeyEntry[];
  /** v0.1.11 (BSD-08): the pinned key-set statement; once set, the ONLY source of `portalKeys` */
  pinnedKeySet?: PinnedKeySet;
  enrolCodeDigest: Sha256Digest;
  configPath: string;
  ackPath: string;
}

interface IdentityFile {
  bridgeId: BridgeId;
  workspaceId: WorkspaceId;
  kid: string;
  publicKey: Ed25519PublicJwk;
  privateKey: string;
  portalKeys: PortalKeyEntry[];
  pinnedKeySet?: PinnedKeySet;
  enrolCodeDigest: Sha256Digest;
  configPath: string;
  ackPath: string;
}

export interface PendingClaim extends ClaimRecord {
  reported: boolean;
}

export interface StandaloneOverlay {
  pausedWorkspace: boolean;
  pausedAgents: AgentId[];
  revokedConnections: ConnectionId[];
  /** monotonic rev for re-minted documents */
  rev: number;
}

export interface KeyStore {
  keysRev: number;
  /**
   * Requirement-named app keys under their requirement name; v0.1.63 owner-named provider keys (label ≤ 60, e.g.
   * "OpenAI main") under {@link PROVIDER_KEY_PREFIX} + label. A requirement name never contains ":", so the two namespaces
   * can never meet (QA-BRIDGE22-1): `GET /tb/v1/keys/<name>` serves only requirement keys, a role binding names its key
   * exactly (`keyName`).
   */
  values: Record<string, string>;
}

/** S3 namespace of owner-named provider keys (QA-BRIDGE22-1) */
export const PROVIDER_KEY_PREFIX = "pk:";
export const providerKeyName = (label: string): string => `${PROVIDER_KEY_PREFIX}${label}`;
export const isProviderKeyName = (name: string): boolean => name.startsWith(PROVIDER_KEY_PREFIX);

/** S11 (BRIDGE §15.1): one model-role binding. `ins` absent = workspace default; set = override for that app instance. */
export interface ModelBinding {
  role: ModelRole;
  ins?: InstanceId;
  /** MODEL_PROVIDERS id */
  provider: string;
  model: string;
  baseUrl?: string;
  /** a name in S3 (`KeyStore.values`): `pk:<label>` of a provider key, or the requirement name of an app key the owner
   *  chose; absent for a provider with `keyNeeded: false` or when the key was deleted */
  keyName?: string;
  dataPolicy: DataPolicy;
  /** ISO time of the owner's zero-data-retention tick (`zdr` only) */
  zdrAttestedAt?: string;
  /** embeddings only */
  dims?: number;
}

/**
 * The S11 record. `rev` = the `keysRev` this write belongs to: the record is written before the key store, so a crash
 * between the two writes is repaired at boot (keysRev = max of both) and apps still see the change.
 */
interface ModelsRecord {
  rev: number;
  bindings: ModelBinding[];
  /** spec follow-up #49 (§15.3): origins the owner states are on their own network; absent in older records = none */
  ownHosts?: string[];
}

/** Facts the status report must carry until Portal confirmed them (BSD-11): survive restarts. */
export interface PendingReports {
  revoked: { con: ConnectionId; reason: "refresh_reuse" | "client_revoke" }[];
  /** pairing code jti per locally created connection, until a config lists the connection */
  pairingJtis: Record<string, string>;
}

/** Every sealed record on the volume (`<name>.sealed.json`). S2 (config.jws) is a signed JWS, not sealed. */
const RECORDS = ["identity", "connections", "claims", "jtis", "keys", "standalone", "reports", "enrol-refused", "models"] as const;
type RecordName = (typeof RECORDS)[number];
/** AAD = purpose + record; the key store keeps the AAD it has always had (its files must stay readable). */
const aadOf = (name: RecordName): string => (name === "keys" ? "tb:seal:bridge-keys:store" : `tb:seal:bridge-state:${name}`);
/** Plaintext files of bridges before 0.1.12 (C133): refused at boot, never read. */
const PLAINTEXT = ["identity.json", "connections.json", "claims.json", "jtis.json", "standalone.json", "reports.json", "enrol-refused.json"];
/**
 * Marker of bridges 0.1.12–0.1.25 (BRG-25): nothing ever gated on it, so 0.1.26 neither reads nor writes it. A KEK
 * rotation removes a marker sealed under another KEK (a 0.1.25 rollback writes it again when it is absent).
 */
const LEGACY_FORMAT = "format.sealed.json";

function syncDir(dir: string): void {
  try {
    const fd = openSync(dir, "r");
    try {
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
  } catch {
    /* some platforms cannot fsync a directory; the file itself is synced */
  }
}

export function atomicWrite(path: string, data: string | Uint8Array): void {
  const tmp = `${path}.tmp-${randomBytes(6).toString("hex")}`;
  try {
    const fd = openSync(tmp, "wx", 0o600);
    try {
      writeSync(fd, typeof data === "string" ? Buffer.from(data, "utf8") : data);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(tmp, path);
  } catch (e) {
    try {
      unlinkSync(tmp);
    } catch {
      /* already gone */
    }
    throw e;
  }
  syncDir(join(path, ".."));
}

const isSealed = (v: unknown): v is SealedBlob => !!v && typeof v === "object" && (v as SealedBlob).alg === "A256GCM" && typeof (v as SealedBlob).ct === "string";

export class BridgeState {
  private readonly dir: string;
  private readonly api: ManifestApi;
  private readonly keks: { current: Kek; previous?: Kek };
  connections: Map<ConnectionId, PairingConnectionRecord> = new Map();
  claims: PendingClaim[] = [];
  /** S6: one-time jtis (pairing codes, keys tickets) until exp + leeway */
  usedJtis: Map<string, number> = new Map();
  keyStore: KeyStore = { keysRev: 0, values: {} };
  /** S11 (v0.1.63): model-role bindings; values stay in S3 */
  bindings: ModelBinding[] = [];
  /** S11 (spec follow-up #49): the owner's "Own hosts" origins (normalized, model-roles.ts `ownHostOrigin`) */
  ownHosts: string[] = [];
  standalone: StandaloneOverlay | undefined;
  reports: PendingReports = { revoked: [], pairingJtis: {} };

  constructor(dataDir: string, api: ManifestApi, keks: { current: Kek; previous?: Kek }) {
    this.dir = join(dataDir, "bridge");
    this.api = api;
    this.keks = keks;
    mkdirSync(this.dir, { recursive: true, mode: 0o700 });
  }

  private path(name: string): string {
    return join(this.dir, name);
  }

  /** C133: ONE boot check; a plaintext file of a bridge before 0.1.12 is refused, never read. */
  private refusePlaintext(): void {
    const found = PLAINTEXT.filter((f) => existsSync(this.path(f)));
    if (found.length) throw new BridgeError("state_corrupt", 500, `${found.join(", ")}: plaintext state (a bridge before 0.1.12) is not accepted; re-enrol this bridge with a new enrolment code`);
  }

  private readBlob(name: RecordName): SealedBlob | undefined {
    const p = this.path(`${name}.sealed.json`);
    if (!existsSync(p)) return undefined;
    let blob: unknown;
    try {
      blob = JSON.parse(readFileSync(p, "utf8"));
    } catch {
      blob = undefined;
    }
    if (!isSealed(blob)) throw new BridgeError("state_corrupt", 500, `${name}.sealed.json is not a sealed record`);
    return blob;
  }

  /** Opens one record. A blob under an unknown KEK or a damaged blob is refused with a plain error; nothing is written. */
  private open(name: RecordName, blob: SealedBlob): Uint8Array {
    const { current, previous } = this.keks;
    if (blob.kek !== current.id && blob.kek !== previous?.id) {
      throw new BridgeError("kek_mismatch", 500, `${name}.sealed.json is sealed under another key than TB_KEK${previous ? " or TB_KEK_PREVIOUS" : ""}; set the key it was sealed with (state unchanged)`);
    }
    try {
      return this.api.unseal(blob, this.keks, aadOf(name));
    } catch {
      throw new BridgeError("state_corrupt", 500, `${name}.sealed.json cannot be opened with its key (edited or damaged; state unchanged)`);
    }
  }

  private readRecord<T>(name: RecordName): T | undefined {
    const blob = this.readBlob(name);
    return blob ? (JSON.parse(Buffer.from(this.open(name, blob)).toString("utf8")) as T) : undefined;
  }

  /** One record = one atomic write (tmp + fsync + rename + dir fsync) under the CURRENT KEK. */
  private writeSealed(name: RecordName, plaintext: Uint8Array): void {
    atomicWrite(this.path(`${name}.sealed.json`), JSON.stringify(this.api.seal(plaintext, this.keks.current, aadOf(name))));
  }

  private writeRecord(name: RecordName, value: unknown): void {
    this.writeSealed(name, Buffer.from(JSON.stringify(value), "utf8"));
  }

  /**
   * BRG-05 KEK rotation. Phase 1 opens EVERY record that is not yet under TB_KEK (a key that opens none changes
   * nothing, L7). Phase 2 reseals them one by one, each atomically: a crash in between leaves every record readable
   * with TB_KEK + TB_KEK_PREVIOUS, and the next start finishes the rest. Records already under TB_KEK are not
   * rewritten, so a start with nothing left to reseal writes nothing (L34). Returns the number of records resealed.
   */
  private reseal(): number {
    const todo: { name: RecordName; plaintext: Uint8Array }[] = [];
    for (const name of RECORDS) {
      const blob = this.readBlob(name);
      if (blob && blob.kek !== this.keks.current.id) todo.push({ name, plaintext: this.open(name, blob) });
    }
    for (const r of todo) this.writeSealed(r.name, r.plaintext);
    const marker = this.path(LEGACY_FORMAT);
    if (existsSync(marker)) {
      let kek: unknown;
      try {
        kek = (JSON.parse(readFileSync(marker, "utf8")) as { kek?: unknown }).kek;
      } catch {
        kek = undefined;
      }
      if (kek !== this.keks.current.id) unlinkSync(marker);
    }
    return todo.length;
  }

  /**
   * Boot: the plaintext check, the KEK rotation (only with TB_KEK_PREVIOUS), then S3–S6, S9 and pending reports.
   * S1 and S2 are read on demand. Returns the number of records resealed under TB_KEK (0 without a rotation).
   */
  load(): number {
    this.refusePlaintext();
    const resealed = this.keks.previous ? this.reseal() : 0;
    for (const r of this.readRecord<PairingConnectionRecord[]>("connections") ?? []) this.connections.set(r.con, r);
    this.claims = this.readRecord<PendingClaim[]>("claims") ?? [];
    const now = nowS();
    for (const [jti, exp] of Object.entries(this.readRecord<Record<string, number>>("jtis") ?? {})) if (exp > now) this.usedJtis.set(jti, exp);
    this.keyStore = this.readRecord<KeyStore>("keys") ?? { keysRev: 0, values: {} };
    const models = this.readRecord<ModelsRecord>("models");
    this.bindings = models?.bindings ?? [];
    this.ownHosts = models?.ownHosts ?? [];
    // a crash after the S11 write and before the key store write: the change still gets its revision
    if (models && models.rev > this.keyStore.keysRev) {
      this.keyStore.keysRev = models.rev;
      this.saveKeyStore();
    }
    this.standalone = this.readRecord<StandaloneOverlay>("standalone");
    this.reports = this.readRecord<PendingReports>("reports") ?? { revoked: [], pairingJtis: {} };
    return resealed;
  }

  async loadIdentity(): Promise<Identity | undefined> {
    const f = this.readRecord<IdentityFile>("identity");
    if (!f) return undefined;
    if (typeof f.privateKey !== "string") throw new BridgeError("identity_corrupt", 500, "bridge identity has no key");
    const pkcs8 = new Uint8Array(Buffer.from(f.privateKey, "base64url"));
    const key = await this.api.importKeyPair(pkcs8);
    if (key.kid !== f.kid) throw new BridgeError("identity_corrupt", 500, "bridge key does not match its record");
    const id: Identity = { bridgeId: f.bridgeId, workspaceId: f.workspaceId, key, portalKeys: f.portalKeys, ...(isPinned(f.pinnedKeySet) ? { pinnedKeySet: f.pinnedKeySet } : {}), enrolCodeDigest: f.enrolCodeDigest, configPath: f.configPath, ackPath: f.ackPath };
    return id;
  }

  async saveIdentity(id: Identity): Promise<void> {
    const pkcs8 = await this.api.exportPrivateKey(id.key);
    const f: IdentityFile = {
      bridgeId: id.bridgeId,
      workspaceId: id.workspaceId,
      kid: id.key.kid,
      publicKey: id.key.publicJwk,
      privateKey: Buffer.from(pkcs8).toString("base64url"),
      portalKeys: id.portalKeys,
      ...(id.pinnedKeySet ? { pinnedKeySet: id.pinnedKeySet } : {}),
      enrolCodeDigest: id.enrolCodeDigest,
      configPath: id.configPath,
      ackPath: id.ackPath,
    };
    // the WHOLE record is sealed (portalKeys = trust anchor, workspaceId, enrolCodeDigest included)
    this.writeRecord("identity", f);
  }

  /**
   * C63a: digest of an enrolment code whose re-enrolment was refused by the key-set rule. S1 stays unchanged, so
   * without this record every restart would try the same (now used) code again.
   */
  loadRefusedEnrolCode(): Sha256Digest | undefined {
    return this.readRecord<{ digest: Sha256Digest }>("enrol-refused")?.digest;
  }

  saveRefusedEnrolCode(digest: Sha256Digest): void {
    this.writeRecord("enrol-refused", { digest });
  }

  loadConfigJws(): string | undefined {
    const p = this.path("config.jws");
    return existsSync(p) ? readFileSync(p, "utf8").trim() : undefined;
  }

  saveConfigJws(jws: string): void {
    atomicWrite(this.path("config.jws"), jws);
  }

  saveConnections(): void {
    this.writeRecord("connections", [...this.connections.values()]);
  }

  saveClaims(): void {
    this.writeRecord("claims", this.claims);
  }

  private saveJtis(): void {
    this.writeRecord("jtis", Object.fromEntries(this.usedJtis));
  }

  saveKeyStore(): void {
    this.writeRecord("keys", this.keyStore);
  }

  saveStandalone(): void {
    if (this.standalone) this.writeRecord("standalone", this.standalone);
  }

  saveReports(): void {
    this.writeRecord("reports", this.reports);
  }

  /** One-time use of a jti (pairing code, keys ticket). Returns false when already used. */
  useJti(jti: string, exp: number): boolean {
    const now = nowS();
    for (const [k, e] of this.usedJtis) if (e <= now) this.usedJtis.delete(k);
    if (this.usedJtis.has(jti)) return false;
    this.usedJtis.set(jti, exp + 30);
    this.saveJtis();
    return true;
  }

  /**
   * Sets or deletes one key: a requirement name, or {@link providerKeyName} of an owner-named provider key. Deleting a
   * key that bindings use leaves those bindings without a key (BRIDGE §15.2) in the same revision: one `keysRev` bump for
   * the whole change.
   */
  setKey(name: string, value: string | null): void {
    if (value === null) delete this.keyStore.values[name];
    else this.keyStore.values[name] = value;
    const served = value === null && this.bindings.some((b) => b.keyName === name);
    if (served)
      this.saveBindings(
        this.bindings.map((b) => {
          if (b.keyName !== name) return b;
          const { keyName: _k, ...unset } = b;
          return unset;
        }),
      );
    else this.bumpKeys();
  }

  /** Replaces the S11 bindings (BRIDGE §15.1); bumps `keysRev` once. */
  saveBindings(next: ModelBinding[]): void {
    this.saveModels(next, this.ownHosts);
  }

  /** Replaces the S11 "Own hosts" list (§15.3): it changes which bindings count as `local`, so it bumps `keysRev` once. */
  saveOwnHosts(next: string[]): void {
    this.saveModels(this.bindings, next);
  }

  private saveModels(bindings: ModelBinding[], ownHosts: string[]): void {
    const rev = this.keyStore.keysRev + 1;
    this.writeRecord("models", { rev, bindings, ...(ownHosts.length ? { ownHosts } : {}) } satisfies ModelsRecord);
    this.bindings = bindings;
    this.ownHosts = ownHosts;
    this.keyStore.keysRev = rev;
    this.saveKeyStore();
  }

  private bumpKeys(): void {
    this.keyStore.keysRev += 1;
    this.saveKeyStore();
  }
}

/** Reads TB_KEK / TB_KEK_PREVIOUS through the manifest package (one encoding rule, C35). */
export function keksFromEnv(env: NodeJS.ProcessEnv, api: ManifestApi): { current: Kek; previous?: Kek } {
  if (!env.TB_KEK) throw new BridgeError("kek_missing", 500, "TB_KEK is not set");
  const current = api.kekFromEnv(env.TB_KEK);
  return env.TB_KEK_PREVIOUS ? { current, previous: api.kekFromEnv(env.TB_KEK_PREVIOUS) } : { current };
}
