/**
 * App events (BRIDGE §14, MANIFEST §16; spec 0.1.57, C274c/C274d): ingest (`POST /tb/v1/events`, internal.ts), one log per
 * agent, and the delivery reads behind `tealbrick/events/{list,poll,stream}` (mcp.ts).
 *
 * Storage: Node's built-in `node:sqlite` (no npm dependency), one file next to the bridge state (`<TB_DATA_DIR>/bridge/events.db`).
 * The log is not sealed like the S-records: a row never grants anything by itself, because every delivery re-checks MANIFEST
 * §16.2 rules 1, 5 and 6 against the current (signed) table. Cached manifests are content-addressed: one is used only when its
 * digest equals a digest the signed config names.
 *
 * Rules shared with the SDK (the declaration lookup, the scope type of an event, the payload check, the grant rule, the limits)
 * come from `@opt2-tealbrick/manifest` (L1); nothing here re-implements them. The visibility rule is the tools/list rule
 * (`opVisibleToGrant`, through `eventVisibleToGrant`), with the per-entry authority of `eligible` for scoped events.
 */
import { existsSync, renameSync } from "node:fs";
import { DatabaseSync, type SQLInputValue, type StatementSync } from "node:sqlite";
import {
  EVENT_BATCH_MAX,
  EVENT_ELIGIBLE_MAX,
  EVENT_INSTANCE_ID_MAX,
  EVENT_ITEM_MAX_BYTES,
  EVENT_KEY_RE,
  EVENT_SUBJECT_ID_MAX,
  EVENT_SUBJECT_KIND_RE,
  EVENT_SUMMARY_MAX,
  EVENT_TO_MAX,
  EVENT_WINDOW_MS,
  eventDecl,
  eventScopeType,
  eventVisibleToGrant,
  isReservedEventName,
  type ResolvedEventDecl,
  ulid,
  validateEventPayload,
  withStandardOps,
} from "@opt2-tealbrick/manifest";
import { type AgentEvent, type EventIngestResult, type EventRefuseCode, type EventsListResult, type EventsPollResult, type EventsStreamResult, PLATFORM_EVENTS } from "@opt2-tealbrick/spec/bridge";
import type { AgentId, GrantClaims, InstanceId } from "@opt2-tealbrick/spec/credentials";
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import type { OperationView } from "@opt2-tealbrick/spec/sdk";
import { type AppRuntime, acceptedDigests, agtRef, grantKey, insRef, type Table } from "./table.ts";
import type { Logger } from "./util.ts";

/** Retention per agent (C274d ruling 3): 10 000 rows or 7 days from ingest, whichever comes first. */
export const EVENT_RETENTION_ROWS = 10_000;
export const EVENT_RETENTION_MS = EVENT_WINDOW_MS;
/** `tealbrick/events/poll` limit (BRIDGE §14.3): 1..100, default 50. */
export const EVENT_POLL_LIMIT = { min: 1, max: 100, default: 50 } as const;
/**
 * BRIDGE §14.1 fan-out limit (C274f): stored recipient rows per app instance, a token bucket of 6 000 rows per minute with a
 * burst of 30 000. A batch that would exceed it is refused as a whole before anything of it is stored: 429 + Retry-After (the
 * SDK retries the same keys), or 413 when the batch alone needs more than the burst (the SDK halves the batch).
 */
export const EVENT_FANOUT_LIMIT = { perMinute: 6_000, burst: 30_000 } as const;

/** A whole-request refusal from the ingest step (the transaction is rolled back; nothing of the batch is stored). */
export class EventIngestLimit extends Error {
  readonly status: 413 | 429;
  readonly retryAfterS: number;
  constructor(status: 413 | 429, retryAfterS: number, message: string) {
    super(message);
    this.status = status;
    this.retryAfterS = retryAfterS;
  }
}

/** How often the age rule and the dedupe window are applied to agents nobody reads (ms). */
const SWEEP_MS = 60_000;
const ULID_RE = /^[0-9A-HJKMNP-TV-Z]{26}$/;
const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const SCHEMA_VERSION = "1";

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
export const isEventCursor = (v: string): boolean => ULID_RE.test(v);

/** The next ULID after `id` in sort order (the random part + 1). A ULID that is all `Z` has no successor. */
export function ulidAfter(id: string): string {
  const chars = id.split("");
  for (let i = chars.length - 1; i >= 0; i--) {
    const v = CROCKFORD.indexOf(chars[i] as string);
    if (v < 31) {
      chars[i] = CROCKFORD[v + 1] as string;
      return chars.join("");
    }
    chars[i] = "0";
  }
  throw new RangeError("ulid space exhausted");
}

/** The world the store reads at a decision: the current table and the knowledge of what each instance's release declares. */
interface Resolved {
  manifest: Manifest;
  digest: string;
}

/** What a stored row records (BRIDGE §14.2): who, which app instance, the declaration it was checked against, its state. */
interface RowRecord {
  id: string;
  origin: string;
  agent: string;
  ins: string;
  product: string;
  type: string;
  instance_id: string | null;
  digest: string;
  op: string;
  scope_type: string | null;
  authority: string | null;
  envelope: string;
  ingest_at: number;
  held: number;
}

type Verdict = { kind: "deliver"; event: AgentEvent } | { kind: "drop" } | { kind: "hold" };
type ItemResult = EventIngestResult["results"][number];

/** Whether an enabled before/after hook (or a declared one missing from the config, fail closed) matches the op (rule 6). */
export type HookMatch = (t: Table, app: AppRuntime, op: OperationView) => boolean;

export interface EventStoreOptions {
  path: string;
  log: Logger;
  /** the manifest digest rule (manifest `manifestDigest`, via the ManifestApi binding) */
  digestOf: (m: Manifest) => string;
  /** rule 6 (calls.ts `eventHookMatches`) */
  hookMatches: HookMatch;
  /** test clock (ms) */
  now?: () => number;
  /** told when the store turns unhealthy or recovers (the status report re-states the caps) */
  onHealth?: (healthy: boolean) => void;
}

/**
 * The per-agent event log. Every method is synchronous (node:sqlite), so one ingest batch, one delivery page and one table
 * change each run as one step: a re-id applied with a resume is done before any later ingest is read (BRIDGE §14.2).
 */
export class EventStore {
  readonly #db: DatabaseSync;
  readonly #log: Logger;
  readonly #digestOf: (m: Manifest) => string;
  readonly #hookMatches: HookMatch;
  now: () => number;
  /** the highest id issued (ids are strictly increasing per bridge, across restarts) */
  #lastId: string;
  /** rows per agent (a cache; dropped on bulk deletes) */
  readonly #counts = new Map<string, number>();
  /** content-addressed manifests (digest → manifest) of the releases the config names */
  readonly #manifests = new Map<string, Manifest>();
  readonly #stmt: Record<string, StatementSync> = {};
  readonly #sweep: NodeJS.Timeout;
  #closed = false;
  #healthy = true;
  readonly #onHealth: ((healthy: boolean) => void) | undefined;
  /** stored recipient rows per app instance (BRIDGE §14.1 fan-out limit): tokens and the time they were counted */
  readonly #fanout = new Map<string, { tokens: number; at: number }>();

  constructor(o: EventStoreOptions) {
    this.#log = o.log;
    this.#digestOf = o.digestOf;
    this.#hookMatches = o.hookMatches;
    this.#onHealth = o.onHealth;
    this.now = o.now ?? Date.now;
    const opened = openDatabase(o.path, o.log, this.now);
    this.#db = opened.db;
    this.#lastId = opened.lastId;
    this.#sweep = setInterval(() => this.sweep(), SWEEP_MS);
    this.#sweep.unref();
  }

  #s(sql: string): StatementSync {
    let st = this.#stmt[sql];
    if (!st) {
      st = this.#db.prepare(sql);
      this.#stmt[sql] = st;
    }
    return st;
  }

  /**
   * One write transaction. On any failure it rolls back and drops the row-count cache (a failed batch must not leave counts
   * that cause false retention deletes). A database failure (not an ingest limit) marks the store unhealthy until a probe
   * (the 60 s sweep) succeeds: while unhealthy the bridge does not declare `events`, ingest answers 503 and the methods -32601.
   */
  #tx<T>(fn: () => T): T {
    try {
      this.#db.exec("BEGIN IMMEDIATE");
    } catch (e) {
      this.#failed(e);
      throw e;
    }
    try {
      const out = fn();
      this.#s("INSERT INTO meta (k, v) VALUES ('last_id', ?) ON CONFLICT (k) DO UPDATE SET v = excluded.v").run(this.#lastId);
      this.#db.exec("COMMIT");
      return out;
    } catch (e) {
      this.#counts.clear();
      try {
        this.#db.exec("ROLLBACK");
      } catch {
        /* the transaction is already gone */
      }
      if (!(e instanceof EventIngestLimit)) this.#failed(e);
      throw e;
    }
  }

  #failed(e: unknown): void {
    if (!this.#healthy) return;
    this.#log.error("bridge.events.db_failed", { code: e instanceof Error ? e.message.slice(0, 120) : "error" });
    this.#healthy = false;
    this.#onHealth?.(false);
  }

  /** false after a database failure, until a probe succeeds (caps.ts drops `events` meanwhile) */
  get healthy(): boolean {
    return this.#healthy && !this.#closed;
  }

  /** A small write transaction; success makes the store healthy again. */
  probe(): boolean {
    try {
      this.#db.exec("BEGIN IMMEDIATE");
      this.#db.prepare("INSERT INTO meta (k, v) VALUES ('probe', ?) ON CONFLICT (k) DO UPDATE SET v = excluded.v").run(String(this.now()));
      this.#db.exec("COMMIT");
      if (!this.#healthy) {
        this.#log.info("bridge.events.db_recovered", {});
        this.#healthy = true;
        this.#onHealth?.(true);
      }
    } catch (e) {
      try {
        this.#db.exec("ROLLBACK");
      } catch {
        /* none open */
      }
      this.#failed(e);
    }
    return this.#healthy;
  }

  /** A new row id: a ULID, strictly greater than every id this bridge issued before (also after a clock step back). */
  #nextId(): string {
    let id: string = ulid(this.now());
    if (id <= this.#lastId) id = ulidAfter(this.#lastId);
    this.#lastId = id;
    return id;
  }

  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    clearInterval(this.#sweep);
    this.#db.close();
  }

  // ── manifests: the serving release and, during a G2b attempt, the candidate ─────────────────────────────────────────────

  /** Remembers the manifest of the release that runs (content-addressed) and forgets digests the config no longer names. */
  #rememberManifests(t: Table): void {
    const named = new Set<string>();
    for (const a of t.apps.values()) for (const d of acceptedDigests(a.entry)) named.add(d);
    for (const a of t.apps.values()) if (a.manifest && a.digest) this.remember(a.digest, a.manifest);
    for (const d of [...this.#manifests.keys()]) if (!named.has(d)) this.#manifests.delete(d);
    const rows = this.#s("SELECT digest FROM manifests").all() as { digest: string }[];
    for (const r of rows) if (!named.has(r.digest)) this.#s("DELETE FROM manifests WHERE digest = ?").run(r.digest);
  }

  /** Stores a manifest under its digest; one whose digest is not `digest` is ignored. */
  remember(digest: string, m: Manifest): void {
    if (this.#manifests.has(digest)) return;
    if (this.#digestOf(m) !== digest) return;
    this.#manifests.set(digest, m);
    try {
      this.#s("INSERT INTO manifests (digest, json) VALUES (?, ?) ON CONFLICT (digest) DO NOTHING").run(digest, JSON.stringify(m));
    } catch (e) {
      this.#failed(e); // kept in memory only (a restart fetches it again)
    }
  }

  #manifestBy(app: AppRuntime, digest: string | undefined): Resolved | undefined {
    if (!digest) return undefined;
    if (app.manifest && app.digest === digest) return { manifest: app.manifest, digest };
    const mem = this.#manifests.get(digest);
    if (mem) return { manifest: mem, digest };
    let row: { json: string } | undefined;
    try {
      row = this.#s("SELECT json FROM manifests WHERE digest = ?").get(digest) as { json: string } | undefined;
    } catch (e) {
      this.#failed(e);
      return undefined;
    }
    if (!row) return undefined;
    try {
      const m = JSON.parse(row.json) as Manifest;
      // content-addressed: a row whose bytes do not hash to its digest is not used
      if (this.#digestOf(m) !== digest) return undefined;
      this.#manifests.set(digest, m);
      return { manifest: m, digest };
    } catch {
      return undefined;
    }
  }

  /** The SERVING release's manifest (`apps[].manifestDigest`), whether or not it is the one that runs. */
  serving(app: AppRuntime): Resolved | undefined {
    return this.#manifestBy(app, app.entry.manifestDigest);
  }

  /** The update candidate's manifest while a G2b attempt runs (`candidateManifestDigest`). */
  candidate(app: AppRuntime): Resolved | undefined {
    const acc = acceptedDigests(app.entry);
    return acc.length > 1 ? this.#manifestBy(app, acc[1]) : undefined;
  }

  // ── ingest (BRIDGE §14.1) ───────────────────────────────────────────────────────────────────────────────────────────────

  /**
   * What the declaration step needs before a batch runs: the serving manifest, and the candidate's when an app name is not
   * in the serving one while a G2b attempt runs. `missing` = a manifest the batch needs that this bridge does not hold.
   */
  needs(app: AppRuntime, items: unknown[]): { missing: "serving" | "candidate" | null } {
    const serving = this.serving(app);
    if (!serving) return { missing: "serving" };
    if (acceptedDigests(app.entry).length < 2 || this.candidate(app)) return { missing: null };
    for (const it of items) {
      if (!isObj(it) || it.kind !== "emit" || typeof it.name !== "string" || isReservedEventName(it.name)) continue;
      if (!eventDecl(serving.manifest, it.name)) return { missing: "candidate" };
    }
    return { missing: null };
  }

  /**
   * One batch from the app instance `app` (its assertion verified), IN ORDER, in one transaction. Returns one result per item
   * and the agents that got a row (the live stream is told after the commit).
   */
  ingest(t: Table, app: AppRuntime, items: unknown[]): { result: EventIngestResult; agents: Set<string> } {
    const agents = new Set<string>();
    const ins = app.entry.ins;
    const budget = { available: this.#fanoutAvailable(ins), stored: 0 };
    const results = this.#tx(() => items.slice(0, EVENT_BATCH_MAX).map((it) => this.#item(t, app, it, agents, budget)));
    // committed: the stored rows are taken from the instance's bucket
    const b = this.#fanout.get(ins);
    if (b) b.tokens -= budget.stored;
    return { result: { results }, agents };
  }

  /** Tokens of the per-instance stored-row bucket now (refilled since the last count). */
  #fanoutAvailable(ins: string): number {
    const now = this.now();
    const b = this.#fanout.get(ins) ?? { tokens: EVENT_FANOUT_LIMIT.burst, at: now };
    b.tokens = Math.min(EVENT_FANOUT_LIMIT.burst, b.tokens + (Math.max(0, now - b.at) / 60_000) * EVENT_FANOUT_LIMIT.perMinute);
    b.at = now;
    this.#fanout.set(ins, b);
    return b.tokens;
  }

  #item(t: Table, app: AppRuntime, it: unknown, agents: Set<string>, budget: { available: number; stored: number }): ItemResult {
    const key = isObj(it) && typeof it.key === "string" ? it.key : "";
    const refuse = (code: EventRefuseCode): ItemResult => ({ key, status: "refused", code });
    if (!isObj(it)) return refuse("event_payload_invalid");
    const ins = app.entry.ins;
    if (it.kind === "purge") {
      const agent = it.agent;
      const instanceId = it.instanceId;
      if (!EVENT_KEY_RE.test(key) || typeof instanceId !== "string" || instanceId.length < 1 || instanceId.length > EVENT_INSTANCE_ID_MAX || (agent !== undefined && typeof agent !== "string")) return refuse("event_payload_invalid");
      // specs#33: purge keys are deduped like emit keys, so a retried batch never applies a purge twice
      if (this.#seen(ins, key)) return { key, status: "duplicate" };
      this.purge(ins, instanceId, typeof agent === "string" ? agent : null);
      return { key, status: "stored" };
    }
    if (it.kind !== "emit") return refuse("event_payload_invalid");
    const product = app.entry.product;
    const serving = this.serving(app);
    if (!serving) return refuse("event_undeclared"); // not reached: the caller answers 503 first (needs())

    // 1. the declaration
    const name = it.name;
    if (typeof name !== "string") return refuse("event_undeclared");
    if (product === "tb") return refuse("event_reserved");
    let decl: ResolvedEventDecl | null = null;
    let declared: Resolved = serving;
    if (isReservedEventName(name)) {
      if (!Object.hasOwn(PLATFORM_EVENTS, name)) return refuse("event_reserved");
      decl = eventDecl(serving.manifest, name);
    } else {
      decl = eventDecl(serving.manifest, name);
      if (!decl) {
        const cand = this.candidate(app);
        const d = cand ? eventDecl(cand.manifest, name) : null;
        if (cand && d) {
          decl = d;
          declared = cand;
        }
      }
    }
    if (!decl) return refuse("event_undeclared");

    // 2. shape and size
    if (!EVENT_KEY_RE.test(key)) return refuse("event_payload_invalid");
    const s = it.subject;
    if (!isObj(s) || typeof s.kind !== "string" || !EVENT_SUBJECT_KIND_RE.test(s.kind) || typeof s.id !== "string" || s.id.length < 1 || s.id.length > EVENT_SUBJECT_ID_MAX) return refuse("event_payload_invalid");
    if (typeof it.at !== "string" || it.at.length < 1 || it.at.length > 64) return refuse("event_payload_invalid");
    if (it.summary !== undefined && typeof it.summary !== "string") return refuse("event_payload_invalid");
    if (it.untrusted !== undefined && it.untrusted !== true) return refuse("event_payload_invalid");
    if (it.causedBy !== undefined && typeof it.causedBy !== "string") return refuse("event_payload_invalid");
    if (typeof it.summary === "string" && it.summary.length > EVENT_SUMMARY_MAX) return refuse("event_too_large");
    const { eligible: _eligible, ...sized } = it;
    if (Buffer.byteLength(JSON.stringify(sized)) > EVENT_ITEM_MAX_BYTES) return refuse("event_too_large");
    const payload = validateEventPayload(decl, it.data);
    if (!payload.ok) return refuse(payload.code);

    // 3. scoped ⇔ instanceId and eligible
    const scopeType = eventScopeType(declared.manifest, decl);
    const hasInstance = typeof it.instanceId === "string" && it.instanceId.length >= 1 && it.instanceId.length <= EVENT_INSTANCE_ID_MAX;
    if (scopeType !== null ? !hasInstance || !Array.isArray(it.eligible) : it.instanceId !== undefined || it.eligible !== undefined) return refuse("event_instance_invalid");

    // 4. audience: target ⇔ to (1..100 agents)
    const to = it.to;
    const toOk = Array.isArray(to) && to.length >= 1 && to.length <= EVENT_TO_MAX && to.every((a) => typeof a === "string");
    if (decl.audience === "target" ? !toOk : to !== undefined) return refuse("event_target_invalid");

    // 5. eligible ≤ 500 well-formed entries; then (app instance, key) seen within 7 days → duplicate
    const eligible = new Map<string, "owner" | "bounded">();
    if (Array.isArray(it.eligible)) {
      if (it.eligible.length > EVENT_ELIGIBLE_MAX) return refuse("event_payload_invalid");
      for (const e of it.eligible) {
        if (!isObj(e) || typeof e.agent !== "string" || (e.authority !== "owner" && e.authority !== "bounded")) return refuse("event_payload_invalid");
        // the same agent twice: the narrower authority wins (fail closed)
        eligible.set(e.agent, eligible.get(e.agent) === "bounded" ? "bounded" : e.authority);
      }
    }
    if (this.#seen(ins, key)) return { key, status: "duplicate" };

    // fan-out at write time (MANIFEST §16.2 rules 1–4), with the declaration of step 1
    const causedBy = typeof it.causedBy === "string" ? it.causedBy : undefined;
    const envelope: Omit<AgentEvent, "id" | "origin"> = {
      type: decl.platform ? name : `${product}.${name}`,
      app: product as AgentEvent["app"],
      ...(scopeType !== null ? { instanceId: it.instanceId as string } : {}),
      at: it.at as AgentEvent["at"],
      subject: { kind: s.kind, id: s.id },
      ...(typeof it.summary === "string" ? { summary: it.summary } : {}),
      ...(it.untrusted === true ? { untrusted: true as const } : {}),
      data: it.data as AgentEvent["data"],
      ...(causedBy ? { causedBy: causedBy as AgentId } : {}),
    };
    const json = JSON.stringify(envelope);
    const candidates = decl.audience === "target" ? [...new Set(to as string[])] : grantees(t, ins);
    // an op the serving manifest lacks (a candidate-only declaration) waits for the attempt: the row is held
    const opServing = withStandardOps(serving.manifest).some((o) => o.id === decl.visibleWith);
    const held = t.pausedInstances.has(ins) || !opServing ? 1 : 0;
    const now = this.now();
    // rule 1 once per distinct grant shape: the same shared function (eventVisibleToGrant) on the declaring manifest reduced
    // to the visibleWith op (its standard ops and declared scope types stay), so a 500-agent fan-out does not rebuild the op list
    const declOp = declared.manifest.operations.find((o) => o.id === decl.visibleWith);
    const reduced = { ...declared.manifest, operations: declOp ? [declOp] : [] } as Manifest;
    const visible = new Map<string, boolean>();
    const rule1 = (claims: GrantClaims, authority: "owner" | "bounded" | null): boolean => {
      const k = `${claims.mode}|${[...claims.wf].sort().join(",")}|${[...claims.crud].sort().join(",")}|${authority}`;
      let v = visible.get(k);
      if (v === undefined) {
        v = eventVisibleToGrant(reduced, decl, claims, authority);
        visible.set(k, v);
      }
      return v;
    };
    let recipients = 0;
    for (const agent of candidates) {
      if (agent === causedBy) continue; // rule 3
      if (!t.agents.has(agent as AgentId)) continue;
      const authority = scopeType !== null ? (eligible.get(agent) ?? null) : null;
      if (scopeType !== null && authority === null) continue; // rule 2: never outside `eligible`
      const claims = validGrant(t, agent, ins, now);
      if (!claims || !rule1(claims, authority)) continue; // rule 1
      // the per-instance stored-row limit: the whole batch is refused (rolled back) before anything of it is stored
      budget.stored += 1;
      if (budget.stored > EVENT_FANOUT_LIMIT.burst) throw new EventIngestLimit(413, 0, "the batch fans out to more rows than this instance may store at once; send smaller batches");
      if (budget.stored > budget.available) throw new EventIngestLimit(429, Math.max(1, Math.ceil(((budget.stored - budget.available) / EVENT_FANOUT_LIMIT.perMinute) * 60)), "this instance stored too many event rows; retry later");
      const before = this.#count(agent);
      const id = this.#nextId();
      this.#s(
        "INSERT INTO rows (id, origin, agent, ins, product, type, instance_id, digest, op, scope_type, authority, envelope, ingest_at, held) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      ).run(id, id, agent, ins, product, envelope.type, scopeType !== null ? (it.instanceId as string) : null, declared.digest, decl.visibleWith, scopeType, authority, json, now, held);
      recipients++;
      agents.add(agent);
      const n = before + 1;
      this.#counts.set(agent, n);
      if (n > EVENT_RETENTION_ROWS) this.#retain(agent, now);
    }
    return { key, status: "stored", recipients };
  }

  /** (app instance, key) seen in the last 7 days (emit and purge keys alike); records it otherwise. */
  #seen(ins: string, key: string): boolean {
    const now = this.now();
    const row = this.#s("SELECT at FROM keys WHERE ins = ? AND key = ?").get(ins, key) as { at: number } | undefined;
    if (row && row.at >= now - EVENT_WINDOW_MS) return true;
    this.#s("INSERT INTO keys (ins, key, at) VALUES (?, ?, ?) ON CONFLICT (ins, key) DO UPDATE SET at = excluded.at").run(ins, key, now);
    return false;
  }

  /** Deletes the stored rows of (agent | every agent, app instance, instanceId), delivered or not. */
  purge(ins: string, instanceId: string, agent: string | null): number {
    const r = agent === null ? this.#s("DELETE FROM rows WHERE ins = ? AND instance_id = ?").run(ins, instanceId) : this.#s("DELETE FROM rows WHERE ins = ? AND instance_id = ? AND agent = ?").run(ins, instanceId, agent);
    if (agent === null) this.#counts.clear();
    else this.#counts.delete(agent);
    return Number(r.changes);
  }

  #count(agent: string): number {
    const c = this.#counts.get(agent);
    if (c !== undefined) return c;
    const n = (this.#s("SELECT count(*) AS n FROM rows WHERE agent = ?").get(agent) as { n: number }).n;
    this.#counts.set(agent, n);
    return n;
  }

  /**
   * Retention (BRIDGE §14.2, C274d ruling 3): rows older than 7 days from INGEST, then the oldest by ingest beyond 10 000 rows.
   * Records `droppedThrough` (the highest id removed by retention) and, when a HELD row went, the per-agent truncation flag.
   */
  #retain(agent: string, now: number): void {
    const cutoff = now - EVENT_RETENTION_MS;
    const aged = this.#s("SELECT id, held FROM rows WHERE agent = ? AND ingest_at < ?").all(agent, cutoff) as { id: string; held: number }[];
    const over = this.#count(agent) - aged.length - EVENT_RETENTION_ROWS;
    const excess = over > 0 ? (this.#s("SELECT id, held FROM rows WHERE agent = ? AND ingest_at >= ? ORDER BY ingest_at, origin LIMIT ?").all(agent, cutoff, over) as { id: string; held: number }[]) : [];
    const drop = [...aged, ...excess];
    if (drop.length === 0) return;
    let hi = "";
    let heldGone = 0;
    for (const r of drop) {
      this.#s("DELETE FROM rows WHERE id = ?").run(r.id);
      if (r.id > hi) hi = r.id;
      if (r.held === 1) heldGone = 1;
    }
    this.#s(
      "INSERT INTO agents (agent, dropped_through, held_dropped) VALUES (?, ?, ?) ON CONFLICT (agent) DO UPDATE SET dropped_through = max(coalesce(dropped_through, ''), excluded.dropped_through), held_dropped = max(held_dropped, excluded.held_dropped)",
    ).run(agent, hi, heldGone);
    this.#counts.set(agent, this.#count(agent) - drop.length);
  }

  /** The age rule and the dedupe window for every agent (also those nobody reads). */
  sweep(): void {
    if (this.#closed) return;
    if (!this.#healthy && !this.probe()) return;
    try {
      const now = this.now();
      this.#tx(() => {
        const old = this.#s("SELECT DISTINCT agent FROM rows WHERE ingest_at < ?").all(now - EVENT_RETENTION_MS) as { agent: string }[];
        for (const r of old) this.#retain(r.agent, now);
        this.#s("DELETE FROM keys WHERE at < ?").run(now - EVENT_WINDOW_MS);
      });
    } catch (e) {
      this.#log.warn("bridge.events.sweep_failed", { code: e instanceof Error ? e.message.slice(0, 120) : "error" });
    }
  }

  // ── held rows: instance pause and G2b attempt (BRIDGE §14.2) ────────────────────────────────────────────────────────────

  /**
   * A new table (or a manifest that became known). Held rows whose reason is gone get NEW ids, in old-id order, in this one
   * synchronous step (before any later ingest from that instance is read); `origin` stays. A held row whose op is missing from
   * the serving manifest once no attempt runs (rollback), or whose instance left the config, is dropped.
   */
  onTable(t: Table): { released: number; dropped: number } {
    try {
      return this.#onTable(t);
    } catch (e) {
      // never takes the config apply down: logged, the store marked unhealthy, held rows are retried on the next table
      this.#failed(e);
      return { released: 0, dropped: 0 };
    }
  }

  #onTable(t: Table): { released: number; dropped: number } {
    this.#tx(() => this.#rememberManifests(t));
    const held = this.#s("SELECT id, agent, ins, op FROM rows WHERE held = 1 ORDER BY id").all() as { id: string; agent: string; ins: string; op: string }[];
    if (held.length === 0) return { released: 0, dropped: 0 };
    let released = 0;
    let dropped = 0;
    this.#tx(() => {
      for (const r of held) {
        const app = t.apps.get(r.ins as InstanceId);
        if (!app) {
          this.#s("DELETE FROM rows WHERE id = ?").run(r.id);
          this.#counts.delete(r.agent);
          dropped++;
          continue;
        }
        if (t.pausedInstances.has(app.entry.ins)) continue;
        const serving = this.serving(app);
        if (!serving) continue; // not decidable yet: stays held until the manifest is known
        if (!withStandardOps(serving.manifest).some((o) => o.id === r.op)) {
          if (acceptedDigests(app.entry).length > 1) continue; // the candidate may still become serving
          this.#s("DELETE FROM rows WHERE id = ?").run(r.id);
          this.#counts.delete(r.agent);
          dropped++;
          continue;
        }
        this.#s("UPDATE rows SET id = ?, held = 0 WHERE id = ?").run(this.#nextId(), r.id);
        released++;
      }
    });
    if (released || dropped) this.#log.info("bridge.events.released", { released, dropped });
    return { released, dropped };
  }

  // ── delivery (BRIDGE §14.3) ─────────────────────────────────────────────────────────────────────────────────────────────

  /** Rules 1, 5 and 6 at delivery against the current table and the CURRENT serving manifest. */
  #verdict(t: Table, r: RowRecord, now: number, memo: Map<string, unknown>): Verdict {
    const app = t.apps.get(r.ins as InstanceId);
    if (!app) return { kind: "drop" };
    if (t.pausedInstances.has(app.entry.ins)) return { kind: "hold" }; // rule 5
    const serving = this.serving(app);
    if (!serving) return { kind: "hold" }; // the serving release is not known to this bridge yet: nothing is decided
    // per page: the op lookup and the rule-1 answer per (manifest, op, grant shape, authority) are computed once
    const opKey = `op|${serving.digest}|${r.op}`;
    if (!memo.has(opKey)) memo.set(opKey, withStandardOps(serving.manifest).find((o) => o.id === r.op) ?? null);
    const op = memo.get(opKey) as OperationView | null;
    if (!op) return acceptedDigests(app.entry).length > 1 ? { kind: "hold" } : { kind: "drop" };
    const scopeType = op.standard ? null : (op.scopeType ?? null);
    if (scopeType !== r.scope_type) return { kind: "drop" };
    const claims = validGrant(t, r.agent, r.ins, now);
    if (!t.agents.has(r.agent as AgentId) || !claims) return { kind: "drop" };
    const authority = r.authority === "owner" || r.authority === "bounded" ? r.authority : null;
    const visKey = `vis|${serving.digest}|${r.op}|${claims.mode}|${[...claims.wf].sort().join(",")}|${[...claims.crud].sort().join(",")}|${authority}`;
    if (!memo.has(visKey)) memo.set(visKey, eventVisibleToGrant(serving.manifest, { visibleWith: r.op as never }, claims, authority));
    if (memo.get(visKey) !== true) return { kind: "drop" };
    const { summary, ...rest } = JSON.parse(r.envelope) as Omit<AgentEvent, "id" | "origin">;
    const hookKey = `hook|${r.ins}|${r.op}`;
    if (summary !== undefined && !memo.has(hookKey)) memo.set(hookKey, this.#hookMatches(t, app, op));
    const strip = summary !== undefined && memo.get(hookKey) === true; // rule 6
    return { kind: "deliver", event: { id: r.id as AgentEvent["id"], origin: r.origin as AgentEvent["origin"], ...rest, ...(summary !== undefined && !strip ? { summary } : {}) } };
  }

  /**
   * Up to `limit` deliverable events of `agent` with id > `after` (null = from the oldest kept), in id order. Rows that fail the
   * re-check are dropped; rows of a paused instance (or waiting on a G2b attempt) are marked held. The caller has checked the
   * agent and workspace pause.
   */
  page(t: Table, agent: string, after: string | null, limit: number): AgentEvent[] {
    const out: AgentEvent[] = [];
    const now = this.now();
    const memo = new Map<string, unknown>();
    let from = after ?? "";
    this.#tx(() => {
      for (;;) {
        const want = limit - out.length;
        const batch = this.#s("SELECT * FROM rows WHERE agent = ? AND held = 0 AND id > ? ORDER BY id LIMIT ?").all(agent, from, Math.max(want, 50)) as unknown as RowRecord[];
        for (const r of batch) {
          from = r.id;
          const v = this.#verdict(t, r, now, memo);
          if (v.kind === "drop") {
            this.#s("DELETE FROM rows WHERE id = ?").run(r.id);
            this.#counts.delete(agent);
          } else if (v.kind === "hold") this.#s("UPDATE rows SET held = 1 WHERE id = ?").run(r.id);
          else {
            out.push(v.event);
            if (out.length >= limit) return;
          }
        }
        if (batch.length < Math.max(want, 50)) return;
      }
    });
    return out;
  }

  /** `truncated` (BRIDGE §14.3) for a poll or stream call; answering it clears the held-row flag. Applies retention first. */
  #truncated(agent: string, cursor: string | null): boolean {
    const now = this.now();
    return this.#tx(() => {
      this.#retain(agent, now);
      const a = this.#s("SELECT dropped_through, held_dropped FROM agents WHERE agent = ?").get(agent) as { dropped_through: string | null; held_dropped: number } | undefined;
      if (!a) return false;
      if (a.held_dropped === 1) {
        this.#s("UPDATE agents SET held_dropped = 0 WHERE agent = ?").run(agent);
        return true;
      }
      const d = a.dropped_through || null;
      return d !== null && (cursor === null || cursor < d);
    });
  }

  /** `tealbrick/events/poll`. `agentPaused` = the agent or the workspace is paused. */
  poll(t: Table, agent: string, cursor: string | null, limit: number, agentPaused: boolean): EventsPollResult {
    if (agentPaused) return { events: [], cursor, truncated: false, paused: true };
    const truncated = this.#truncated(agent, cursor);
    const events = this.page(t, agent, cursor, limit);
    return { events, cursor: events.at(-1)?.id ?? cursor, truncated };
  }

  /** `tealbrick/events/stream`: the start position and `truncated` (frames: {@link page} from mcp.ts). */
  stream(agent: string, cursor: string | null, agentPaused: boolean): EventsStreamResult {
    if (agentPaused) return { cursor, truncated: false, paused: true };
    return { cursor, truncated: this.#truncated(agent, cursor) };
  }

  /** `tealbrick/events/list`: the types this agent can receive now (rule 1; scoped types without the per-instance part). */
  list(t: Table, agent: string): EventsListResult {
    const types: EventsListResult["types"] = [];
    if (!t.agents.has(agent as AgentId)) return { types };
    const now = this.now();
    const prefix = `${agtRef(agent as AgentId)}|`;
    const keys = [...t.grants.keys()].filter((k) => k.startsWith(prefix)).sort();
    for (const k of keys) {
      const ins = (t.grants.get(k)?.claims.aud ?? "").slice(7);
      const app = t.apps.get(ins as InstanceId);
      const claims = validGrant(t, agent, ins, now);
      const serving = app ? this.serving(app) : undefined;
      // as tools/list: a paused or down instance lists nothing now
      if (!app || app.down || t.pausedInstances.has(app.entry.ins) || !claims || !serving) continue;
      const m = serving.manifest;
      for (const d of m.events ?? []) {
        const scoped = eventScopeType(m, d) !== null;
        if (!eventVisibleToGrant(m, d, claims, scoped ? "owner" : null)) continue;
        types.push({ type: `${app.entry.product}.${d.name}`, app: app.entry.product as AgentEvent["app"], title: d.title, payloadSchema: d.payloadSchema, scoped, delivery: ["poll", "stream"] });
      }
      const hold = PLATFORM_EVENTS["tb.hold.decided"];
      if (app.entry.product !== "tb" && eventVisibleToGrant(m, { visibleWith: hold.visibleWith as never }, claims)) {
        types.push({ type: "tb.hold.decided", app: app.entry.product as AgentEvent["app"], title: hold.title, payloadSchema: hold.payloadSchema as never, scoped: false, delivery: ["poll", "stream"] });
      }
    }
    return { types };
  }

  /** Test and diagnostics view of one agent's rows (id order). */
  rows(agent: string): { id: string; origin: string; held: boolean; ingestAt: number; type: string; instanceId: string | null }[] {
    return (this.#s("SELECT id, origin, held, ingest_at, type, instance_id FROM rows WHERE agent = ? ORDER BY id").all(agent) as { id: string; origin: string; held: number; ingest_at: number; type: string; instance_id: string | null }[]).map((r) => ({
      id: r.id,
      origin: r.origin,
      held: r.held === 1,
      ingestAt: r.ingest_at,
      type: r.type,
      instanceId: r.instance_id,
    }));
  }

  /** Test and diagnostics view of an agent's retention state. */
  retention(agent: string): { droppedThrough: string | null; heldDropped: boolean } {
    const a = this.#s("SELECT dropped_through, held_dropped FROM agents WHERE agent = ?").get(agent) as { dropped_through: string | null; held_dropped: number } | undefined;
    return { droppedThrough: a?.dropped_through || null, heldDropped: a?.held_dropped === 1 };
  }

  /** Test hook: raw SQL against the log (e.g. to age rows). Never used by the bridge. */
  exec(sql: string, ...params: SQLInputValue[]): void {
    this.#db.prepare(sql).run(...params);
    this.#counts.clear();
  }
}

/** The schema of events.db (STRICT tables). */
function createSchema(db: DatabaseSync): void {
  db.exec("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA busy_timeout = 5000;");
  db.exec(`
    CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL) STRICT;
    CREATE TABLE IF NOT EXISTS rows (
      id TEXT PRIMARY KEY,
      origin TEXT NOT NULL,
      agent TEXT NOT NULL,
      ins TEXT NOT NULL,
      product TEXT NOT NULL,
      type TEXT NOT NULL,
      instance_id TEXT,
      digest TEXT NOT NULL,
      op TEXT NOT NULL,
      scope_type TEXT,
      authority TEXT,
      envelope TEXT NOT NULL,
      ingest_at INTEGER NOT NULL,
      held INTEGER NOT NULL DEFAULT 0
    ) STRICT;
    CREATE INDEX IF NOT EXISTS rows_agent_id ON rows (agent, id);
    CREATE INDEX IF NOT EXISTS rows_agent_ingest ON rows (agent, ingest_at, origin);
    CREATE INDEX IF NOT EXISTS rows_scope ON rows (ins, instance_id, agent);
    CREATE INDEX IF NOT EXISTS rows_held ON rows (held) WHERE held = 1;
    CREATE INDEX IF NOT EXISTS rows_ingest ON rows (ingest_at);
    CREATE TABLE IF NOT EXISTS agents (agent TEXT PRIMARY KEY, dropped_through TEXT, held_dropped INTEGER NOT NULL DEFAULT 0) STRICT;
    CREATE TABLE IF NOT EXISTS keys (ins TEXT NOT NULL, key TEXT NOT NULL, at INTEGER NOT NULL, PRIMARY KEY (ins, key)) STRICT;
    CREATE INDEX IF NOT EXISTS keys_at ON keys (at);
    CREATE TABLE IF NOT EXISTS manifests (digest TEXT PRIMARY KEY, json TEXT NOT NULL) STRICT;
  `);
  const schema = db.prepare("SELECT v FROM meta WHERE k = 'schema'").get() as { v: string } | undefined;
  if (!schema) db.prepare("INSERT INTO meta (k, v) VALUES ('schema', ?)").run(SCHEMA_VERSION);
  else if (schema.v !== SCHEMA_VERSION) throw new Error(`events.db schema ${schema.v} is not ${SCHEMA_VERSION}`);
  db.prepare("SELECT count(*) FROM rows").get();
}

/**
 * Opens events.db; a file that fails to open or to pass the schema check is moved aside (`events.db.corrupt-<ms>`, with its
 * -wal/-shm) and a fresh log is created (ids continue from the clock: a ULID is time-ordered). A second failure throws (the
 * caller then runs the bridge without the event log and without the `events` cap).
 */
function openDatabase(path: string, log: Logger, now: () => number): { db: DatabaseSync; lastId: string } {
  const attempt = (): { db: DatabaseSync; lastId: string } => {
    const db = new DatabaseSync(path);
    try {
      createSchema(db);
      const stored = (db.prepare("SELECT v FROM meta WHERE k = 'last_id'").get() as { v: string } | undefined)?.v ?? "";
      const maxRow = (db.prepare("SELECT max(id) AS m FROM rows").get() as { m: string | null }).m ?? "";
      return { db, lastId: stored > maxRow ? stored : maxRow };
    } catch (e) {
      try {
        db.close();
      } catch {
        /* already unusable */
      }
      throw e;
    }
  };
  try {
    return attempt();
  } catch (e) {
    const aside = `${path}.corrupt-${now()}`;
    log.error("bridge.events.db_unusable", { code: e instanceof Error ? e.message.slice(0, 120) : "error", movedTo: aside });
    for (const suffix of ["", "-wal", "-shm"]) if (existsSync(`${path}${suffix}`)) renameSync(`${path}${suffix}`, `${aside}${suffix}`);
    return attempt();
  }
}

/**
 * The event log, or undefined when it cannot be opened even after moving a bad file aside: the bridge then runs WITHOUT app
 * events (ingest 503, `tealbrick/events/*` -32601, no `events` cap).
 */
export function openEventStore(o: EventStoreOptions): EventStore | undefined {
  try {
    return new EventStore(o);
  } catch (e) {
    o.log.error("bridge.events.unavailable", { code: e instanceof Error ? e.message.slice(0, 120) : "error" });
    return undefined;
  }
}

/** Every agent with a grant to `ins` (in a stable order). */
function grantees(t: Table, ins: string): string[] {
  const aud = insRef(ins as InstanceId);
  const out: string[] = [];
  for (const g of t.grants.values()) if (g.claims.aud === aud) out.push(g.claims.sub.slice(7));
  return [...new Set(out)].sort();
}

/** The VALID grant claims of `agent` for `ins` (the table holds verified grants; expiry and revocation are re-checked). */
function validGrant(t: Table, agent: string, ins: string, nowMs: number): GrantClaims | null {
  const g = t.grants.get(grantKey(agtRef(agent as AgentId), insRef(ins as InstanceId)));
  if (!g) return null;
  if (typeof g.claims.exp === "number" && g.claims.exp * 1000 <= nowMs) return null;
  if (t.revokedJtis.has(g.claims.jti)) return null;
  return g.claims;
}

/** The poll `limit`: an integer in 1..100; absent → 50; other numbers are clamped. */
export function pollLimit(v: unknown): number {
  if (typeof v !== "number" || !Number.isFinite(v)) return EVENT_POLL_LIMIT.default;
  return Math.min(EVENT_POLL_LIMIT.max, Math.max(EVENT_POLL_LIMIT.min, Math.trunc(v)));
}
