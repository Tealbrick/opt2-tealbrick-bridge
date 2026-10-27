/**
 * The per-call routing pipeline (BRIDGE §8): resolve → select grant → validate input → gate() →
 * before hooks → context hooks → config age → re-gate → forward → after hooks → result.
 * The bridge gates; the app's authorize() decides run/hold (C10). The bridge never counts or holds.
 */

import { tooDeep } from "@opt2-tealbrick/relay";
import type {
  AfterHookResponse,
  BeforeHookResponse,
  ContextHookResponse,
  HookEntry,
  JsonObject,
  JsonValue,
  OpResult,
} from "@opt2-tealbrick/spec/bridge";
import { type AgentId, BRIDGE_OP_PATH, type BridgeOp, type CallId, type CompanionGrantClaims, type InstanceId, LIFETIME_S, TYP } from "@opt2-tealbrick/spec/credentials";
import { type CrudAction, type DynamicCatalogEntry, type DynamicResolution, EFFECTS, type Effect, type HoldFamily } from "@opt2-tealbrick/spec/manifest";
import type { Json, OperationView } from "@opt2-tealbrick/spec/sdk";
import { APP_HOLD_STATUS_MIN_SDK, APP_HOLD_STATUS_OP, callerContextKeys, sdkVersionAtLeast } from "./app-calls.ts";
import type { BridgeContext } from "./context.ts";
import { type AppRuntime, grantKey, insRef, pauseFor, type Table, trustFor } from "./table.ts";
import { isSecretOutputOp } from "./tools.ts";
import { BridgeError, isRecord, nowS, readCapped, readCappedJson } from "./util.ts";

export type Caller =
  | { type: "agent"; agt: `agt_${string}`; con: `con_${string}` }
  | { type: "app"; ins: InstanceId; grant: string };

export interface Target {
  app: AppRuntime;
  op: OperationView;
  /** dynamic op: the concrete tool (list entry or `_call` tool) */
  tool?: string;
}

export interface CallRequest {
  caller: Caller;
  target: Target;
  input: Json;
  idempotencyKey?: string;
  parentCall?: CallId;
  signal?: AbortSignal;
  /** bridge-written `tb.*` context (BRIDGE §8.5), set BEFORE the before hooks; e.g. `tb.onBehalfOf` */
  reservedContext?: JsonObject;
  /**
   * v0.1.77 (C367 P4, BRIDGE §8.5, cap `app_call_context`): `CallEnvelope.context` exactly as the app caller sent it (`undefined` =
   * absent). Companion path only; `route` validates it against the VERIFIED product of the presented grant, after the grant is
   * selected and before any hook, and merges the keys into the op body `context`.
   */
  callerContext?: unknown;
}

export type CallOutcome = OpResult<JsonValue>;

export const RESOLVE_TTL_MS = 5 * 60_000;
/** spec 0.1.68 (BRIDGE v0.1.68, cap `hook_tool`): a dynamic resolution's canonical tool name. */
export const DYNAMIC_TOOL_RE = /^[a-z][a-z0-9_]{1,62}$/; // spec 0.1.68: catalog names (<= 48) and variants the agent requests, such as `<tool>__first_contact`
const APP_TIMEOUT_MS = 30_000;
/** F57a: message of a call cut off at the drain bound (it may have run: the caller checks before retrying) */
const CUT_OFF = "the bridge restarted while this call ran; its outcome is unknown, check before retrying";
const MAX_RESULT_BYTES = 4 * 1024 * 1024;
/** hook answers and bridge-only SDK answers (catalog, resolve, mark, scope summary), BSD-05 */
const MAX_SMALL_ANSWER_BYTES = 256 * 1024;
/** dynamic search results kept per call */
const MAX_SEARCH_RESULTS = 50;

/**
 * Bridge verdict codes: only the bridge decides these, so an app answer naming one is not passed through
 * (an app cannot make a call look paused or revoked to the agent, H-7).
 */
const BRIDGE_VERDICTS: ReadonlySet<string> = new Set([
  "paused",
  "grant_revoked",
  "grant_invalid",
  "grant_expired",
  "grant_stale",
  "no_grant",
  "unauthenticated",
  "config_expired",
  "hook_denied",
  "hook_failed",
  "crud_exceeds_grant",
  "not_in_workflow",
  "audience_not_agent",
  "scope_type_unknown",
]);
const APP_CODE_RULE = /^[a-z][a-z0-9_]{1,40}$/;

/** Fixed metric label set (H-5): bridge codes as they are, every app-side code as `app_code`. */
const METRIC_CODES: ReadonlySet<string> = new Set([
  "ok",
  "unauthenticated",
  "paused",
  "unknown_tool",
  "no_grant",
  "grant_invalid",
  "grant_expired",
  "grant_stale",
  "grant_revoked",
  "crud_exceeds_grant",
  "audience_not_agent",
  "scope_type_unknown",
  "not_in_workflow",
  "input_invalid",
  "dynamic_resolve_failed",
  "dynamic_ceiling_exceeded",
  "hook_denied",
  "hook_failed",
  "hook_reentry",
  "call_depth_exceeded",
  "config_expired",
  "app_unavailable",
  "app_timeout",
  "app_error",
  "after_failed",
  "payload_too_large",
  "rate_limited",
  "request_timeout",
]);

/** Maps any code to the fixed metric label set (H-5). */
export function metricCode(code: string): string {
  return METRIC_CODES.has(code) ? code : "app_code";
}

/** An app-side error code passes through only when well-formed and not a bridge verdict (H-7). */
export function appErrorCode(code: unknown): string {
  return typeof code === "string" && APP_CODE_RULE.test(code) && !BRIDGE_VERDICTS.has(code) ? code : "app_error";
}

/** App error text without control or bidi-override characters, at most 500 chars (H-7). */
export function appErrorMessage(message: unknown, fallback: string): string {
  if (typeof message !== "string") return fallback;
  const clean = message.replace(/[\p{Cc}\u2028\u2029\u200e\u200f\u202a-\u202e\u2066-\u2069]/gu, " ").slice(0, 500).trim();
  return clean || fallback;
}

/** Calls currently in flight: hook re-entry and companion depth (BRIDGE §8.2). */
interface Active {
  inHook: boolean;
  depth: number;
  /** A2A-2: instances this call was delivered to (target app, hook apps); only they may name it as parentCall */
  deliveredTo: Set<string>;
  startedMs: number;
}

/** A2A-2/3: a parentCall is `call_` + ULID; anything else is refused before it is logged or looked up */
export const CALL_ID_RE = /^call_[0-9A-HJKMNP-TV-Z]{26}$/;
/** an open parent call is accepted as parentCall for at most this long (the op/hook answer windows are shorter) */
export const PARENT_CALL_TTL_MS = 120_000;

/** A hook answered, but not in the phase's shape (manifest hookResponseProblem). */
class HookBadAnswer extends Error {}

/**
 * Does a hook's `match` cover this call? MANIFEST §16 (Hooks): hooks match only `agent`-audience manifest operations reached through
 * the bridge, never the standard `tb.*` ops, person ops or hook calls (Rules F2). So a standard op, or any op whose audience is not
 * `agent`, never matches (not even a `products: ["*"]` hook with no `operations`): a hook outage must not fail `tb.holds_*`,
 * `tb.hold_status` or `tb.receipts_list` closed. Used by the call path (`matchingHooks`, `requireListedHooks`) and by rule 6 of
 * the event summaries (`eventHookMatches`). Hook calls themselves never route through here (`callHook` is not a call).
 */
function hookMatches(m: { products: readonly string[]; operations?: readonly string[]; effects?: readonly string[] }, target: Pick<Target, "app">, op: OperationView): boolean {
  if (op.standard || op.audience !== "agent") return false;
  return (m.products.includes("*") || m.products.includes(target.app.entry.product)) && (!m.operations || m.operations.includes(op.id)) && (!m.effects || m.effects.includes(op.effect));
}

/**
 * MANIFEST §16.2 rule 6 (bridge 0.2.7): does a `before` or `after` hook match a call of `op` on `app`? An enabled listed hook
 * (the same match as the call path), or one a deployed app DECLARES that the config does not list (the call path refuses such a
 * call `hook_failed`, C117; for an event the bridge fails closed the same way: no summary). Listed with `enabled: false` = the
 * owner switched it off: no match.
 */
export function eventHookMatches(t: Table, app: AppRuntime, op: OperationView): boolean {
  const target = { app };
  if (t.hooks.some((h) => (h.phase === "before" || h.phase === "after") && h.enabled !== false && hookMatches(h.match, target, op))) return true;
  const listed = new Set(t.hooks.map((h) => `${h.ins}|${h.hookId}`));
  for (const a of t.apps.values()) {
    for (const d of a.declaredHooks) {
      if ((d.phase === "before" || d.phase === "after") && !listed.has(`${a.entry.ins}|${d.id}`) && hookMatches(d.match ?? { products: ["*"] }, target, op)) return true;
    }
  }
  return false;
}

export class CallRouter {
  private readonly ctx: BridgeContext;
  private readonly active = new Map<CallId, Active>();
  /** F57a: aborted at the drain bound; every forward listens to it (hooks and bridge ops are bounded at 2 s) */
  private readonly shutdown = new AbortController();
  /** F57a: calls (agent and companion) still running — the drain waits for 0 */
  activeCount(): number {
    return this.active.size;
  }
  /**
   * F57a: the drain bound is reached. Every call still forwarding is cut off and answers its caller with
   * `app_unavailable` ("outcome unknown"): it may have run at the app, so it is never re-sent automatically.
   */
  abortAll(): number {
    this.shutdown.abort();
    return this.active.size;
  }
  private readonly resolveCache = new Map<string, { at: number; value: DynamicResolution; digest: string }>();
  private readonly catalogCache = new Map<string, { at: number; entries: DynamicCatalogEntry[] }>();
  /** QA-P5-3: instance → the release digest its cached resolutions came from */
  private readonly resolvedDigest = new Map<string, string>();
  readonly counters = new Map<string, number>();

  constructor(ctx: BridgeContext) {
    this.ctx = ctx;
    // C296: expire, never drop: the next listing asks the apps again, and a refresh that fails falls back to the last
    // good answer instead of an empty list (`catalogFresh`).
    ctx.on("table", (next: Table | undefined) => {
      this.expireCatalogs();
      // an instance that left the table never answers again: its cached catalogs go (review: the cache is pruned)
      const live = new Set([...(next?.apps.values() ?? [])].map((a) => String(a.entry.ins)));
      for (const key of this.catalogCache.keys()) if (!live.has(key.slice(0, key.indexOf("|")))) this.catalogCache.delete(key);
      // QA-P5-3: a resolution belongs to the release that answered it; an instance that left or now runs another release
      // (digest changed: update, rollback, candidate) resolves again, so a reclassified tool never keeps its old crud/effect
      const running = new Map([...(next?.apps.values() ?? [])].map((a) => [String(a.entry.ins), String(a.digest ?? a.entry.manifestDigest)]));
      for (const [ins, digest] of this.resolvedDigest) {
        if (running.get(ins) === digest) continue;
        this.resolvedDigest.delete(ins);
        for (const key of this.resolveCache.keys()) if (key.startsWith(`${ins}|`)) this.resolveCache.delete(key);
      }
    });
    // C283 A1: `admitted` marks follow the app's owner rows, which changed
    ctx.on("scopes", () => this.expireCatalogs());
  }

  /**
   * A2A-2: `parentCall` as the caller named it → the call id when it is an OPEN call this bridge delivered to that
   * same (verified) caller instance within the TTL; otherwise undefined (the call is then app-initiated: limited and
   * audited). A forged, foreign or finished id never grants the parent-chain exemptions.
   */
  parentCallFor(callerIns: string, parentCall: string): CallId | undefined {
    const a = this.active.get(parentCall as CallId);
    if (!a || !a.deliveredTo.has(callerIns) || Date.now() - a.startedMs > PARENT_CALL_TTL_MS) return undefined;
    return parentCall as CallId;
  }

  private count(key: string): void {
    this.counters.set(key, (this.counters.get(key) ?? 0) + 1);
  }

  // ── bridge-only SDK calls (catalog, resolve, mark, scope summary; C16 B5) ──
  // Proof claims per bop (SDK-API §3.2, C91), matched EXACTLY by the SDK's verifyBridgeOpProof:
  //   catalog {bop, op} · resolve {bop, op, in} · mark {bop, in} · scope_summary {bop}
  async bridgeOp<T>(app: AppRuntime, bop: BridgeOp, body: Record<string, unknown>, timeoutMs = 2_000): Promise<T> {
    const id = this.ctx.identity;
    if (!id) throw new BridgeError("app_unavailable", 503);
    const now = nowS();
    const call = `call_${this.ctx.api.ulid()}` as CallId;
    const claims = {
      iss: this.ctx.bridgeRef,
      sub: this.ctx.bridgeRef,
      aud: insRef(app.entry.ins),
      iat: now,
      exp: now + LIFETIME_S.proof,
      jti: this.ctx.api.ulid(),
      call,
      // C91: exactly the claims the SDK binds, from the shared rule (manifest bridgeOpProofClaims, L1)
      ...this.ctx.api.bridgeOpProofClaims(bop, body as Json),
    };
    const proof = await this.ctx.api.signJws(TYP.callProof, claims, id.key);
    // L3 (spec 0.1.14): a failed bridge op is never only a log line; it is counted in the status report
    const failed = (code: string, detail: string): never => {
      this.ctx.reject({ kind: "bridge_op", code, ins: app.entry.ins, detail: `${bop}: ${detail}` });
      throw new BridgeError("app_error", 502, `bridge op ${bop} answered ${detail}`);
    };
    let res: Response;
    try {
      res = await this.ctx.fetch(new URL(`/tb/v1/bridge/${BRIDGE_OP_PATH[bop]}`, app.entry.internalUrl), {
        method: "POST",
        headers: { "content-type": "application/json", "TB-Call": proof },
        body: JSON.stringify(body),
        redirect: "error",
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (e) {
      return failed(`${bop}_failed`, isTimeout(e) ? "timeout" : "network");
    }
    if (!res.ok) {
      await res.body?.cancel().catch(() => undefined);
      return failed(`${bop}_failed`, String(res.status));
    }
    try {
      return await readCappedJson<T>(res, MAX_SMALL_ANSWER_BYTES);
    } catch {
      return failed(`${bop}_failed`, "bad answer");
    }
  }

  /**
   * C296: a tool index past its TTL is rebuilt from fresh catalogs: the agent's cached answers are EXPIRED (not dropped),
   * so a refresh that fails falls back to the last good answer (`catalogFresh`).
   */
  expireCatalogs(agent?: AgentId): void {
    for (const [key, hit] of this.catalogCache) if (!agent || key.endsWith(`|${agent}`)) this.catalogCache.set(key, { ...hit, at: 0 });
  }

  /**
   * C283 A1 (spec 0.1.50): the body carries `agent`, so the SDK can mark the entries that agent's owner rows admit
   * (`admitted: "owner"`). The marks differ per agent, so the cache is per agent too. Not bound by the bridge-op proof.
   */
  async catalog(app: AppRuntime, op: string, agent: AgentId): Promise<DynamicCatalogEntry[]> {
    return (await this.catalogFresh(app, op, agent)).entries;
  }

  /**
   * C296: the catalog, and whether it is the last good answer served because a refresh failed (`stale`: the caller retries
   * soon). A failure with no earlier answer throws, as before.
   */
  async catalogFresh(app: AppRuntime, op: string, agent: AgentId): Promise<{ entries: DynamicCatalogEntry[]; stale: boolean }> {
    const key = `${app.entry.ins}|${op}|${agent}`;
    const hit = this.catalogCache.get(key);
    if (hit && Date.now() - hit.at < RESOLVE_TTL_MS) return { entries: hit.entries, stale: false };
    let entries: DynamicCatalogEntry[] | undefined;
    try {
      entries = await this.bridgeOp<DynamicCatalogEntry[]>(app, "catalog", { op, agent });
    } catch (error) {
      if (hit) return { entries: hit.entries, stale: true };
      throw error;
    }
    const list = Array.isArray(entries) ? entries.slice(0, 256) : [];
    this.catalogCache.set(key, { at: Date.now(), entries: list });
    return { entries: list, stale: false };
  }

  async search(app: AppRuntime, op: string, query: string, limit: number | undefined, agent: AgentId): Promise<DynamicCatalogEntry[]> {
    const entries = await this.bridgeOp<DynamicCatalogEntry[]>(app, "catalog", { op, query, ...(limit ? { limit } : {}), agent });
    return Array.isArray(entries) ? entries.slice(0, MAX_SEARCH_RESULTS) : [];
  }

  private async resolve(app: AppRuntime, op: string, tool: string): Promise<DynamicResolution> {
    const key = `${app.entry.ins}|${op}|${tool}`;
    const hit = this.resolveCache.get(key);
    // QA-BR29-3: a hit counts only for the release that runs now (a resolve in flight across a table swap keeps the old digest)
    if (hit && Date.now() - hit.at < RESOLVE_TTL_MS && hit.digest === String(app.digest ?? app.entry.manifestDigest)) return hit.value;
    let value: DynamicResolution;
    try {
      value = await this.bridgeOp<DynamicResolution>(app, "resolve", { op, tool });
    } catch {
      throw new BridgeError("dynamic_resolve_failed", 503);
    }
    if (!isRecord(value) || !Array.isArray(value.crud) || !(EFFECTS as readonly string[]).includes(value.effect as string)) {
      throw new BridgeError("dynamic_resolve_failed", 503);
    }
    // C107 (BRIDGE v0.1.17 rule, shipped 0.1.18): an outward or money resolution must name its hold family, or the
    // held/gate decision would silently skip it. Refused, not retried; not cached.
    if ((value.effect === "outward" || value.effect === "money") && !(typeof value.holdFamily === "string" && value.holdFamily)) {
      throw new BridgeError("dynamic_resolve_failed", 403, "the app resolved an outward or money tool without a hold family", { reason: "family_missing" });
    }
    // spec 0.1.68 (BRIDGE v0.1.68, cap `hook_tool`; C354): the resolution names the app's canonical tool, which hooks see as
    // `target.tool`. It must EQUAL the requested name (an app never swaps the tool behind the agent's request; a variant such
    // as `<tool>__first_contact` is requested by the agent itself) and match DYNAMIC_TOOL_RE (≤ 63 chars). A case, space,
    // alias or `__` variant is refused, never mapped, so a hold on a tool cannot be bypassed. Refused, not cached.
    if (typeof value.tool !== "string" || value.tool !== tool || !DYNAMIC_TOOL_RE.test(value.tool)) {
      throw new BridgeError("dynamic_resolve_failed", 403, "the app's resolution names a different or malformed tool", { reason: "tool_mismatch" });
    }
    if (this.resolveCache.size > 5000) this.resolveCache.clear();
    this.resolveCache.set(key, { at: Date.now(), value, digest: String(app.digest ?? app.entry.manifestDigest) });
    this.resolvedDigest.set(String(app.entry.ins), String(app.digest ?? app.entry.manifestDigest));
    return value;
  }

  /**
   * Effective op for gate() and hooks: dynamic ops take crud/effect/holdFamily from resolve, within ceilings, and `tool` =
   * the resolution's canonical tool (spec 0.1.68, hook target `tool`); static ops have no tool.
   */
  private async effectiveOp(t: Target): Promise<{ op: OperationView; tool?: string }> {
    const op = t.op;
    if (op.standard || !op.dynamic) return { op };
    if (!t.tool) throw new BridgeError("input_invalid", 400, "dynamic tool missing");
    const r = await this.resolve(t.app, op.id, t.tool);
    const ceilingIdx = EFFECTS.indexOf(op.dynamic.effectCeiling);
    if (!r.crud.every((c) => op.dynamic?.crudCeiling.includes(c)) || EFFECTS.indexOf(r.effect) > ceilingIdx) {
      throw new BridgeError("dynamic_ceiling_exceeded", 403);
    }
    return { op: { ...op, crud: r.crud as CrudAction[], effect: r.effect as Effect, ...(r.holdFamily ? { holdFamily: r.holdFamily as HoldFamily } : {}) }, tool: r.tool };
  }

  private selectGrant(t: Table, caller: Caller, target: InstanceId): string {
    if (caller.type === "app") return caller.grant;
    const g = t.grants.get(grantKey(`tb:agt:${caller.agt}`, insRef(target)));
    if (!g) throw new BridgeError("no_grant", 403);
    return g.token;
  }

  /**
   * Gate (and, for a companion call, the grant-subject checks). Returns the presented companion grant's `prd` (GRANT-PRD,
   * spec 0.1.46: the product of the calling instance, signed with the grant) when the grant carries one; the manifest
   * library has already shape-checked it (a malformed `prd` is `grant_invalid` in gate()).
   */
  private runGate(t: Table, caller: Caller, target: Target, op: OperationView, grant: string): string | undefined {
    const now = nowS();
    const paused =
      caller.type === "agent"
        ? pauseFor(t, caller.agt, caller.con, target.app.entry.ins)
        : { ...pauseFor(t, undefined, undefined, target.app.entry.ins), instance: t.pausedInstances.has(target.app.entry.ins) || t.pausedInstances.has(caller.ins) };
    const d = this.ctx.api.gate({ paused, grant, trust: trustFor(t, target.app.entry.ins, now), op, declaredScopeTypes: target.app.scopeTypes });
    if (d.decision !== "pass") throw new BridgeError(d.reason, undefined as never);
    // companion: the presented grant's subject must be the asserting instance (CREDENTIALS §11)
    if (caller.type === "app") {
      const v = this.ctx.api.verifyGrant(grant, trustFor(t, target.app.entry.ins, now));
      if (!("claims" in v) || v.claims.sub !== insRef(caller.ins)) throw new BridgeError("grant_invalid", 403);
      // v0.1.77 (C367 P3, BRIDGE §8.3, cap `app_hold_status`): gate() lets `tb.hold_status` pass on any valid grant (I4 skips the
      // CRUD ceiling and the workflow step), which is right for an agent. An APP caller needs the op in its companion grant's `wf`
      // (MANIFEST M-CP-3 mints it there): not listed → `not_in_workflow`, like any op outside `wf`. Never for another standard op.
      if (op.standard && op.id === APP_HOLD_STATUS_OP && !(v.claims.wf as readonly string[]).includes(APP_HOLD_STATUS_OP)) throw new BridgeError("not_in_workflow", 403);
      // C70: a valid grant that is not in the caller's CURRENT slice was minted under an older revision → the SDK
      // re-reads its slice once and retries (grant_expired stays the code for exp)
      const current = sliceGrants(t.apps.get(caller.ins));
      if (current && !current.includes(grant)) throw new BridgeError("grant_stale", 403, "the grant is from an older slice revision; re-read the slice");
      return (v.claims as CompanionGrantClaims).prd;
    }
    return undefined;
  }

  /**
   * C117 / BRIDGE v0.1.24: every hook DECLARED by a deployed app's manifest that matches the call (any phase) must be
   * listed in config.hooks; declared but ABSENT → refused `hook_failed` BEFORE anything runs or is forwarded (an
   * after-hook gap must not surface only after the op ran). Listed with `enabled: false` = the owner's switch, skipped.
   */
  private requireListedHooks(t: Table, target: Target, op: OperationView): void {
    const listed = new Set(t.hooks.map((h) => `${h.ins}|${h.hookId}`));
    for (const app of t.apps.values()) {
      for (const d of app.declaredHooks) {
        if (!hookMatches(d.match ?? { products: ["*"] }, target, op)) continue;
        if (listed.has(`${app.entry.ins}|${d.id}`)) continue;
        this.ctx.reject({ kind: "config", code: "hook_not_listed", ins: app.entry.ins, detail: `${app.entry.product}.${d.id}` });
        throw new BridgeError("hook_failed", 503, `hook ${app.entry.product}.${d.id} is declared but not in the config`);
      }
    }
  }

  /**
   * Listed, enabled hooks of one phase that match the call (a listed hook whose app is down fails closed in callHook).
   * BRG-28: `t.hooks` is already in THE hook order (table.ts compareHooks); filtering keeps it, no second sort.
   */
  private matchingHooks(t: Table, phase: HookEntry["phase"], target: Target, op: OperationView): HookEntry[] {
    return t.hooks.filter((h) => h.phase === phase && h.enabled !== false && hookMatches(h.match, target, op));
  }

  /**
   * One hook request, answer shape-checked by the shared rule (manifest hookResponseProblem; a bad shape throws
   * {@link HookBadAnswer}). BRG-28 (L3, L34): `tb_bridge_hook_calls_total{result}` = done | slow (answered, over
   * `timeoutMs`) | timeout (aborted at the ≤ 2 s cap) | failed (down app, HTTP error, unreadable or bad answer).
   */
  private async callHook<R>(t: Table, h: HookEntry, call: CallId, request: Record<string, unknown>, callerRef: string, input: Json | undefined): Promise<R> {
    const started = Date.now();
    let result = "failed";
    try {
      const r = await this.requestHook(t, h, call, request, callerRef, input);
      if (this.ctx.api.hookResponseProblem(h.phase, r, h.product) !== null) throw new HookBadAnswer();
      result = Date.now() - started > h.timeoutMs ? "slow" : "done";
      return r as R;
    } catch (e) {
      if ((e as { name?: unknown } | null)?.name === "TimeoutError") result = "timeout";
      throw e;
    } finally {
      this.count(`hook|${h.id}|${result}`);
    }
  }

  private async requestHook(t: Table, h: HookEntry, call: CallId, request: Record<string, unknown>, callerRef: string, input: Json | undefined): Promise<unknown> {
    this.active.get(call)?.deliveredTo.add(h.ins);
    const app = t.apps.get(h.ins);
    // a hook app that is down (or refused by BSD-07) fails closed without a request
    if (!app || app.down || app.refused || t.pausedInstances.has(h.ins)) throw new BridgeError("hook_failed", 503);
    const id = this.ctx.identity;
    if (!id) throw new BridgeError("hook_failed", 503);
    const now = nowS();
    const context = (request.context ?? {}) as Json;
    // C268 B / C268c: serialise ONCE, hash those bytes, send those bytes. `bd` only when the app's stored capability set
    // (its claim, then its status pushes) lists "bd"; never inferred from a version, never dropped by a failed call.
    const bytes = Buffer.from(JSON.stringify(request), "utf8");
    const bd = this.ctx.proofCaps.hasBd(h.ins) ? this.ctx.api.sha256Bytes(bytes) : undefined;
    const proof = await this.ctx.api.signJws(
      TYP.callProof,
      {
        iss: this.ctx.bridgeRef,
        sub: callerRef,
        aud: insRef(h.ins),
        iat: now,
        exp: now + LIFETIME_S.proof,
        jti: this.ctx.api.ulid(),
        call,
        hook: h.hookId,
        phase: h.phase,
        ctx: this.ctx.api.digest(context),
        ...(input !== undefined ? { in: this.ctx.api.digest(input) } : {}),
        ...(bd ? { bd } : {}),
      },
      id.key,
    );
    // a refusal (401 included), a timeout or a connect failure ends this hook call as `hook_failed`: there is no second try,
    // with or without `bd`, and the stored capability is not touched (C268c)
    const res = await this.ctx.fetch(new URL(`/tb/v1/hooks/${h.hookId}`, app.entry.internalUrl), {
      method: "POST",
      headers: { "content-type": "application/json", "TB-Call": proof },
      body: bytes,
      redirect: "error",
      signal: AbortSignal.timeout(Math.min(Math.max(h.timeoutMs, 100), 2_000)),
    });
    if (!res.ok) {
      await res.body?.cancel().catch(() => undefined);
      throw new Error(String(res.status));
    }
    return await readCappedJson<unknown>(res, MAX_SMALL_ANSWER_BYTES);
  }

  /** Runs one call through the pipeline. Throws BridgeError for refusals; returns ok/held results. */
  async route(req: CallRequest): Promise<{ call: CallId; result: CallOutcome }> {
    const ctx = this.ctx;
    const t0 = ctx.table;
    if (!t0) throw new BridgeError("config_expired", 503);
    const call = `call_${ctx.api.ulid()}` as CallId;
    const started = Date.now();
    const { caller, target } = req;
    const callerRef = caller.type === "agent" ? `tb:agt:${caller.agt}` : `tb:ins:${caller.ins}`;
    let code = "ok";
    // companion re-entry and depth (BRIDGE §8.2)
    let depth = 0;
    if (caller.type === "app" && req.parentCall) {
      const parent = this.active.get(req.parentCall);
      if (parent?.inHook) throw new BridgeError("hook_reentry", 409);
      depth = (parent?.depth ?? 0) + 1;
      if (depth > 3) throw new BridgeError("call_depth_exceeded", 409);
    }
    const active: Active = { inHook: false, depth, deliveredTo: new Set([target.app.entry.ins]), startedMs: Date.now() };
    this.active.set(call, active);
    try {
      if (target.app.down || !target.app.manifest) throw new BridgeError("app_unavailable", 503);
      // spec 0.1.68 (BRIDGE v0.1.68, cap `secret_output`): a secretOutput op answers app callers only; an agent is refused
      // before anything runs (on every path: MCP, relay; the op is never listed for agents either)
      if (caller.type === "agent" && isSecretOutputOp(target.op)) throw new BridgeError("secret_output_app_only", 403, "this operation answers app callers only");
      const { op, tool: resolvedTool } = await this.effectiveOp(target);
      const grant = this.selectGrant(t0, caller, target.app.entry.ins);
      // 4. input against the op schema (dynamic: the fixed DynamicCallInput shape)
      const v = ctx.api.validateInput(target.op, req.input);
      if (!v.ok) throw new BridgeError("input_invalid", 400, v.errors.slice(0, 3).join("; "));
      if (!target.op.standard && target.op.idempotency === "required" && !req.idempotencyKey) {
        throw new BridgeError("input_invalid", 400, "idempotency key required");
      }
      // 5. gate
      const grantPrd = this.runGate(t0, caller, target, op, grant);
      // v0.1.77 (C367 P3, BRIDGE §8.3, PK-D6): the ownership rule of `tb.hold_status` lives in the target's SDK, so an APP caller
      // reaches it only on a target whose last reported `sdkVersion` (the status push) is at least APP_HOLD_STATUS_MIN_SDK. Lower,
      // unknown or malformed → refused here, before any hook; the target is not called. Agent calls are unchanged.
      // QA-BR29-1: the status counts only when it was pushed by the version the config names now (serving or update candidate),
      // so a rollback to an older SDK is not trusted on the last push of the newer one.
      const pushed = ctx.health.get(target.app.entry.ins)?.status;
      const named = [target.app.entry.version, target.app.entry.candidateVersion].filter((v) => typeof v === "string");
      if (caller.type === "app" && op.standard && op.id === APP_HOLD_STATUS_OP && (!pushed || !named.includes(pushed.version) || !sdkVersionAtLeast(pushed.sdkVersion, APP_HOLD_STATUS_MIN_SDK))) {
        throw new BridgeError("not_in_workflow", 403, "the target app does not answer hold status for app callers yet");
      }
      // v0.1.77 (C367 P4, BRIDGE §8.5, cap `app_call_context`): the caller context, checked against the VERIFIED product of the
      // presented grant (its `prd`; never the envelope, never the instance table), after the grant is selected and before any hook.
      // Absent or `{}` = none. Informational only: nothing below (gate, grant checks, hook authority) reads it.
      // QA-BR29-2: when the grant's `prd` and the instance table disagree (see below), no product is verified: a non-empty
      // context is then refused like a caller without a verified product (PK-D3).
      const tableProductForContext = caller.type === "app" ? t0.apps.get(caller.ins)?.entry.product : undefined;
      const verifiedPrd = grantPrd !== undefined && grantPrd === tableProductForContext ? grantPrd : null;
      const callerKeys = caller.type === "app" ? callerContextKeys(req.callerContext, verifiedPrd) : undefined;
      // HOOK-CALLER-PRODUCT + GRANT-PRD (spec 0.1.46): the product of an app caller comes from the bridge's own signed
      // config (the instance table). When the presented companion grant also carries `prd` and it differs, the two
      // sources disagree: the hook request carries NO product (a policy app then treats the caller as unverified) and the
      // mismatch is logged (both product ids; no tokens). No `prd` (an older Core, an agent) → the table's product.
      const tableProduct = caller.type === "app" ? t0.apps.get(caller.ins)?.entry.product : undefined;
      let callerProduct = tableProduct;
      if (caller.type === "app" && grantPrd !== undefined && grantPrd !== tableProduct) {
        callerProduct = undefined;
        ctx.log.warn("bridge.hooks.caller_product_mismatch", { ins: caller.ins, tableProduct: tableProduct ?? null, grantProduct: grantPrd, detail: `${tableProduct ?? "-"}|${grantPrd}` });
      }
      const callInfo = {
        id: call,
        ws: t0.ws,
        caller:
          caller.type === "agent"
            ? { type: "agent" as const, id: caller.agt, ...(t0.agents.get(caller.agt) ? { mode: t0.agents.get(caller.agt)?.mode } : {}) }
            : // never from input, a header or a manifest name; an instance the table cannot map carries none (see above)
              { type: "app" as const, id: caller.ins, ...(callerProduct ? { product: callerProduct } : {}) },
        target: {
          instance: target.app.entry.ins,
          product: target.app.entry.product,
          op: op.id,
          // spec 0.1.68 (C336 RQ-2, BRIDGE §8.2, cap `hook_tool`): a dynamic call (listed entry, `<op>_call`, relay dynamic
          // call) carries the resolution's canonical tool; crud/effect/holdFamily below are that resolution (effectiveOp).
          // Absent for static ops (dynamic search never routes a call here).
          ...(resolvedTool ? { tool: resolvedTool } : {}),
          crud: op.crud,
          effect: op.effect,
          ...(!op.standard && op.holdFamily ? { holdFamily: op.holdFamily } : {}),
        },
        input: req.input as JsonValue,
      };
      // the caller's keys first (v0.1.77, §8.5), then the bridge's reserved `tb.*` keys: the two sets never overlap (a caller key
      // is `<product>.…` and `tb.` is refused), the order only states who owns a collision. Hooks and the app see both, and the
      // op proof's `ctx` digest covers them.
      let context: JsonObject = { ...(callerKeys ?? {}), ...(req.reservedContext ?? {}) };
      // 6. before hooks (fail closed). v0.1.13: answers allow | refuse | hold, shape-checked and reduced by the shared
      // rule (manifest hookResponseProblem + reduceBeforeChain): the first refuse stops the chain at once; else the
      // FIRST hold is kept and the remaining hooks still run (a later refuse wins). Runs for every call, a retry
      // after an approval included (C82): a hook that now refuses refuses the retry.
      // C117: a declared hook missing from the config refuses the call before any hook runs or anything is forwarded
      this.requireListedHooks(t0, target, op);
      active.inHook = true;
      const answers: { by: string; answer: { allow: boolean; reason?: string; hold?: { family: string; reason: string } } }[] = [];
      for (const h of this.matchingHooks(t0, "before", target, op)) {
        let r: BeforeHookResponse;
        try {
          r = await this.callHook<BeforeHookResponse>(t0, h, call, { phase: "before", call: callInfo, context }, callerRef, req.input);
        } catch (e) {
          throw new BridgeError("hook_failed", 503, `hook ${h.id} ${e instanceof HookBadAnswer ? "bad answer" : "failed"}`);
        }
        const answer = r as unknown as { allow: boolean; reason?: string; hold?: { family: string; reason: string } };
        answers.push({ by: `${h.product}/${h.hookId}`, answer });
        if (!answer.allow && !answer.hold) break;
      }
      const chain = ctx.api.reduceBeforeChain(answers);
      if (chain.kind === "refuse") throw new BridgeError("hook_denied", 403, chain.reason ? chain.reason.slice(0, 200) : `denied by ${chain.by}`);
      const hv = chain.kind === "hold" ? ctx.api.holdVerdictClaim(chain) : undefined;
      // 7. context hooks (namespaced additions; never `tb.*`, the shared rule checks both)
      for (const h of this.matchingHooks(t0, "context", target, op)) {
        let r: ContextHookResponse;
        try {
          r = await this.callHook<ContextHookResponse>(t0, h, call, { phase: "context", call: callInfo, context }, callerRef, req.input);
        } catch (e) {
          throw new BridgeError("hook_failed", 503, `hook ${h.id} ${e instanceof HookBadAnswer ? "bad answer" : "failed"}`);
        }
        for (const [k, val] of Object.entries((r as { add: Record<string, unknown> }).add)) {
          // §8.5 (G4b): `tb.*` is the bridge's namespace (also enforced here, defence in depth)
          if (k.startsWith("tb.") || !k.startsWith(`${h.product}.`)) throw new BridgeError("hook_failed", 503, `hook ${h.id} wrote outside its namespace`);
          context = { ...context, [k]: val as JsonValue };
        }
      }
      active.inHook = false;
      // 8. config age; 9. re-gate on the current table (a pause applied during hooks wins)
      if (ctx.configExpired()) throw new BridgeError("config_expired", 503);
      const t1 = ctx.table ?? t0;
      const target1 = t1 === t0 ? target : { ...target, app: t1.apps.get(target.app.entry.ins) ?? target.app };
      const grant1 = t1 === t0 ? grant : this.selectGrant(t1, caller, target.app.entry.ins);
      this.runGate(t1, caller, target1, op, grant1);
      // BRG-09 (C117, L33): the after hooks come from t1, so t1 must list every declared matching hook too. A config
      // swap during the before/context hooks that drops a declared hook refuses the call here, before it is forwarded
      // (always run: a manifest fetched during the hooks can add declared hooks to the same table).
      this.requireListedHooks(t1, target1, op);
      // 10. forward
      const result = await this.forward(t1, call, callerRef, target1, op.id, grant1, req, context, hv);
      // 12. after hooks (ok only). spec 0.1.68: never for a secretOutput op — the result goes to the caller only
      if (result.status === "ok" && !isSecretOutputOp(target1.op)) {
        let output: JsonValue = result.output;
        active.inHook = true;
        for (const h of this.matchingHooks(t1, "after", target1, op)) {
          let r: AfterHookResponse;
          try {
            r = await this.callHook<AfterHookResponse>(t1, h, call, { phase: "after", call: callInfo, context, output }, callerRef, req.input);
          } catch {
            void this.bridgeOp(target1.app, "mark", { call, mark: "after_failed" }).catch(() => undefined);
            throw new BridgeError("after_failed", 503, `after hook ${h.id} failed; output withheld`);
          }
          if (r.output !== undefined) output = r.output as JsonValue;
          if (Array.isArray(r.redactions)) output = redact(output, r.redactions);
        }
        active.inHook = false;
        return { call, result: { ...result, output: output as JsonValue } };
      }
      return { call, result };
    } catch (e) {
      code = e instanceof BridgeError ? e.code : "app_error";
      throw e;
    } finally {
      this.active.delete(call);
      this.count(`call|${target.app.entry.product}|${metricCode(code)}`);
      ctx.log.info(caller.type === "app" && !req.parentCall ? "call.app_initiated" : "bridge.call", {
        call,
        ...(caller.type === "agent" ? { agt: caller.agt } : { ins: caller.ins, parentCall: req.parentCall ?? null }),
        product: target.app.entry.product,
        op: target.op.id,
        decision: code === "ok" ? "forwarded" : "refused",
        code,
        ms: Date.now() - started,
        inDigest: safeDigest(ctx, req.input),
      });
    }
  }

  private async forward(t: Table, call: CallId, callerRef: string, target: Target, opId: string, grant: string, req: CallRequest, context: JsonObject, hv?: { f: string; r: string; by: string }): Promise<CallOutcome> {
    const id = this.ctx.identity;
    if (!id) throw new BridgeError("app_unavailable", 503);
    const grantClaims = t.grants.get(grantKey(callerRef, insRef(target.app.entry.ins)))?.claims;
    const gjti = grantClaims?.jti ?? peekJti(grant);
    const input = req.input;
    const now = nowS();
    const proof = await this.ctx.api.signJws(
      TYP.callProof,
      {
        iss: this.ctx.bridgeRef,
        sub: callerRef,
        aud: insRef(target.app.entry.ins),
        iat: now,
        exp: now + LIFETIME_S.proof,
        jti: this.ctx.api.ulid(),
        call,
        gjti,
        op: opId,
        in: this.ctx.api.digest(input),
        ctx: this.ctx.api.digest(context as Json),
        // v0.1.13 (G1): a kept before-hook hold verdict; the APP decides the hold (authorize), never the bridge
        ...(hv ? { hv } : {}),
      },
      id.key,
    );
    // spec 0.1.68: a secretOutput op is never replayed from a stored result; no key reaches the app (M-OP-11: idempotency none)
    const idempotencyKey = isSecretOutputOp(target.op) ? undefined : req.idempotencyKey;
    const body = JSON.stringify({ input, context, ...(idempotencyKey ? { idempotencyKey } : {}) });
    const url = new URL(`/tb/v1/ops/${opId}`, target.app.entry.internalUrl);
    const send = () =>
      this.ctx.fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${grant}`, "TB-Call": proof },
        body,
        redirect: "error",
        signal: AbortSignal.any([...(req.signal ? [req.signal] : []), this.shutdown.signal, AbortSignal.timeout(APP_TIMEOUT_MS)]),
      });
    let res: Response;
    try {
      if (this.shutdown.signal.aborted) throw new BridgeError("app_unavailable", 503, CUT_OFF);
      res = await send();
    } catch (e) {
      if (e instanceof BridgeError) throw e;
      if (this.shutdown.signal.aborted) throw new BridgeError("app_unavailable", 503, CUT_OFF);
      if (isTimeout(e)) throw new BridgeError("app_timeout", 504);
      // one retry only if the connection failed before any byte was sent
      if (!isPreConnect(e)) throw new BridgeError("app_unavailable", 503);
      try {
        res = await send();
      } catch (e2) {
        throw new BridgeError(isTimeout(e2) ? "app_timeout" : "app_unavailable", isTimeout(e2) ? 504 : 503);
      }
    }
    let text: string;
    try {
      text = (await readCapped(res, MAX_RESULT_BYTES)).toString("utf8");
    } catch (e) {
      if (e instanceof BridgeError) throw e;
      if (this.shutdown.signal.aborted) throw new BridgeError("app_unavailable", 503, CUT_OFF);
      throw new BridgeError(isTimeout(e) ? "app_timeout" : "app_unavailable", isTimeout(e) ? 504 : 503);
    }
    let parsed: unknown;
    try {
      parsed = text ? JSON.parse(text) : undefined;
    } catch {
      throw new BridgeError("app_error", 502, "app answered non-JSON");
    }
    // after-hooks digest and redact the output recursively: refuse absurd nesting before they see it (C62)
    if (tooDeep(parsed)) throw new BridgeError("app_error", 502, "app answer nested too deep");
    if (res.status === 200 && isRecord(parsed) && parsed.status === "ok") return parsed as CallOutcome;
    if (res.status === 202 && isRecord(parsed) && parsed.status === "held" && typeof parsed.holdId === "string") return parsed as CallOutcome;
    if (isRecord(parsed) && isRecord(parsed.error) && typeof parsed.error.code === "string") {
      // app-side codes pass through, but never as a bridge verdict, never malformed (H-7)
      const code = appErrorCode(parsed.error.code);
      throw new BridgeError(code, Math.min(599, Math.max(400, res.status)), appErrorMessage(parsed.error.message, code));
    }
    throw new BridgeError("app_error", 502, `app answered ${res.status}`);
  }
}

function peekJti(token: string): string {
  try {
    const p = JSON.parse(Buffer.from(token.split(".")[1] ?? "", "base64url").toString("utf8")) as { jti?: string };
    return p.jti ?? "";
  } catch {
    return "";
  }
}

function safeDigest(ctx: BridgeContext, v: Json): string | undefined {
  try {
    return ctx.api.digest(v);
  } catch {
    return undefined;
  }
}

const isTimeout = (e: unknown) => e instanceof Error && (e.name === "TimeoutError" || e.name === "AbortError");
const PRE_CONNECT = new Set(["ECONNREFUSED", "ENOTFOUND", "EAI_AGAIN", "ENETUNREACH", "EHOSTUNREACH", "UND_ERR_CONNECT_TIMEOUT"]);
function isPreConnect(e: unknown): boolean {
  const cause = (e as { cause?: { code?: string } })?.cause;
  return !!cause?.code && PRE_CONNECT.has(cause.code);
}

const UNSAFE_SEGMENTS: ReadonlySet<string> = new Set(["__proto__", "constructor", "prototype"]);

/**
 * Removes the members named by RFC 6901 pointers (after-hook `redactions`). Steps only through own
 * properties and never through `__proto__`/`constructor`/`prototype`, so a pointer cannot reach a shared
 * prototype (BSD-06).
 */
export function redact(value: JsonValue, pointers: readonly unknown[]): JsonValue {
  const copy = structuredClone(value);
  for (const p of pointers) {
    if (typeof p !== "string" || !p.startsWith("/")) continue;
    const parts = p.slice(1).split("/").map((s) => s.replace(/~1/g, "/").replace(/~0/g, "~"));
    if (parts.some((part) => UNSAFE_SEGMENTS.has(part))) continue;
    let node: unknown = copy;
    for (let i = 0; i < parts.length - 1 && node !== undefined; i++) {
      const part = parts[i] as string;
      node = (isRecord(node) || Array.isArray(node)) && Object.hasOwn(node, part) ? (node as Record<string, unknown>)[part] : undefined;
    }
    const last = parts.at(-1) as string;
    if (Array.isArray(node)) {
      const i = Number(last);
      if (Number.isInteger(i) && i >= 0 && i < node.length && String(i) === last) node.splice(i, 1);
    } else if (isRecord(node) && Object.hasOwn(node, last)) delete node[last];
  }
  return copy;
}

/** Companion grants in an instance's current slice (K9 `grants`); undefined when the bridge holds no readable slice. */
export function sliceGrants(app: AppRuntime | undefined): string[] | undefined {
  const payload = app?.entry.slice?.split(".")[1];
  if (!payload) return undefined;
  try {
    const p = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as { grants?: unknown };
    return Array.isArray(p.grants) ? p.grants.filter((g): g is string => typeof g === "string") : undefined;
  } catch {
    return undefined;
  }
}
