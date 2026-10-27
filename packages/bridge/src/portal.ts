/**
 * Outbound-only link to Portal Core (BRIDGE §4–§5): enrolment, signed config long-poll, status report.
 * Every request after enrolment carries a bridge assertion (`TB-Assert`, typ tb-bridge-assert+jwt).
 * Portal never connects in.
 */

import { isRefusal, MCP_VERSIONS, SDK_MAJORS } from "@opt2-tealbrick/relay";
import type { AppEntry, EnrolRequest, EnrolResponse, StatusReport, WorkspaceConfig } from "@opt2-tealbrick/spec/bridge";
import { type ConnectionId, LIFETIME_S, type PortalKeyEntry, TYP } from "@opt2-tealbrick/spec/credentials";
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import type { Json } from "@opt2-tealbrick/spec/sdk";
import { bridgeCaps, missingBridgeCap } from "./caps.ts";
import { BRIDGE_VERSION, type BridgeContext } from "./context.ts";
import { roleStatuses } from "./model-roles.ts";
import { remintStandalone } from "./standalone.ts";
import { upgradeFields } from "./status-fields.ts";
import { acceptedDigests, buildTable, internalUrlAllowed, keyRequirements, type Table } from "./table.ts";
import { BridgeError, isRecord, jitter, nowS, sleep } from "./util.ts";

const API = "/api/v1";
const MAX_CONFIG_BYTES = 4 * 1024 * 1024;
/** Pause between pulls after a refused config document (tight-loop guard). */
export const REFUSED_PULL_DELAY_MS = 5_000;
/** Minimum spacing of config pulls (BSD-09); a long-poll normally takes up to 60 s anyway. */
export const MIN_PULL_INTERVAL_MS = 5_000;
/** StatusReport.connectionsSeen cap (spec 0.1.14) */
export const MAX_CONNECTIONS_SEEN = 500;

/** BRIDGE §4.1: first start, or re-enrolment when TB_ENROL_CODE changed (§4.3). */
export async function ensureEnrolled(ctx: BridgeContext, enrolCode: string | undefined): Promise<void> {
  const existing = await ctx.state.loadIdentity();
  const codeDigest = enrolCode ? ctx.api.opaqueDigest(enrolCode) : undefined;
  if (existing && (!codeDigest || ctx.api.digestEqual(codeDigest, existing.enrolCodeDigest))) {
    ctx.identity = existing;
    return;
  }
  if (!enrolCode || !codeDigest) throw new BridgeError("not_enrolled", 500, "TB_ENROL_CODE is required for the first start");
  // C63a: a code whose re-enrolment the key-set rule refused is not tried again on every restart (Core used it)
  const refused = existing ? ctx.state.loadRefusedEnrolCode() : undefined;
  if (existing && refused && ctx.api.digestEqual(refused, codeDigest)) {
    ctx.identity = existing;
    ctx.reject({ kind: "config", code: "keyset_refused_enrolment", detail: "TB_ENROL_CODE was refused before; running under the pinned identity" });
    return;
  }
  const key = await ctx.api.generateKeyPair();
  const body: EnrolRequest = {
    code: enrolCode,
    publicKey: key.publicJwk,
    version: BRIDGE_VERSION,
    sdkMajors: SDK_MAJORS,
    form: ctx.form,
    publicOrigin: ctx.publicUrl,
  };
  const res = await ctx.fetch(new URL(`${API}/bridge/enrol`, ctx.portalUrl), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
    redirect: "error",
    signal: AbortSignal.timeout(30_000),
  });
  if (!res.ok) throw new BridgeError("enrol_failed", 502, `Portal refused enrolment (${res.status})`);
  const r = (await res.json()) as EnrolResponse;
  if (!r || typeof r.bridgeId !== "string" || typeof r.workspaceId !== "string" || !Array.isArray(r.portalKeys)) {
    throw new BridgeError("enrol_failed", 502, "malformed enrolment response");
  }
  if (existing && existing.bridgeId !== r.bridgeId) throw new BridgeError("enrol_failed", 502, "Portal returned another bridge id");
  // BSD-08 (BRIDGE §4.1/§4.3, CREDENTIALS §9.5): the response's key-set statement is checked against the build's
  // roots and the pinned statement BEFORE anything is written. A refused re-enrolment keeps S1 (key, identity, pin).
  const trust = ctx.api.trustedPortalKeys(r, existing?.pinnedKeySet ?? null, ctx.portalRoots);
  if (isRefusal(trust)) {
    ctx.reject({ kind: "config", code: trust.code, detail: `${existing ? "re-enrolment" : "enrolment"} refused: ${trust.reason}` });
    ctx.log.error("bridge.enrol.keyset_refused", { code: trust.code, reenrol: !!existing });
    if (!existing) throw new BridgeError("enrol_failed", 502, `enrolment refused: ${trust.code}`);
    ctx.state.saveRefusedEnrolCode(codeDigest);
    ctx.identity = existing;
    return;
  }
  ctx.identity = {
    bridgeId: r.bridgeId,
    workspaceId: r.workspaceId,
    key,
    portalKeys: statementKeys(trust.kss),
    pinnedKeySet: { seq: trust.seq, kss: trust.kss },
    enrolCodeDigest: codeDigest,
    configPath: r.configPath,
    ackPath: r.ackPath,
  };
  await ctx.state.saveIdentity(ctx.identity);
  ctx.log.info("bridge.enrolled", { bridge: r.bridgeId, ws: r.workspaceId, reenrol: !!existing, keySetSeq: trust.seq });
}

/** `keys` of a statement that `trustedPortalKeys` already verified (CREDENTIALS §9.5): the trusted set as S1 entries. */
export function statementKeys(kss: string): PortalKeyEntry[] {
  const claims = JSON.parse(Buffer.from(kss.split(".")[1] ?? "", "base64url").toString("utf8")) as { keys: PortalKeyEntry[] };
  return claims.keys.map((k) => ({ jwk: k.jwk, status: k.status }));
}

async function portalRequest(ctx: BridgeContext, method: "GET" | "POST", pathAndQuery: string, body?: unknown, timeoutMs = 30_000, abort?: AbortSignal): Promise<Response> {
  const id = ctx.identity;
  if (!id) throw new BridgeError("not_enrolled", 500);
  const raw = body === undefined ? undefined : Buffer.from(JSON.stringify(body), "utf8");
  const now = nowS();
  const ref = ctx.bridgeRef;
  const assertion = await ctx.api.signAssertion(
    TYP.bridgeAssertion,
    { iss: ref, sub: ref, aud: "tb:portal", iat: now, exp: now + LIFETIME_S.proof, jti: ctx.api.ulid() },
    id.key,
    { method, pathAndQuery, ...(raw ? { body: raw } : {}) },
  );
  return ctx.fetch(new URL(pathAndQuery, ctx.portalUrl), {
    method,
    headers: { "TB-Assert": assertion, ...(raw ? { "content-type": "application/json" } : {}) },
    ...(raw ? { body: raw } : {}),
    redirect: "error",
    signal: abort ? AbortSignal.any([abort, AbortSignal.timeout(timeoutMs)]) : AbortSignal.timeout(timeoutMs),
  });
}

/**
 * C57: an app whose manifest could not be fetched during a config apply (e.g. restarting after an update) is
 * retried in the background with backoff (2 s → 60 s), independent of config revisions. A new manifestDigest in
 * a later config is a new retry key (refetch). On success the runtime entry in the CURRENT table is filled in
 * place and listeners are told (MCP tool lists refresh, list_changed).
 */
export function startManifestRetry(ctx: BridgeContext, signal: AbortSignal): void {
  const attempts = new Map<string, { at: number; delay: number }>();
  let running = false;
  const tick = async () => {
    const t = ctx.table;
    if (!t || signal.aborted || running) return;
    running = true;
    let fixed = false;
    try {
      for (const app of t.apps.values()) {
        if (!app.down || app.refused) continue;
        // G2b: the candidate digest is part of the key (a new candidate in a later config is a new key, refetch)
        const accepted = acceptedDigests(app.entry);
        const key = `${app.entry.ins}|${accepted.join("|")}`;
        const a = attempts.get(key) ?? { at: 0, delay: 2_000 };
        if (Date.now() < a.at) continue;
        try {
          const m = await fetchManifestFrom(ctx, app.entry);
          const got = ctx.api.manifestDigest(m);
          if (!accepted.includes(got)) throw new ManifestError("manifest_mismatch", got);
          app.manifest = m;
          app.digest = got;
          app.ops = new Map(ctx.api.withStandardOps(m).map((op) => [op.id, op]));
          app.scopeTypes = (m.scopes ?? []).map((sc) => sc.type);
          app.declaredHooks = m.hooks ?? [];
          app.down = false;
          attempts.delete(key);
          fixed = true;
          ctx.log.info("bridge.manifest.recovered", { ins: app.entry.ins });
        } catch (e) {
          const next = Math.min(a.delay * 2, 60_000);
          attempts.set(key, { at: Date.now() + a.delay, delay: next });
          logManifestFailure(ctx, app.entry, e);
        }
      }
    } finally {
      running = false;
    }
    if (fixed && ctx.table === t) ctx.emit("table", t, t);
  };
  const timer = setInterval(() => void tick(), 1_000);
  timer.unref();
  signal.addEventListener("abort", () => clearInterval(timer));
}

export class ManifestError extends Error {
  readonly served: string | undefined;
  /** extra reason detail for the rejection log line (e.g. the missing bridge cap); ids and codes only */
  readonly detail: string | undefined;
  constructor(code: string, served?: string, detail?: string) {
    super(code);
    this.served = served;
    this.detail = detail;
  }
}

/** One line per app + reason per minute: fetch failure vs digest mismatch (with both digests — public values). */
export function logManifestFailure(ctx: BridgeContext, app: AppEntry, e: unknown): void {
  const mismatch = e instanceof ManifestError && e.message === "manifest_mismatch";
  // v0.1.18 (spec 0.1.17, L3, C104): a manifest the bridge REFUSED is reported (Core shows the reason instead of "starting");
  // a transient fetch failure (HTTP status, network) is not a refusal
  if (e instanceof ManifestError && !e.message.startsWith("fetch_")) ctx.reject({ kind: "manifest", code: e.message, ins: app.ins, detail: e.detail ? `${app.product}: ${e.detail}` : app.product });
  ctx.log.warn("bridge.manifest.unavailable", {
    ins: app.ins,
    product: app.product,
    code: mismatch ? "manifest_mismatch" : e instanceof ManifestError ? e.message : "fetch_failed",
    expected: app.manifestDigest,
    ...(acceptedDigests(app).length > 1 ? { expectedCandidate: acceptedDigests(app)[1] } : {}),
    ...(mismatch ? { served: (e as ManifestError).served } : {}),
  });
}

export async function fetchManifestFrom(ctx: BridgeContext, app: AppEntry): Promise<Manifest> {
  const res = await ctx.fetch(new URL("/tb/v1/manifest", app.internalUrl), { redirect: "error", signal: AbortSignal.timeout(10_000) });
  if (!res.ok) throw new ManifestError(`fetch_http_${res.status}`);
  const v = ctx.api.validateManifest(await res.json());
  // the validator's own code (e.g. dynamic_invalid), so Core can say why (L3)
  if (!v.ok) throw new ManifestError(v.errors[0]?.code ?? "manifest_invalid");
  // C104: an app that needs a newer bridge is refused here, never routed half-working
  const need = ctx.api.requiredBridgeVersion(v.manifest).bridge;
  if (need && ctx.api.compareSemver(need, BRIDGE_VERSION) > 0) throw new ManifestError("bridge_too_old");
  // spec 0.1.68 (C354): an app whose requires.bridgeCaps (or a feature it uses) names a cap this bridge does not declare is
  // refused here, before it is routed (Core refuses such a deploy too; this is the bridge's own check)
  const missing = missingBridgeCap(v.manifest, ctx.api);
  if (missing) throw new ManifestError("bridge_cap_missing", undefined, `missing bridge cap ${missing}`);
  return v.manifest;
}

/**
 * BRIDGE §5.2 + §5.3: verify a config JWS and swap the routing table. Returns false when the document
 * is dropped (S2 kept). Used for pulled configs and for the S2 reload at boot (`boot: true` allows
 * equal rev and an expired document, which then fails closed per §5.4).
 */
export async function applyConfig(ctx: BridgeContext, jws: string, opts: { boot?: boolean } = {}): Promise<boolean> {
  const id = ctx.identity;
  if (!id) return false;
  const now = nowS();
  if (Buffer.byteLength(jws) > MAX_CONFIG_BYTES) {
    ctx.reject({ kind: "config", code: "payload_too_large" });
    return false;
  }
  // BSD-08 first (BRIDGE §5.2): the key-set rule on the body's `portalKeySet` against the pin. The statement is
  // self-authenticating, so it is read before the document signature and the document is verified with its set.
  const peeked = peekBody(jws);
  const trust = ctx.api.trustedPortalKeys(isRecord(peeked) ? peeked : {}, id.pinnedKeySet ?? null, ctx.portalRoots);
  if (isRefusal(trust)) {
    ctx.reject({ kind: "config", code: trust.code, detail: `${trust.reason}; rev ${peekRev(jws)}${opts.boot ? "; boot copy refused" : ""}` });
    return false;
  }
  // only `active` / `pending` keys of the statement may sign a config; grants, tickets and codes use every key
  const issuers = trust.signers;
  // BSD-03: the boot copy (S2 on the volume) is verified with the TRUSTED set like any pulled document; the ONLY
  // waived check is time (an S2 older than 12 h still loads, and then fails closed for calls, §5.4). A document
  // that fails any other check (signature, unknown kid, audience, workspace) is not loaded at all.
  const peekedExp = (peekBody(jws) as { exp?: unknown } | undefined)?.exp;
  const verifyNow = opts.boot && typeof peekedExp === "number" ? Math.min(now, peekedExp - 1) : now;
  const v = ctx.api.verifyConfig(jws, { now: verifyNow, self: ctx.bridgeRef, issuers });
  if (isRefusal(v)) {
    ctx.reject({ kind: "config", code: v.code, detail: `${v.reason}; rev ${peekRev(jws)}; trusted ${issuers.keys.length}${opts.boot ? "; boot copy refused" : ""}` });
    return false;
  }
  const body = v.body as WorkspaceConfig | undefined;
  if (!body || !isRecord(body)) return false;
  const current = ctx.table?.rev ?? -1;
  if (body.v !== 1 || body.ws !== id.workspaceId || body.sub !== ctx.bridgeRef || body.aud !== ctx.bridgeRef) {
    ctx.reject({ kind: "config", code: "config_mismatch" });
    return false;
  }
  if (!opts.boot && body.rev <= current) {
    if (body.rev < current) ctx.reject({ kind: "config", code: "rev_lower" });
    return false;
  }
  if (!opts.boot && body.exp <= now) {
    ctx.reject({ kind: "config", code: "config_expired" });
    return false;
  }
  // the trusted set is the verified statement's `keys`; the body's `portalKeys` never replaces it (§5.3, C133)
  const nextKeys = statementKeys(trust.kss);
  const table: Table = await buildTable({
    api: ctx.api,
    config: body,
    jws,
    bridgeId: id.bridgeId,
    ownKeys: ctx.ownKeySet(),
    issuers: trust.keys,
    previous: ctx.table,
    fetchManifest: (app) => fetchManifestFrom(ctx, app),
    internalUrlAllowed: (e) => internalUrlAllowed(ctx.api, e.internalUrl, e.ownInfra === true, ctx.ownInfraOrigins),
    onManifestFailure: (app, e) => logManifestFailure(ctx, app, e),
    now,
    reject: (r) => ctx.reject(r),
  });
  if (!opts.boot) ctx.state.saveConfigJws(jws);
  if (trust.changed) {
    // the newer statement is pinned with the document it came with (S2 above, S1 here, sealed)
    id.pinnedKeySet = { seq: trust.seq, kss: trust.kss };
    id.portalKeys = nextKeys;
    await ctx.state.saveIdentity(id);
    ctx.log.info("bridge.keyset.pinned", { seq: trust.seq, keys: nextKeys.length });
  }
  reconcileConnections(ctx, table);
  ctx.swapTable(table);
  ctx.log.info("bridge.config.applied", { rev: body.rev, apps: body.apps.length, agents: body.agents.length, boot: !!opts.boot });
  // final Portal config with `standalone`: freeze it and become the issuer (BRIDGE §11)
  if (body.standalone) await remintStandalone(ctx);
  return true;
}

function peekRev(jws: string): number | undefined {
  const b = peekBody(jws) as { rev?: unknown } | undefined;
  return typeof b?.rev === "number" ? b.rev : undefined;
}

function peekBody(jws: string): unknown {
  const p = jws.split(".")[1];
  if (!p) return undefined;
  try {
    return JSON.parse(Buffer.from(p, "base64url").toString("utf8"));
  } catch {
    return undefined;
  }
}

/**
 * S4 housekeeping after a new config (BRIDGE §5.3, §6): mark locally created pairing connections that
 * the config now lists; drop those the config revoked; drop reported ones Core refused (a config issued
 * after the report omits them).
 */
function reconcileConnections(ctx: BridgeContext, table: Table): void {
  let changed = false;
  for (const [con, rec] of ctx.state.connections) {
    const listed = table.connections.get(con);
    const agentGone = !table.agents.has(rec.agt);
    if ((listed && listed.status === "revoked") || agentGone) {
      ctx.state.connections.delete(con);
      changed = true;
      continue;
    }
    if (listed && !rec.reported) {
      rec.reported = true;
      changed = true;
      if (ctx.state.reports.pairingJtis[con] !== undefined) {
        delete ctx.state.reports.pairingJtis[con];
        ctx.state.saveReports();
      }
      continue;
    }
    const reportedAt = reportedAtS.get(con);
    if (!listed && rec.reported) {
      ctx.state.connections.delete(con);
      changed = true;
    } else if (!listed && reportedAt !== undefined && table.config.iat > reportedAt) {
      ctx.state.connections.delete(con);
      changed = true;
    }
  }
  if (changed) ctx.state.saveConnections();
  // pending claims Core now lists in instanceKeys are cleared
  const before = ctx.state.claims.length;
  ctx.state.claims = ctx.state.claims.filter((c) => !table.instanceKeys.has(`${c.ins}|${c.service ?? ""}`));
  if (ctx.state.claims.length !== before) ctx.state.saveClaims();
}

/** LA-1: the tb-views probe is bounded (BRIDGE §9.2): a slow viewer service is a "not ok", never a stuck report. */
const VIEWS_PROBE_TIMEOUT_MS = 3_000;
/** between reports the probe runs this often, so a viewer service that breaks (or heals) reaches Portal promptly */
const VIEWS_PROBE_EVERY_MS = 60_000;

/**
 * LA-1 / L3: probes the workspace views service (`TB_VIEWS_PUBLIC_URL` + `/readyz`) and records ok / not ok with the check
 * time. A broken viewer is a health signal for Core, not silence. No views service → nothing. Returns true when `ok` changed since the previous probe.
 */
export async function probeViews(ctx: BridgeContext): Promise<boolean> {
  if (!ctx.viewsUrl) return false;
  const was = ctx.views?.ok;
  let ok = false;
  try {
    const r = await ctx.fetch(new URL("/readyz", ctx.viewsUrl), { redirect: "error", signal: AbortSignal.timeout(VIEWS_PROBE_TIMEOUT_MS) });
    ok = r.status === 200;
    await r.body?.cancel().catch(() => undefined);
  } catch {
    ok = false;
  }
  ctx.views = { ok, lastCheckAt: new Date().toISOString() };
  if (was !== undefined && was !== ok) ctx.log.warn("bridge.views.health_changed", { ok });
  return was !== undefined && was !== ok;
}

/** con → epoch s of the status report that first carried it (memory; re-reported after restart). */
const reportedAtS = new Map<string, number>();

/** BRIDGE §5.6. */
/** Core reads an ack body up to 256 KiB; the bridge keeps its report below this (QA bridge#26 S2: one app pushed 443 KB). */
export const STATUS_REPORT_MAX_BYTES = 240 * 1024;
/** per app, after the first cuts: at most this many omitted tools and scope summaries are reported */
export const REPORT_PER_APP_MAX = 50;
/** QA bridge#26 round 2: an app's `attention.reason` is shortened to this many code points when the report is too large */
export const REPORT_ATTENTION_MAX = 500;

const jsonBytes = (v: unknown): number => Buffer.byteLength(JSON.stringify(v), "utf8");
type ReportApp = StatusReport["apps"][number];
type ScopeRow = StatusReport["scopeSummaries"][number] & { sources?: unknown[] };

/**
 * Keeps a status report under STATUS_REPORT_MAX_BYTES. Only what apps can grow is cut, cheapest display data first and always
 * from the app that grew most first: (1) `sources` of the scope summaries, app by app (heaviest first); (2) `attention.reason`
 * shortened to REPORT_ATTENTION_MAX code points, app by app; (3) omitted tools, then scope summaries, to REPORT_PER_APP_MAX per
 * app; (4) all omitted tools, then all scope summaries; (5) `attention` itself. Each cut adds one marker per app in `rejected`
 * (kind `bridge_op`, code `report_truncated_sources` | `_attention` | `_tools` | `_scopes`, count = items cut), so Core and the
 * owner see that the report is incomplete. A report already small enough is returned unchanged (the same object).
 */
export function boundStatusReport(report: StatusReport, maxBytes = STATUS_REPORT_MAX_BYTES): StatusReport {
  let r = report;
  const fits = () => jsonBytes(r) <= maxBytes;
  if (fits()) return r;
  const mark = (code: string, ins: string, count: number) => {
    if (count > 0) r = { ...r, rejected: [...r.rejected, { kind: "bridge_op", code, count, ins: ins as never }] };
  };
  const heaviest = (weights: Map<string, number>) => [...weights.entries()].filter(([, w]) => w > 0).sort((a, b) => b[1] - a[1]);
  // (1) sources, from the app with the most bytes of them
  const sourceBytes = new Map<string, number>();
  for (const s of r.scopeSummaries as ScopeRow[]) if (s.sources?.length) sourceBytes.set(s.ins, (sourceBytes.get(s.ins) ?? 0) + jsonBytes(s.sources));
  for (const [ins] of heaviest(sourceBytes)) {
    const rows = r.scopeSummaries as ScopeRow[];
    const cut = rows.filter((s) => s.ins === ins && s.sources?.length).length;
    r = { ...r, scopeSummaries: rows.map((s) => (s.ins === ins ? (({ sources: _x, ...rest }: ScopeRow) => rest)(s) : s)) };
    mark("report_truncated_sources", ins, cut);
    if (fits()) return r;
  }
  // (2) attention reasons, from the longest
  const attentionBytes = new Map<string, number>(r.apps.filter((a) => a.attention).map((a) => [a.ins, jsonBytes(a.attention)]));
  for (const [ins] of heaviest(attentionBytes)) {
    const app = r.apps.find((a) => a.ins === ins);
    const reason = (app?.attention as { reason?: unknown } | undefined)?.reason;
    if (!app?.attention || typeof reason !== "string" || Array.from(reason).length <= REPORT_ATTENTION_MAX) continue;
    const short = Array.from(reason.toWellFormed()).slice(0, REPORT_ATTENTION_MAX).join("");
    r = { ...r, apps: r.apps.map((a): ReportApp => (a.ins === ins ? { ...a, attention: { ...(a.attention as object), reason: short } as ReportApp["attention"] } : a)) };
    mark("report_truncated_attention", ins, 1);
    if (fits()) return r;
  }
  // (3) per app caps
  const capPerApp = <T extends { ins: string }>(items: T[], code: string): T[] => {
    const seen = new Map<string, number>();
    const kept = items.filter((i) => {
      const n = (seen.get(i.ins) ?? 0) + 1;
      seen.set(i.ins, n);
      return n <= REPORT_PER_APP_MAX;
    });
    for (const [ins, n] of seen) mark(code, ins, n - REPORT_PER_APP_MAX);
    return kept;
  };
  // capPerApp adds markers to `r`: take the kept list first, then build on the updated `r`
  const keptTools = capPerApp(r.toolsOmitted, "report_truncated_tools");
  r = { ...r, toolsOmitted: keptTools };
  if (fits()) return r;
  const keptScopes = capPerApp(r.scopeSummaries, "report_truncated_scopes");
  r = { ...r, scopeSummaries: keptScopes };
  if (fits()) return r;
  // (4) the lists whole
  const countBy = (items: { ins: string }[]) => items.reduce((m, i) => m.set(i.ins, (m.get(i.ins) ?? 0) + 1), new Map<string, number>());
  for (const [ins, n] of countBy(r.toolsOmitted)) mark("report_truncated_tools", ins, n);
  r = { ...r, toolsOmitted: [] };
  if (fits()) return r;
  for (const [ins, n] of countBy(r.scopeSummaries)) mark("report_truncated_scopes", ins, n);
  r = { ...r, scopeSummaries: [] };
  if (fits()) return r;
  // (5) attention itself
  for (const a of r.apps) if (a.attention) mark("report_truncated_attention", a.ins, 1);
  r = { ...r, apps: r.apps.map(({ attention: _a, ...a }) => a as ReportApp) };
  return r;
}

export function buildStatusReport(ctx: BridgeContext): StatusReport {
  const t = ctx.table;
  const id = ctx.identity;
  if (!id) throw new Error("not enrolled");
  const now = nowS();
  const apps: StatusReport["apps"] = (t ? [...t.apps.values()] : []).map((a) => {
    const h = ctx.health.get(a.entry.ins);
    const claimed = !!t?.instanceKeys.has(`${a.entry.ins}|`);
    const stale = !h || now - h.lastSeen > 150;
    const state: StatusReport["apps"][number]["state"] = t?.pausedInstances.has(a.entry.ins)
      ? "paused"
      : !claimed
        ? "unclaimed"
        : a.down || stale
          ? "down"
          : h.status.readiness === "needs_keys"
            ? "needs_keys"
            : h.status.readiness === "degraded"
              ? "degraded"
              : "ok";
    return {
      ins: a.entry.ins,
      state,
      version: h?.status.version ?? null,
      sdkVersion: h?.status.sdkVersion ?? null,
      // G2b: the digest of the manifest the service actually serves (the serving or the candidate digest)
      manifestDigest: a.manifest ? (a.digest ?? a.entry.manifestDigest) : null,
      lastSeen: h ? new Date(h.lastSeen * 1000).toISOString() : null,
      pendingHolds: h?.status.pendingHolds ?? 0,
      // the slice revision the app last reported it holds (AppStatus.sliceRevision); omitted before its first report
      ...(typeof h?.status.sliceRevision === "number" ? { sliceRevision: h.status.sliceRevision } : {}),
      // spec 0.1.28 (F89): AppStatus.attention as the app last reported it, copied unchanged; absent stays absent (L24)
      ...(isRecord(h?.status.attention) ? { attention: h.status.attention } : {}),
      // spec 0.1.39 (C213 US-2, miniapp-sdk 0.1.25): schemaVersion / minCompatibleCode / failure, shape-checked and copied
      // unchanged; absent or malformed stays absent (L24). Core's health-gated update and rollback read them.
      ...upgradeFields(h?.status),
    };
  });
  const keys = (t ? keyRequirements(t) : [])
    .filter((k) => k.source === "account_default")
    .map((k) => ({ name: k.name, ins: k.ins, set: Object.hasOwn(ctx.state.keyStore.values, k.name) }));
  const connectionsCreated = [...ctx.state.connections.values()]
    .filter((r) => !r.reported)
    .map((r) => {
      if (!reportedAtS.has(r.con)) reportedAtS.set(r.con, now);
      return { con: r.con, agt: r.agt, method: "pairing" as const, clientName: r.clientName, createdAt: new Date(r.createdAt * 1000).toISOString(), pairingJti: ctx.state.reports.pairingJtis[r.con] ?? "" };
    });
  return boundStatusReport({
    rev: t?.rev ?? 0,
    appliedAt: new Date().toISOString(),
    // spec 0.1.54 (C292): the capabilities this build implements, in EVERY report (caps.ts: only with the code they name)
    bridge: { id: id.bridgeId, version: BRIDGE_VERSION, form: ctx.form, boot: ctx.boot, sdkMajors: SDK_MAJORS, mcpVersions: MCP_VERSIONS, caps: bridgeCaps(ctx) },
    portalReachable: ctx.portalReachable(now),
    portalKeysDigest: ctx.api.digest(id.portalKeys as unknown as Json),
    apps,
    keys,
    // v0.1.63 (BRIDGE §15.5): one row per declared role per instance — labels only, never a base URL, key name or value
    roles: roleStatuses(ctx),
    scopeSummaries: [...ctx.scopeSummaries.values()],
    connectionsCreated,
    // v0.1.14: connections that authenticated since the previous ACCEPTED report (latest time each, ≤ 500)
    connectionsSeen: [...ctx.connectionsSeen.entries()].slice(-MAX_CONNECTIONS_SEEN).map(([con, ms]) => ({ con: con as ConnectionId, lastSeen: new Date(ms).toISOString() })),
    connectionsRevoked: [...ctx.state.reports.revoked],
    claims: ctx.state.claims.map(({ reported: _r, ...c }) => c),
    rejected: [...ctx.rejected.entries()].map(([k, count]) => {
      const [kind, code, ins] = k.split("|") as [StatusReport["rejected"][number]["kind"], string, string];
      return { kind, code, count, ...(ins ? { ins: ins as never } : {}) };
    }),
    toolsOmitted: [...ctx.toolsOmitted.values()],
    // spec 0.1.43 (LA-1): only when the workspace has a views service (TB_VIEWS_PUBLIC_URL); a probe has not run yet → not ok
    ...(ctx.viewsUrl ? { views: { url: ctx.viewsUrl, ok: ctx.views?.ok ?? false, lastCheckAt: ctx.views?.lastCheckAt ?? new Date(0).toISOString() } } : {}),
  });
}


export async function sendStatus(ctx: BridgeContext): Promise<boolean> {
  if (!ctx.identity || ctx.table?.standalone) return true;
  const report = buildStatusReport(ctx);
  try {
    const res = await portalRequest(ctx, "POST", ctx.identity.ackPath, report);
    if (res.ok) {
      // Portal recorded the revocations it was told about (BSD-11: kept on the volume until then)
      if (ctx.state.reports.revoked.length) {
        const sent = new Set(report.connectionsRevoked.map((r) => r.con));
        ctx.state.reports.revoked = ctx.state.reports.revoked.filter((r) => !sent.has(r.con));
        ctx.state.saveReports();
      }
      ctx.rejected.clear();
      // drop only what this report carried (a connection seen again meanwhile keeps its newer time)
      for (const c of report.connectionsSeen ?? []) if (ctx.connectionsSeen.get(c.con) === Date.parse(c.lastSeen)) ctx.connectionsSeen.delete(c.con);
    } else ctx.log.warn("bridge.status.failed", { code: `http_${res.status}` });
    await res.body?.cancel().catch(() => undefined);
    return res.ok;
  } catch {
    ctx.log.warn("bridge.status.failed", { code: "portal_unreachable" });
    return false;
  }
}

/** Debounced status sender: after each applied rev, on content change (2 s) and every 5 min (§5.6). */
export function startStatusLoop(ctx: BridgeContext, signal: AbortSignal): { poke(): void } {
  let timer: NodeJS.Timeout | undefined;
  let lastDigest = "";
  const fire = async () => {
    timer = undefined;
    if (signal.aborted || !ctx.identity) return;
    await probeViews(ctx);
    const r = buildStatusReport(ctx);
    const { appliedAt: _a, ...stable } = r;
    // the check time moves on every probe: only ok / not ok is content (it would defeat the "send on change" digest)
    if (stable.views) stable.views = { ...stable.views, lastCheckAt: "" };
    const d = ctx.api.digest(stable as never);
    if (d === lastDigest && !(ctx.state.reports.revoked.length || ctx.rejected.size)) return;
    lastDigest = d;
    if (await sendStatus(ctx)) {
      retryMs = 15_000;
      return;
    }
    // a report Portal did not receive is retried (revocations and claims must arrive, BSD-11)
    lastDigest = "";
    if (!timer && !signal.aborted) timer = setTimeout(fire, retryMs);
    retryMs = Math.min(retryMs * 2, 300_000);
  };
  let retryMs = 15_000;
  const poke = () => {
    if (!timer && !signal.aborted) timer = setTimeout(fire, 2_000);
  };
  // first report right after start (the boot config was applied before this loop listened)
  poke();
  const periodic = setInterval(() => {
    lastDigest = "";
    poke();
  }, 300_000);
  signal.addEventListener("abort", () => {
    clearInterval(periodic);
    if (timer) clearTimeout(timer);
  });
  ctx.on("table", poke);
  if (ctx.viewsUrl) {
    const probe = setInterval(() => void probeViews(ctx).then((changed) => changed && poke()), VIEWS_PROBE_EVERY_MS);
    probe.unref();
    signal.addEventListener("abort", () => clearInterval(probe));
  }
  return { poke };
}

/** A code for an apply failure (an fs errno or a BridgeError code, else the error class): never a message (BRIDGE §12). */
function applyErrorCode(e: unknown): string {
  const code = (e as { code?: unknown } | undefined)?.code;
  if (typeof code === "string" && /^[A-Za-z0-9_]{1,40}$/.test(code)) return code;
  return e instanceof Error ? e.name : "error";
}

/** BRIDGE §5.1: long-poll loop. Errors never extend or replace S2. */
export async function runConfigLoop(ctx: BridgeContext, signal: AbortSignal): Promise<void> {
  // error backoff: first retry after ~5 s (never below MIN_PULL_INTERVAL_MS, BSD-09), then doubling to 4 min. A
  // transient 401/network error right after a restart (e.g. a refused re-enrolment, C63a) recovers quickly.
  const FIRST_BACKOFF_MS = MIN_PULL_INTERVAL_MS;
  let backoff = FIRST_BACKOFF_MS;
  while (!signal.aborted) {
    if (ctx.table?.standalone) return;
    const id = ctx.identity;
    if (!id) return;
    const after = ctx.table?.rev ?? 0;
    const started = Date.now();
    // BSD-09: whatever the answer, never pull more than once per ~5 s (a Portal or proxy that ignores `wait`
    // would otherwise make every bridge loop signed requests at network speed)
    const pace = async () => {
      if (Date.now() - started < MIN_PULL_INTERVAL_MS) await sleep(jitter(MIN_PULL_INTERVAL_MS), signal);
    };
    try {
      const res = await portalRequest(ctx, "GET", `${id.configPath}?after=${after}&wait=60`, undefined, 75_000, signal);
      if (res.status === 304) {
        ctx.lastPull = nowS();
        backoff = FIRST_BACKOFF_MS;
        await pace();
        continue;
      }
      if (res.status === 200) {
        const jws = (await res.text()).trim();
        ctx.lastPull = nowS();
        backoff = FIRST_BACKOFF_MS;
        const sameRev = peekRev(jws) === ctx.table?.rev;
        let applied: boolean;
        try {
          applied = await applyConfig(ctx, jws);
        } catch (e) {
          // BRG-08 / L3: the document arrived; APPLYING it failed (disk, sealing, a bug). That is no network blip: it is
          // a status signal (rejected config/apply_failed) and an error line. The running table keeps serving (L7).
          const code = applyErrorCode(e);
          ctx.reject({ kind: "config", code: "apply_failed", detail: `${code}; rev ${peekRev(jws)}` });
          ctx.log.error("bridge.config.apply_failed", { code, rev: peekRev(jws) ?? null });
          await sleep(Math.max(MIN_PULL_INTERVAL_MS, jitter(backoff)), signal);
          backoff = Math.min(backoff * 2, 240_000);
          continue;
        }
        // A refused document would be served again at once (`after` is unchanged): wait before the next pull
        // instead of re-pulling it in a tight loop. Pause/revoke in the next valid revision is still picked up ≤ ~6 s.
        // A document with the revision we already run is a no-op, not a refusal: only a short pause.
        if (!applied && !sameRev) await sleep(jitter(REFUSED_PULL_DELAY_MS), signal);
        else await pace();
        continue;
      }
      await res.body?.cancel().catch(() => undefined);
      if (res.status === 429 || res.status === 503) {
        const ra = Number(res.headers.get("retry-after"));
        const wait = Number.isFinite(ra) && ra > 0 ? Math.min(Math.max(ra, 30), 900) * 1000 : 30_000;
        await sleep(wait, signal);
        continue;
      }
      ctx.log.warn("bridge.config.pull_failed", { code: `http_${res.status}` });
    } catch {
      ctx.log.warn("bridge.config.pull_failed", { code: "network" });
    }
    await sleep(Math.max(MIN_PULL_INTERVAL_MS, jitter(backoff)), signal);
    backoff = Math.min(backoff * 2, 240_000);
  }
}
