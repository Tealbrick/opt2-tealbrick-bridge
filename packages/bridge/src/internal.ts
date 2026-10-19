/**
 * Internal listener (private network only, BRIDGE §3.2): app claim, status push + slice/keys
 * long-poll, key fetch, app→app companion call, metrics. Callers prove themselves with instance
 * assertions (`TB-Assert`, typ tb-instance-assert+jwt, bound to method, path and body).
 */
import type { IncomingMessage, ServerResponse } from "node:http";
import type { AppStatus, AppStatusResponse, CallEnvelope, ClaimRequest, ClaimResponse, KeyFetchResponse } from "@opt2-tealbrick/spec/bridge";
import { type InstanceAssertionClaims, type InstanceId, LIFETIME_S, TYP } from "@opt2-tealbrick/spec/credentials";
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import { isRefusal, type Json, type KeySet } from "./api.ts";
import type { CallRouter } from "./calls.ts";
import { CALL_ID_RE } from "./calls.ts";
import { type BridgeContext, DRAIN_RETRY_AFTER_S, SDK_CURRENT_MAJOR } from "./context.ts";
import { upgradeFields } from "./status-fields.ts";
import { type AppRuntime, acceptedDigests, internalUrlAllowed, type Table } from "./table.ts";
import { BridgeError, envelope, headerValue, isRecord, nowS, parseJson, readBody, sendError, sendJson, statusFor, TokenBucket } from "./util.ts";

interface InstanceCaller {
  ins: InstanceId;
  svc: string | undefined;
}

/** C85 app-initiated companion calls: 120 per minute per caller instance, burst 30. */
export const APP_INITIATED_LIMIT = { perMinute: 120, burst: 30 } as const;

export class InternalApi {
  private readonly ctx: BridgeContext;
  private readonly router: CallRouter;
  private readonly seenJtis = new Map<string, number>();
  private readonly waiters = new Set<() => void>();
  private readonly appInitiated = new TokenBucket(APP_INITIATED_LIMIT.perMinute / 60, APP_INITIATED_LIMIT.burst);
  /** BRG-12 (L31): digests of one-time codes whose claim is in progress (reserved before the first await) */
  private readonly claiming = new Set<string>();

  constructor(ctx: BridgeContext, router: CallRouter) {
    this.ctx = ctx;
    this.router = router;
    ctx.on("table", () => this.wake());
    ctx.on("keys", () => this.wake());
  }

  private wake(): void {
    for (const w of [...this.waiters]) w();
  }

  /** Verifies the instance assertion against config `instanceKeys` or a pending claim (S5). */
  private assertCaller(req: IncomingMessage, body: Buffer): InstanceCaller {
    const token = headerValue(req, "tb-assert") ?? "";
    const parts = token.split(".");
    let peek: Partial<InstanceAssertionClaims> = {};
    try {
      peek = JSON.parse(Buffer.from(parts[1] ?? "", "base64url").toString("utf8"));
    } catch {
      throw new BridgeError("unauthenticated", 401);
    }
    const ins = typeof peek.iss === "string" && peek.iss.startsWith("tb:ins:") ? (peek.iss.slice(7) as InstanceId) : undefined;
    if (!ins) throw new BridgeError("unauthenticated", 401);
    const svc = typeof peek.svc === "string" ? peek.svc : undefined;
    const keys = this.keysFor(ins, svc);
    if (!keys) throw new BridgeError("unauthenticated", 401);
    const now = nowS();
    const v = this.ctx.api.verifyAssertion<InstanceAssertionClaims>(token, keys, {
      typ: TYP.instanceAssertion,
      aud: this.ctx.bridgeRef,
      iss: [`tb:ins:${ins}`],
      now,
      maxLifetimeS: LIFETIME_S.proof,
      request: { method: req.method ?? "GET", pathAndQuery: req.url ?? "/", ...(body.length ? { body } : {}) },
    });
    if (isRefusal(v) || (v.claims.svc ?? undefined) !== svc) {
      this.ctx.reject({ kind: "assertion", code: "invalid_token" });
      throw new BridgeError("unauthenticated", 401);
    }
    for (const [k, e] of this.seenJtis) if (e <= now) this.seenJtis.delete(k);
    const replayKey = `${v.header.kid}|${v.claims.jti}`;
    if (this.seenJtis.has(replayKey) || this.ctx.proofBeforeBoot(v.claims.iat, now)) throw new BridgeError("unauthenticated", 401);
    this.seenJtis.set(replayKey, v.claims.exp + 30);
    return { ins, svc };
  }

  private keysFor(ins: InstanceId, svc: string | undefined): KeySet | undefined {
    const listed = this.ctx.table?.instanceKeys.get(`${ins}|${svc ?? ""}`);
    if (listed) return listed;
    const pending = this.ctx.state.claims.find((c) => c.ins === ins && (c.service ?? undefined) === svc);
    return pending ? this.ctx.api.keySetFrom({ keys: [pending.publicKey] }, `tb:ins:${ins}`) : undefined;
  }

  private paused(ins: InstanceId): boolean {
    const t = this.ctx.table;
    return !!t && (t.pausedWorkspace || t.pausedInstances.has(ins));
  }

  async handle(req: IncomingMessage, res: ServerResponse, requestId: string): Promise<void> {
    const url = new URL(req.url ?? "/", "http://internal");
    try {
      if (req.method === "POST" && url.pathname === "/tb/v1/claim") return await this.claim(req, res);
      if (req.method === "POST" && url.pathname === "/tb/v1/status") return await this.status(req, res, url);
      if (req.method === "GET" && url.pathname.startsWith("/tb/v1/keys/")) return await this.keyFetch(req, res, decodeURIComponent(url.pathname.slice(12)));
      if (req.method === "POST" && url.pathname === "/tb/v1/call") {
        // F57a: no new companion call while draining (retryable; nothing ran)
        if (this.ctx.draining) return sendJson(res, 503, envelope("temporarily_unavailable", "the bridge is restarting; retry in a few seconds", requestId), { "retry-after": String(DRAIN_RETRY_AFTER_S) });
        return await this.companionCall(req, res, requestId);
      }
      if (req.method === "GET" && url.pathname === "/metrics") return this.metrics(res);
      sendJson(res, 404, envelope("not_found", "not found", requestId));
    } catch (e) {
      if (e instanceof BridgeError && e.status === 400 && statusFor(e.code) !== 400) return sendError(res, new BridgeError(e.code, statusFor(e.code), e.message), requestId);
      const retry: Record<string, string> = e instanceof BridgeError && e.status === 503 ? { "retry-after": "5" } : {};
      sendError(res, e, requestId, retry);
    }
  }

  // ── §10.1 claim ──
  private async claim(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const ctx = this.ctx;
    const t = ctx.table;
    const id = ctx.identity;
    if (!t || !id) throw new BridgeError("app_unavailable", 503, "bridge has no config yet");
    const body = parseJson(await readBody(req, 64 * 1024));
    if (!isRecord(body)) throw new BridgeError("input_invalid", 400);
    const r = body as unknown as ClaimRequest;
    if (typeof r.code !== "string" || !r.instancePublicKey || typeof r.manifestDigest !== "string") throw new BridgeError("input_invalid", 400);
    const codeDigest = ctx.api.opaqueDigest(r.code);
    const now = nowS();
    const entry = t.config.enrolCodes.find((e) => ctx.api.digestEqual(e.digest, codeDigest) && e.exp > now);
    const taken = (d: string) => ctx.api.digestEqual(d as typeof codeDigest, codeDigest);
    if (!entry || ctx.state.claims.some((c) => taken(c.codeDigest)) || [...this.claiming].some(taken)) {
      ctx.reject({ kind: "claim", code: "code_invalid" });
      throw new BridgeError("code_invalid", 403);
    }
    // BRG-12: reserve the code in the same synchronous step as the check (a neighbour claim awaits its manifest
    // fetch below); a parallel claim with the same code is refused code_invalid. Released when this claim ends:
    // on success the persisted claim record holds the code, on failure a retry can claim again.
    this.claiming.add(codeDigest);
    try {
      await this.claimReserved(res, t, id, r, entry, codeDigest);
    } finally {
      this.claiming.delete(codeDigest);
    }
  }

  private async claimReserved(res: ServerResponse, t: Table, id: NonNullable<BridgeContext["identity"]>, r: ClaimRequest, entry: Table["config"]["enrolCodes"][number], codeDigest: Table["config"]["enrolCodes"][number]["digest"]): Promise<void> {
    const ctx = this.ctx;
    if (typeof r.sdkVersion !== "string" || !ctx.api.sdkMajorServed(r.sdkVersion, SDK_CURRENT_MAJOR)) throw new BridgeError("sdk_major_unsupported", 400);
    const service = entry.kind === "service" ? entry.service : undefined;
    if ((r.service ?? undefined) !== service) throw new BridgeError("code_invalid", 403);
    const app = t.apps.get(entry.ins);
    let manifest: Manifest | undefined = app?.manifest;
    let internalUrl: string | undefined;
    if (entry.kind === "neighbour") {
      if (typeof r.internalUrl !== "string") throw new BridgeError("input_invalid", 400, "internalUrl required for neighbours");
      // §10.2: a neighbour's address is evaluated as own infrastructure (TB_OWN_INFRA_ORIGINS or railway.internal)
      if (!internalUrlAllowed(ctx.api, r.internalUrl, true, ctx.ownInfraOrigins)) throw new BridgeError("internal_url_refused", 403, "this neighbour address is not in TB_OWN_INFRA_ORIGINS");
      internalUrl = new URL(r.internalUrl).origin;
      const res2 = await ctx.fetch(new URL("/tb/v1/manifest", internalUrl), { redirect: "error", signal: AbortSignal.timeout(10_000) });
      const v = ctx.api.validateManifest(await res2.json());
      if (!v.ok || v.digest !== r.manifestDigest) throw new BridgeError("manifest_mismatch", 409);
      manifest = v.manifest;
    } else if (!app || !acceptedDigests(app.entry).includes(r.manifestDigest)) {
      // G2b: the claim may carry the serving digest or, mid-attempt, the candidate digest; anything else is refused
      throw new BridgeError("manifest_mismatch", 409);
    }
    // Build the COMPLETE answer first; record the claim and consume the one-time code only when it is complete.
    const out: ClaimResponse = { ins: entry.ins, bridge: { id: id.bridgeId, publicKey: id.key.publicJwk, internalUrl: ctx.internalUrl } };
    const keyListed = t.instanceKeys.has(`${entry.ins}|${service ?? ""}`);
    if (keyListed && app && !service) out.slice = app.entry.slice;
    if (service) {
      // the app's key: listed by Core, or the app's own claim pending at this bridge (S5)
      const appKey =
        t.config.instanceKeys.find((k) => k.ins === entry.ins && !k.svc)?.jwk ??
        ctx.state.claims.find((c) => c.ins === entry.ins && c.service === undefined)?.publicKey;
      if (!appKey) {
        // companions may start before their app (startOrder): retryable, code NOT consumed
        throw new BridgeError("app_not_claimed", 503, "the app instance has not claimed yet; retry");
      }
      if (!manifest) throw new BridgeError("app_unavailable", 503, "the app manifest is not available yet; retry");
      out.app = { publicKey: appKey };
      out.serviceKeys = serviceKeyNames(t, entry.ins, service).map((name) => ({ name, env: name }));
    }
    const record = {
      kind: entry.kind,
      ins: entry.ins,
      ...(service ? { service } : {}),
      publicKey: r.instancePublicKey,
      manifestDigest: r.manifestDigest,
      version: r.version,
      ...(internalUrl ? { internalUrl } : {}),
      codeDigest,
      claimedAt: new Date().toISOString(),
      reported: false,
    };
    ctx.state.claims.push(record);
    try {
      ctx.state.saveClaims();
    } catch (e) {
      // not persisted → not claimed: the code stays usable (one state change = one write, L31)
      ctx.state.claims.splice(ctx.state.claims.indexOf(record), 1);
      throw e;
    }
    ctx.emit("claim");
    ctx.log.info("bridge.claim", { ins: entry.ins, kind: entry.kind, ...(service ? { svc: service } : {}) });
    sendJson(res, 200, out);
  }

  // ── §10.3 status + slice/keys long-poll ──
  private async status(req: IncomingMessage, res: ServerResponse, url: URL): Promise<void> {
    const raw = await readBody(req, 16 * 1024);
    const caller = this.assertCaller(req, raw);
    const body = parseJson(raw) as AppStatus;
    if (!isRecord(body) || typeof body.readiness !== "string") throw new BridgeError("input_invalid", 400);
    const ctx = this.ctx;
    if (!caller.svc) {
      const prev = ctx.health.get(caller.ins);
      ctx.health.set(caller.ins, { status: body, lastSeen: nowS() });
      if (!prev || prev.status.scopesRev !== body.scopesRev) void this.refreshScopeSummary(caller.ins);
      const attentionChanged = JSON.stringify(prev?.status.attention ?? null) !== JSON.stringify(body.attention ?? null);
      // spec 0.1.39 (US-2): a new schema or a failed boot reaches Portal at once too (Core's update health gate waits on it)
      const upgradeChanged = JSON.stringify(upgradeFields(prev?.status)) !== JSON.stringify(upgradeFields(body));
      if (!prev || prev.status.readiness !== body.readiness || prev.status.pendingHolds !== body.pendingHolds || attentionChanged || upgradeChanged) ctx.emit("health");
    }
    const wait = Math.min(Math.max(Number(url.searchParams.get("wait") ?? 0) || 0, 0), 60);
    const answer = (): AppStatusResponse | undefined => {
      const app = ctx.table?.apps.get(caller.ins);
      if (!app) return undefined;
      const sliceRev = sliceRevision(app);
      const keysRev = ctx.state.keyStore.keysRev;
      if (sliceRev !== body.sliceRevision || keysRev !== body.keysRev) return { slice: app.entry.slice, sliceRevision: sliceRev, keysRev };
      return undefined;
    };
    const now = answer();
    if (now || wait === 0) {
      if (now) sendJson(res, 200, now);
      else res.writeHead(204).end();
      return;
    }
    await new Promise<void>((resolve) => {
      let done = false;
      const finish = () => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        this.waiters.delete(check);
        resolve();
      };
      const check = () => {
        const a = answer();
        if (a) {
          sendJson(res, 200, a);
          finish();
        }
      };
      const timer = setTimeout(() => {
        if (!res.headersSent) res.writeHead(204).end();
        finish();
      }, wait * 1000);
      this.waiters.add(check);
      req.on("close", finish);
    });
  }

  private async refreshScopeSummary(ins: InstanceId): Promise<void> {
    const app = this.ctx.table?.apps.get(ins);
    if (!app || this.paused(ins)) return;
    try {
      const list = await this.router.bridgeOp<{ agent: `agt_${string}`; label: string }[]>(app, "scope_summary", {});
      for (const k of [...this.ctx.scopeSummaries.keys()]) if (k.endsWith(`|${ins}`)) this.ctx.scopeSummaries.delete(k);
      for (const s of Array.isArray(list) ? list : []) {
        if (typeof s?.agent !== "string" || typeof s.label !== "string") continue;
        this.ctx.scopeSummaries.set(`${s.agent}|${ins}`, { agt: s.agent, ins, label: s.label.slice(0, 80) });
      }
      this.ctx.emit("health");
    } catch {
      this.ctx.log.warn("bridge.scope_summary.failed", { ins, code: "app_error" });
    }
  }

  // ── §9.4 key fetch ──
  private async keyFetch(req: IncomingMessage, res: ServerResponse, name: string): Promise<void> {
    const caller = this.assertCaller(req, Buffer.alloc(0));
    const t = this.ctx.table;
    if (!t) throw new BridgeError("app_unavailable", 503);
    if (this.paused(caller.ins)) throw new BridgeError("paused", 403);
    // C69: decide from the SIGNED config only (Core is the one `when` evaluator, C48), never from the app's live
    // manifest: a manifest fetch_failed during an update must not cut companions off their declared keys.
    const app = t.apps.get(caller.ins);
    if (!app) throw new BridgeError("app_unavailable", 503, "no verified config entry for this instance yet; retry");
    const user = caller.svc ?? "app";
    const declared = t.config.keyRequirements.some((r) => r.ins === caller.ins && r.name === name && r.source === "account_default" && r.usedBy.includes(user));
    // mid-deploy (app down or its manifest not loaded): a key the next revision adds may not be listed yet → transient
    if (!declared && (app.down || !app.manifest)) throw new BridgeError("app_unavailable", 503, "the app is updating; retry");
    if (!declared) throw new BridgeError("key_not_declared", 403);
    const value = this.ctx.state.keyStore.values[name];
    if (value === undefined) throw new BridgeError("key_not_set", 404);
    const out: KeyFetchResponse = { name, value, keysRev: this.ctx.state.keyStore.keysRev };
    sendJson(res, 200, out);
  }

  // ── §8.3 companion (app→app) ──
  private async companionCall(req: IncomingMessage, res: ServerResponse, requestId: string): Promise<void> {
    const raw = await readBody(req, 2 * 1024 * 1024);
    const caller = this.assertCaller(req, raw);
    if (caller.svc) throw new BridgeError("unauthenticated", 401, "services cannot make companion calls");
    const t = this.ctx.table;
    if (!t) throw new BridgeError("config_expired", 503);
    if (this.ctx.configExpired()) throw new BridgeError("config_expired", 503);
    if (this.paused(caller.ins)) throw new BridgeError("paused", 403);
    const grant = headerValue(req, "tb-grant");
    if (!grant) throw new BridgeError("no_grant", 403);
    const env = parseJson(raw) as CallEnvelope;
    if (!isRecord(env) || typeof env.target !== "string" || typeof env.op !== "string") throw new BridgeError("input_invalid", 400);
    const app: AppRuntime | undefined = t.appsByProduct.get(env.target);
    if (!app) throw new BridgeError("unknown_tool", 404);
    if (app.down || !app.manifest) throw new BridgeError("app_unavailable", 503, "the target app is starting; retry");
    const op = app.ops.get(env.op);
    if (!op) throw new BridgeError("unknown_tool", 404);
    // A2A-3: a parentCall must be a call id (format and size) before it is looked up or logged
    if (env.parentCall !== undefined && (typeof env.parentCall !== "string" || !CALL_ID_RE.test(env.parentCall))) {
      throw new BridgeError("parent_call_invalid", 400, "parentCall must be a call id (call_<ULID>)");
    }
    // A2A-2: only an OPEN call this bridge delivered to THIS (verified) caller instance counts as a parent
    const parentCall = env.parentCall ? this.router.parentCallFor(caller.ins, env.parentCall) : undefined;
    if (env.parentCall && !parentCall) this.ctx.log.warn("bridge.call.parent_call_unknown", { ins: caller.ins, parentCall: env.parentCall });
    // C85: an app-initiated call (no valid parentCall: timers, background work) is limited per caller instance like
    // any caller (120/min, burst 30); calls inside a request chain are bounded by that request
    if (!parentCall) {
      const wait = this.appInitiated.take(caller.ins);
      if (wait) return sendError(res, new BridgeError("rate_limited", 429, "too many app-initiated calls from this instance; retry later"), requestId, { "retry-after": String(wait) });
    }
    try {
      const { result } = await this.router.route({
        caller: { type: "app", ins: caller.ins, grant },
        target: { app, op, ...(op.standard || !op.dynamic ? {} : isRecord(env.input) && typeof env.input.tool === "string" ? { tool: env.input.tool } : {}) },
        input: (env.input ?? {}) as Json,
        ...(env.idempotencyKey ? { idempotencyKey: env.idempotencyKey } : {}),
        ...(parentCall ? { parentCall } : {}),
      });
      sendJson(res, result.status === "held" ? 202 : 200, result);
    } catch (e) {
      const code = e instanceof BridgeError ? e.code : "app_error";
      sendJson(res, e instanceof BridgeError && e.status !== 400 ? e.status : statusFor(code), envelope(code, e instanceof Error ? e.message : code, requestId));
    }
  }

  private metrics(res: ServerResponse): void {
    const lines: string[] = [];
    const t = this.ctx.table;
    lines.push(`tb_bridge_config_rev ${t?.rev ?? 0}`);
    lines.push(`tb_bridge_config_age_seconds ${t ? nowS() - t.config.iat : -1}`);
    lines.push(`tb_bridge_portal_reachable ${this.ctx.portalReachable() ? 1 : 0}`);
    for (const [k, v] of this.router.counters) {
      const [kind, a, b] = k.split("|");
      if (kind === "call") lines.push(`tb_bridge_calls_total{product="${a}",code="${b}"} ${v}`);
      if (kind === "hook") lines.push(`tb_bridge_hook_calls_total{hook="${a}",result="${b}"} ${v}`);
    }
    for (const [k, v] of this.ctx.rejected) {
      const [kind, code] = k.split("|");
      lines.push(`tb_bridge_rejected_total{kind="${kind}",code="${code}"} ${v}`);
    }
    res.writeHead(200, { "content-type": "text/plain; version=0.0.4" });
    res.end(`${lines.join("\n")}\n`);
  }
}

/**
 * Key names one instance's user (`app` or a service id) may fetch. The ONE `when` evaluation is Core's
 * (`activeKeyRequirements` + `resolveSettings`), delivered as SIGNED config `keyRequirements[]`; the bridge never
 * sees settings (S6) and never re-derives this from the app's live manifest (C69).
 */
export function serviceKeyNames(t: Table, ins: InstanceId, user: string): string[] {
  return t.config.keyRequirements.filter((r) => r.ins === ins && r.usedBy.includes(user)).map((r) => r.name);
}

/** Slice `rev` (from the slice payload) is the revision apps compare. */
export function sliceRevision(app: AppRuntime): number {
  try {
    const p = JSON.parse(Buffer.from(app.entry.slice.split(".")[1] ?? "", "base64url").toString("utf8")) as { rev?: number };
    return typeof p.rev === "number" ? p.rev : 0;
  } catch {
    return 0;
  }
}
