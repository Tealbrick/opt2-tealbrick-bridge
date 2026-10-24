/**
 * MCP surface (BRIDGE §7): Streamable HTTP at /mcp (POST JSON-RPC, GET SSE for notifications,
 * DELETE ends the session). Tools come from grants; skills are resources + an instructions index +
 * the `<product>__tb_skills` fallback tool. Every request re-authenticates the agent (K5).
 */
import { randomBytes } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { MCP_VERSIONS, tooDeep, validRpcId } from "@opt2-tealbrick/relay";
import type { HeldToolResult, JsonObject, JsonValue } from "@opt2-tealbrick/spec/bridge";
import { EVENT_MCP_METHODS, TOOL_NAME_RULE } from "@opt2-tealbrick/spec/bridge";
import type { AgentId, ConnectionId, InstanceId } from "@opt2-tealbrick/spec/credentials";
import type { Skill } from "@opt2-tealbrick/spec/manifest";
import type { Json } from "@opt2-tealbrick/spec/sdk";
import { type CallRouter, RESOLVE_TTL_MS } from "./calls.ts";
import { BRIDGE_VERSION, type BridgeContext, DRAIN_RETRY_AFTER_S } from "./context.ts";
import { EVENT_POLL_LIMIT, isEventCursor, pollLimit } from "./events.ts";
import { authenticateAgent, connectionState } from "./identity.ts";
import { LIST_MAX_AGE_MS, MISS_MIN_AGE_MS, refreshScopeSummaryIfOlder } from "./scope-summary.ts";
import { agtRef, grantKey, insRef, type Table } from "./table.ts";
import { agentPausedOrEmpty, buildToolIndex, grantedProducts, searchLazy, type ToolIndex, type ToolRoute } from "./tools.ts";
import { BridgeError, envelope, headerValue, isRecord, nowS, readBody, sendError, sendJson, TokenBucket } from "./util.ts";

interface Session {
  id: string;
  agt: AgentId;
  con: ConnectionId;
  protocol: string;
  streams: Set<ServerResponse>;
  toolDigest: string;
  skillsDigest: string;
  lastSeen: number;
  /** BRIDGE §14.3 (0.2.7): the event subscription of this session (`tealbrick/events/stream`); `cursor` = the last event id
   *  framed (null = from the oldest kept). One per session: a second `stream` call replaces it. */
  events?: { cursor: string | null };
  /** a frame flush is scheduled */
  flushQueued?: boolean;
  /** a flush waits for 'drain' on a slow stream (one listener at a time) */
  drainWait?: boolean;
}

interface RpcRequest {
  jsonrpc: "2.0";
  id?: string | number | null;
  method: string;
  params?: Record<string, unknown>;
}

const MAX_BODY = 2 * 1024 * 1024;
const SESSION_IDLE_MS = 3600_000;

/** Per-connection and global limits (BSD-02); counted per verified `con`, after K5 verification. */
export const MCP_LIMITS = Object.freeze({
  sessionsPerConnection: 16,
  streamsPerSession: 2,
  /** POST /mcp token bucket per connection */
  ratePerS: 10,
  burst: 40,
  callsPerConnection: 8,
  callsGlobal: 256,
  /** C296: a tool index with dynamic list entries is rebuilt after this (the app's catalog changes without a config revision) */
  dynamicIndexTtlMs: RESOLVE_TTL_MS,
  /** C296: an index built while a dynamic catalog failed is retried after this */
  incompleteIndexRetryMs: 30_000,
  /** BRIDGE §14.3 (0.2.7): `tealbrick/events/*` requests per connection (their own bucket: a backlog of 10 000 rows is 100 polls) */
  eventsRatePerS: 20,
  eventsBurst: 200,
});

/** A POST body up to this size (declared Content-Length) is read before the rate check, to find `tealbrick/events/*` reads. */
const EVENTS_PEEK_MAX = 4096;
const EVENT_METHOD_PREFIX = "tealbrick/events/";

export type McpLimits = { -readonly [K in keyof typeof MCP_LIMITS]: number };

type Principal = { agt: AgentId; con: ConnectionId; gen: number; exp: number };

/** BRIDGE §8.5 (G4b): MCP `_meta` key of the onBehalfOf claim */
export const ON_BEHALF_OF_META_KEY = "tealbrick/onBehalfOf"; // gitleaks:allow (MCP _meta key name, not a secret)

export class McpServer {
  private readonly ctx: BridgeContext;
  private readonly router: CallRouter;
  /** insertion order = least recently used first (a touched session moves to the end) */
  private readonly sessions = new Map<string, Session>();
  private readonly indexCache = new Map<string, Promise<ToolIndex>>();
  /** C296: keys whose background rebuild runs (one at a time per key) */
  private readonly rebuilding = new Set<string>();
  private readonly limits: McpLimits;
  private readonly postBucket: TokenBucket;
  /** S1: the connection gen and token expiry of the token that opened each GET stream */
  private readonly streamAuth = new WeakMap<ServerResponse, { gen: number; exp: number }>();
  private readonly eventsBucket: TokenBucket;
  private readonly callsByCon = new Map<string, number>();
  private callsInFlight = 0;

  /** `limits` is a test hook; production uses {@link MCP_LIMITS} */
  constructor(ctx: BridgeContext, router: CallRouter, limits: Partial<McpLimits> = {}) {
    this.ctx = ctx;
    this.router = router;
    this.limits = { ...MCP_LIMITS, ...limits };
    this.postBucket = new TokenBucket(this.limits.ratePerS, this.limits.burst);
    this.eventsBucket = new TokenBucket(this.limits.eventsRatePerS, this.limits.eventsBurst);
    ctx.on("table", () => {
      this.indexCache.clear();
      // S1: a config that revokes a connection or removes its agent ends that connection's sessions at once; a gen rotation
      // closes the streams opened with an older gen (the session and its subscription stay; the client reopens GET with a
      // current token and Last-Event-ID), before any frame or list_changed goes out under the new table
      for (const s of [...this.sessions.values()]) {
        if (!this.sessionValid(s)) this.endSession(s.id);
        else this.pruneStreams(s);
      }
      void this.notifyChanges();
      // BRIDGE §14.3: a resume (agent, workspace or instance) releases held rows; subscribed streams pick them up
      for (const s of this.sessions.values()) this.scheduleFlush(s);
    });
    // BRIDGE §14.3: live frames within 1 s of ingest (internal.ts emits the agents that got a row, after the commit)
    ctx.on("events-stored", (agents: Set<string>) => {
      for (const s of this.sessions.values()) if (agents.has(s.agt)) this.scheduleFlush(s);
    });
    // C283 A1: the app's scope summary (`admittedOps`) changed → the tool lists are rebuilt and sessions told
    ctx.on("scopes", () => {
      this.indexCache.clear();
      void this.notifyChanges();
    });
    ctx.on("connection-revoked", (con: string) => {
      for (const [id, s] of this.sessions) if (s.con === con) this.endSession(id);
    });
    setInterval(() => {
      const now = Date.now();
      for (const [id, s] of this.sessions) if (now - s.lastSeen > SESSION_IDLE_MS && s.streams.size === 0) this.sessions.delete(id);
    }, 600_000).unref();
  }

  /** The caller's own live session: same agent AND same connection (H-4); touching it marks it recently used. */
  private sessionFor(sid: string | undefined, p: Principal): Session | undefined {
    const s = sid ? this.sessions.get(sid) : undefined;
    if (!s || s.agt !== p.agt || s.con !== p.con) return undefined;
    if (Date.now() - s.lastSeen > SESSION_IDLE_MS && s.streams.size === 0) {
      this.endSession(s.id);
      return undefined;
    }
    s.lastSeen = Date.now();
    this.sessions.delete(s.id);
    this.sessions.set(s.id, s);
    return s;
  }

  /** Adds a session; past the per-connection cap the least recently used session of that connection ends. */
  private addSession(s: Session): void {
    const mine = [...this.sessions.values()].filter((x) => x.con === s.con);
    for (let i = 0; i <= mine.length - this.limits.sessionsPerConnection; i++) this.endSession((mine[i] as Session).id);
    this.sessions.set(s.id, s);
  }

  private index(t: Table, agt: AgentId): Promise<ToolIndex> {
    const key = `${t.rev}|${agt}`;
    const p = this.indexCache.get(key);
    if (!p) {
      const built = buildToolIndex(this.ctx, this.router, t, agt);
      this.indexCache.set(key, built);
      built.catch(() => this.indexCache.get(key) === built && this.indexCache.delete(key));
      return built;
    }
    // C296 (INC-20261020-03): dynamic list entries come from the app at run time. Kept for the whole config revision, an
    // index built while the app had no engine yet (0 entries, or a failed catalog) hid the engine tools until the next
    // revision. A stale index is still answered at once; ONE background rebuild replaces it and the agent's sessions get
    // list_changed when the tool set changed. Only an idle client that never asks again hears nothing until it does.
    void p.then((idx) => this.refresh(t, agt, key, p, idx)).catch(() => undefined);
    return p;
  }

  private refresh(t: Table, agt: AgentId, key: string, previous: Promise<ToolIndex>, idx: ToolIndex): void {
    if (this.indexCache.get(key) !== previous || this.rebuilding.has(key)) return;
    const age = Date.now() - (idx.builtAt ?? 0);
    const expired = idx.dynamic === true && age >= this.limits.dynamicIndexTtlMs;
    const retry = idx.incomplete === true && age >= this.limits.incompleteIndexRetryMs;
    if (!expired && !retry) return;
    // Past the TTL every catalog of this agent is asked again (a failed refresh keeps the last good answer); a retry after
    // a failure asks only what is not cached (the failed catalog), never the healthy apps again.
    if (expired) this.router.expireCatalogs(agt);
    this.rebuilding.add(key);
    buildToolIndex(this.ctx, this.router, t, agt)
      .then((fresh) => {
        if (this.indexCache.get(key) !== previous) return; // the table or the scopes changed meanwhile: that index wins
        this.indexCache.set(key, Promise.resolve(fresh));
        this.toolsChanged(agt, fresh);
      })
      .catch(() => undefined) // the previous index keeps serving; the next request tries again
      .finally(() => this.rebuilding.delete(key));
  }

  /** C296: list_changed to this agent's sessions whose last listed tool set differs from the rebuilt index. */
  private toolsChanged(agt: AgentId, idx: ToolIndex): void {
    const td = this.ctx.api.digest(idx.tools.map((x) => x.name) as Json);
    for (const s of this.sessions.values()) {
      if (s.agt !== agt || !s.toolDigest || s.toolDigest === td) continue;
      this.push(s, { jsonrpc: "2.0", method: "notifications/tools/list_changed" });
      s.toolDigest = td;
    }
  }

  /**
   * C283 A1: asks the apps this agent has a grant to for their scope summary when the last answer is older than `maxAgeMs`
   * (display input for the tool list; scope-summary.ts). A changed `admittedOps` rebuilds the tool lists (event `scopes`).
   */
  private async refreshSummaries(t: Table, agt: AgentId, maxAgeMs: number): Promise<void> {
    if (agentPausedOrEmpty(t, agt)) return;
    const prefix = `${agtRef(agt)}|`;
    const ins = new Set<InstanceId>();
    for (const [k, g] of t.grants) if (k.startsWith(prefix)) ins.add(g.claims.aud.slice(7) as InstanceId);
    await Promise.all([...ins].filter((i) => { const a = t.apps.get(i); return a && !a.down; }).map((i) => refreshScopeSummaryIfOlder(this.ctx, this.router, i, maxAgeMs)));
  }

  /**
   * C283 A1: a tools/call named a tool the list does not show. When it names a STATIC scoped op of an app this agent has a grant
   * to, the app's scope summary is asked again (at most every {@link MISS_MIN_AGE_MS} per app, so an agent cannot make the bridge
   * hammer an app) and the caller looks the tool up once more. Other unknown names never cause a request. true = asked or an
   * answer younger than the bound exists.
   */
  private async refreshOnMiss(t: Table, agt: AgentId, name: string): Promise<boolean> {
    const at = name.indexOf("__");
    if (at < 1) return false;
    const app = t.appsByProduct.get(name.slice(0, at));
    const op = app?.ops.get(name.slice(at + 2));
    if (!app || app.down || !op || op.standard || op.scopeType === undefined || op.dynamic) return false;
    if (!t.grants.has(grantKey(agtRef(agt), insRef(app.entry.ins)))) return false;
    await refreshScopeSummaryIfOlder(this.ctx, this.router, app.entry.ins, MISS_MIN_AGE_MS);
    return true;
  }

  private skillsFor(t: Table, agt: AgentId) {
    const products = grantedProducts(t, agt);
    return t.config.skills.files.filter((f) => products.has(f.product));
  }

  private instructions(t: Table, agt: AgentId): string {
    if (agentPausedOrEmpty(t, agt)) return "Teal Brick: this agent is paused by the owner. No tools are available until the owner resumes it.";
    const lines = [
      "Teal Brick apps are available as tools named <product>__<operation>.",
      `When a tool result has status "held", the owner must approve it in the app; check it later with the tool named in "checkWith" (<product>__${TOOL_NAME_RULE.holdStatusOp}) and repeat the same call once approved.`,
      "Skills (read before first use):",
    ];
    for (const s of this.skillsFor(t, agt)) {
      lines.push(`- ${s.title}${s.when ? ` (when: ${s.when})` : ""}: ${TOOL_NAME_RULE.skillUriPrefix}${s.product}/${s.id} or tool ${s.product}__${TOOL_NAME_RULE.skillsOp} {"skillId":"${s.id}"}`);
    }
    let out = lines.join("\n");
    if (Buffer.byteLength(out) > 4096) out = `${out.slice(0, 4000)}\n…`;
    return out;
  }

  private renderSkill(t: Table, agt: AgentId, product: string, id: string): string | undefined {
    const f = t.config.skills.files.find((s) => s.product === product && s.id === id);
    if (!f) return undefined;
    const agent = t.agents.get(agt);
    const skill: Skill = { id: f.id, title: f.title, file: "SKILL.md" };
    return this.ctx.api.renderSkill(skill, f.content, { agent: { id: agt, name: agent?.name ?? agt } });
  }

  /** Pushes list_changed to sessions whose tool or skill set changed. */
  private async notifyChanges(): Promise<void> {
    const t = this.ctx.table;
    if (!t) return;
    for (const s of this.sessions.values()) {
      try {
        const idx = await this.index(t, s.agt);
        const td = this.ctx.api.digest(idx.tools.map((x) => x.name) as Json);
        const sd = this.ctx.api.digest(this.skillsFor(t, s.agt).map((f) => `${f.product}/${f.id}`).concat(t.config.skills.digest) as Json);
        if (s.toolDigest && td !== s.toolDigest) this.push(s, { jsonrpc: "2.0", method: "notifications/tools/list_changed" });
        if (s.skillsDigest && sd !== s.skillsDigest) this.push(s, { jsonrpc: "2.0", method: "notifications/resources/list_changed" });
        s.toolDigest = td;
        s.skillsDigest = sd;
      } catch {
        /* next change retries */
      }
    }
  }

  private push(s: Session, message: unknown): void {
    const data = `event: message\ndata: ${JSON.stringify(message)}\n\n`;
    for (const res of s.streams) res.write(data);
  }

  /** BRIDGE §14.3: frames go only to an open GET stream of a subscribed session; one flush at a time per session. */
  private scheduleFlush(s: Session): void {
    if (!s.events || s.streams.size === 0 || s.flushQueued) return;
    s.flushQueued = true;
    setImmediate(() => {
      s.flushQueued = false;
      this.flush(s);
    });
  }

  /**
   * Writes the events after the subscription cursor as `notifications/tealbrick/event` frames (SSE `id:` = event id), moving
   * the cursor. Nothing while the agent or the workspace is paused (the subscription stays; frames start on resume). A slow
   * reader is waited for (drain) instead of buffering the whole backlog.
   */
  /**
   * S1 (bridge 0.2.7 review): a session lives while its connection is listed (or locally paired) and active, for the same
   * agent, and the agent is in the config. A revoke or an agent change/removal ends it (the client re-initializes).
   */
  private sessionValid(s: Session): boolean {
    const t = this.ctx.table;
    const st = connectionState(this.ctx, s.con);
    return !!t && !!st && st.active && st.agt === s.agt && t.agents.has(s.agt);
  }

  /**
   * Review round 2: gen and expiry belong to each STREAM (the token that opened it). A stream whose gen is not the
   * connection's current gen (a pairing refresh, a Portal rotation) or whose token expired is closed; the session stays.
   */
  private pruneStreams(s: Session): void {
    const st = connectionState(this.ctx, s.con);
    const now = nowS();
    for (const res of [...s.streams]) {
      const a = this.streamAuth.get(res);
      if (a && st && a.gen === st.gen && a.exp > now) continue;
      s.streams.delete(res);
      res.end();
    }
  }

  private flush(s: Session): void {
    const store = this.ctx.events;
    const t = this.ctx.table;
    const sub = s.events;
    if (!store?.available || !t || !sub || s.streams.size === 0 || this.sessions.get(s.id) !== s) return;
    if (this.ctx.configExpired()) return; // fail closed like a call; the next config swap schedules a flush again
    if (!this.sessionValid(s)) {
      this.endSession(s.id);
      return;
    }
    this.pruneStreams(s);
    if (s.streams.size === 0) return;
    if (t.pausedWorkspace || t.pausedAgents.has(s.agt)) return;
    try {
      for (let pages = 0; pages < 20; pages++) {
        const evs = store.page(t, s.agt, sub.cursor, EVENT_POLL_LIMIT.max);
        for (const e of evs) {
          // a slow reader: stop before the next write, continue on 'drain' (the cursor names the last frame written)
          const slow = [...s.streams].find((r) => r.writableNeedDrain);
          if (slow) {
            if (!s.drainWait) {
              s.drainWait = true;
              const go = () => {
                s.drainWait = false;
                slow.off("close", go);
                slow.off("drain", go);
                this.scheduleFlush(s);
              };
              slow.once("drain", go);
              slow.once("close", go);
            }
            return;
          }
          const data = `id: ${e.id}\nevent: message\ndata: ${JSON.stringify({ jsonrpc: "2.0", method: EVENT_MCP_METHODS.notification, params: { event: e } })}\n\n`;
          for (const res of s.streams) res.write(data);
          sub.cursor = e.id;
        }
        if (evs.length < EVENT_POLL_LIMIT.max) return;
      }
      this.scheduleFlush(s);
    } catch (e) {
      this.ctx.log.warn("bridge.events.flush_failed", { agt: s.agt, code: e instanceof Error ? e.message.slice(0, 120) : "error" });
    }
  }


  /** `cursor` of poll/stream: absent or null = none; a string that is not a ULID this bridge could issue → -32602 cursor_invalid. */
  private eventCursor(v: unknown): string | null {
    if (v === undefined || v === null) return null;
    if (typeof v !== "string" || !isEventCursor(v)) throw new RpcError(-32602, "cursor not issued by this bridge", { code: "cursor_invalid" });
    return v;
  }

  private endSession(id: string): void {
    const s = this.sessions.get(id);
    if (!s) return;
    for (const r of s.streams) r.end();
    s.streams.clear();
    s.events = undefined;
    this.sessions.delete(id);
  }

  private unauthorized(res: ServerResponse, requestId: string): void {
    sendJson(res, 401, envelope("unauthenticated", "agent session required", requestId), {
      "www-authenticate": `Bearer resource_metadata="${this.ctx.publicUrl}/.well-known/oauth-protected-resource/mcp"`,
    });
  }

  private tooMany(res: ServerResponse, requestId: string, message: string, retryAfterS: number): void {
    sendJson(res, 429, envelope("rate_limited", message, requestId), { "retry-after": String(retryAfterS) });
  }

  async handle(req: IncomingMessage, res: ServerResponse, requestId: string): Promise<void> {
    let principal: Principal;
    try {
      principal = authenticateAgent(this.ctx, headerValue(req, "authorization"));
    } catch {
      this.unauthorized(res, requestId);
      return;
    }
    const sid = headerValue(req, "mcp-session-id");
    const missingSession = () => sendJson(res, 400, envelope("input_invalid", "Mcp-Session-Id header required", requestId));
    if (req.method === "DELETE") {
      if (!sid) return missingSession();
      const s = this.sessionFor(sid, principal);
      if (!s) {
        sendJson(res, 404, envelope("not_found", "unknown session", requestId));
        return;
      }
      this.endSession(s.id);
      res.writeHead(204).end();
      return;
    }
    if (req.method === "GET") {
      if (!sid) return missingSession();
      const s = this.sessionFor(sid, principal);
      if (!s) {
        sendJson(res, 404, envelope("not_found", "unknown session", requestId));
        return;
      }
      if (s.streams.size >= this.limits.streamsPerSession) return this.tooMany(res, requestId, "too many open streams for this session", 5);
      res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-store", connection: "keep-alive" });
      res.write(": ok\n\n");
      s.streams.add(res);
      this.streamAuth.set(res, { gen: principal.gen, exp: principal.exp });
      const ka = setInterval(() => {
        if (!res.writableEnded) res.write(": ping\n\n");
      }, 25_000);
      // S1: a stream ends at its token's expiry (the client reconnects with a fresh token and Last-Event-ID)
      const expiry = setTimeout(() => {
        clearInterval(ka);
        s.streams.delete(res);
        res.end();
      }, Math.max(0, principal.exp * 1000 - Date.now()));
      expiry.unref();
      req.on("close", () => {
        clearInterval(ka);
        clearTimeout(expiry);
        s.streams.delete(res);
      });
      // BRIDGE §14.3: a reconnect with Last-Event-ID resumes after it while the session holds its subscription
      const last = headerValue(req, "last-event-id");
      if (s.events && last && isEventCursor(last)) s.events.cursor = last;
      this.scheduleFlush(s);
      return;
    }
    if (req.method !== "POST") {
      res.writeHead(405, { allow: "GET, POST, DELETE" }).end();
      return;
    }
    // BRIDGE §14.3 (0.2.7): `tealbrick/events/*` reads have their own per-connection bucket (a runtime catching up on a
    // backlog pages through up to 10 000 rows, 100 per poll). A small body (≤ 4 KiB, declared length) is read first to tell
    // them apart; every other request takes the general bucket BEFORE its body is read, as before.
    const declared = Number(req.headers["content-length"]);
    let body: Buffer | undefined;
    let msg: unknown;
    try {
      if (Number.isInteger(declared) && declared >= 0 && declared <= EVENTS_PEEK_MAX) {
        body = await readBody(req, EVENTS_PEEK_MAX);
        msg = JSON.parse(body.toString("utf8"));
      }
    } catch (e) {
      if (e instanceof BridgeError) return sendError(res, e, requestId);
      msg = undefined; // answered below as a parse error, after the general bucket
    }
    const eventsRead = isRecord(msg) && typeof msg.method === "string" && msg.method.startsWith(EVENT_METHOD_PREFIX);
    const wait = (eventsRead ? this.eventsBucket : this.postBucket).take(principal.con);
    if (wait > 0) return this.tooMany(res, requestId, "too many requests for this connection", wait);
    try {
      if (!body) body = await readBody(req, MAX_BODY);
      if (msg === undefined) msg = JSON.parse(body.toString("utf8"));
    } catch (e) {
      if (e instanceof BridgeError) return sendError(res, e, requestId);
      sendJson(res, 400, { jsonrpc: "2.0", id: null, error: { code: -32700, message: "parse error" } });
      return;
    }
    if (!isRecord(msg) || msg.jsonrpc !== "2.0" || typeof msg.method !== "string") {
      // responses or batches from the client: accepted and ignored (no server→client requests)
      res.writeHead(202).end();
      return;
    }
    if (!validRpcId(msg.id) || tooDeep(msg)) {
      sendJson(res, 400, { jsonrpc: "2.0", id: null, error: { code: -32600, message: !validRpcId(msg.id) ? "invalid request id" : "request nested too deep" } });
      return;
    }
    const rpc = msg as unknown as RpcRequest;
    const isNotification = rpc.id === undefined;
    let session: Session | undefined;
    if (rpc.method === "initialize") {
      const requested = typeof rpc.params?.protocolVersion === "string" ? rpc.params.protocolVersion : "";
      const protocol = MCP_VERSIONS.includes(requested) ? requested : (MCP_VERSIONS[0] as string);
      const clientName = isRecord(rpc.params?.clientInfo) && typeof rpc.params.clientInfo.name === "string" ? rpc.params.clientInfo.name.slice(0, 64) : "";
      session = { id: randomBytes(16).toString("base64url"), agt: principal.agt, con: principal.con, protocol, streams: new Set(), toolDigest: "", skillsDigest: "", lastSeen: Date.now() };
      this.addSession(session);
      const t = this.ctx.table as Table;
      this.ctx.log.info("bridge.mcp.initialize", { agt: principal.agt, protocol, client: clientName });
      sendJson(
        res,
        200,
        {
          jsonrpc: "2.0",
          id: rpc.id ?? null,
          result: {
            protocolVersion: protocol,
            capabilities: { tools: { listChanged: true }, resources: { listChanged: true } },
            serverInfo: { name: "tealbrick-bridge", version: BRIDGE_VERSION },
            instructions: this.instructions(t, principal.agt),
          },
        },
        { "mcp-session-id": session.id },
      );
      return;
    }
    if (!sid) {
      sendJson(res, 400, { jsonrpc: "2.0", id: rpc.id ?? null, error: { code: -32600, message: "Mcp-Session-Id header required (initialize first)" } });
      return;
    }
    session = this.sessionFor(sid, principal);
    if (!session) {
      sendJson(res, 404, { jsonrpc: "2.0", id: rpc.id ?? null, error: { code: -32001, message: "session not found; re-initialize" } });
      return;
    }
    if (isNotification) {
      res.writeHead(202).end();
      return;
    }
    // F57a / L21: while draining (SIGTERM), a NEW tool call is not started: it is answered at once with the retryable
    // code and Retry-After (nothing ran, so a retry is safe); other methods are still served
    if (this.ctx.draining && rpc.method === "tools/call") {
      sendJson(res, 200, { jsonrpc: "2.0", id: rpc.id, result: toolError("temporarily_unavailable", "the bridge is restarting; retry in a few seconds", requestId) }, { "retry-after": String(DRAIN_RETRY_AFTER_S) });
      return;
    }
    const controller = new AbortController();
    req.on("close", () => {
      if (!res.writableEnded) controller.abort();
    });
    try {
      const result = await this.dispatch(session, principal, rpc, requestId, controller.signal);
      sendJson(res, 200, { jsonrpc: "2.0", id: rpc.id, result });
    } catch (e) {
      // only messages the bridge wrote reach the agent; anything else is a generic internal error (H-7)
      const code = e instanceof RpcError ? e.rpcCode : -32603;
      const message = e instanceof RpcError || e instanceof BridgeError ? e.message : "internal error";
      sendJson(res, 200, { jsonrpc: "2.0", id: rpc.id, error: { code, message, ...(e instanceof RpcError && e.data !== undefined ? { data: e.data } : {}) } });
    }
  }

  private async dispatch(s: Session, p: Principal, rpc: RpcRequest, requestId: string, signal: AbortSignal): Promise<unknown> {
    const t = this.ctx.table;
    if (!t) throw new RpcError(-32603, "bridge not ready");
    switch (rpc.method) {
      case "ping":
        return {};
      case "tools/list": {
        await this.refreshSummaries(t, p.agt, LIST_MAX_AGE_MS);
        const idx = await this.index(this.ctx.table ?? t, p.agt);
        s.toolDigest = this.ctx.api.digest(idx.tools.map((x) => x.name) as Json);
        return { tools: idx.tools };
      }
      case "resources/list": {
        const files = this.skillsFor(t, p.agt);
        s.skillsDigest = this.ctx.api.digest(files.map((f) => `${f.product}/${f.id}`).concat(t.config.skills.digest) as Json);
        return {
          resources: files.map((f) => ({ uri: `${TOOL_NAME_RULE.skillUriPrefix}${f.product}/${f.id}`, name: `${f.product}/${f.id}`, title: f.title, description: f.when ?? f.title, mimeType: "text/markdown" })),
        };
      }
      case "resources/templates/list":
        return { resourceTemplates: [] };
      case "resources/read": {
        const uri = typeof rpc.params?.uri === "string" ? rpc.params.uri : "";
        const m = /^tealbrick:\/\/skills\/([a-z][a-z0-9-]{1,31})\/([a-z][a-z0-9-]{1,39})$/.exec(uri);
        if (!m || !grantedProducts(t, p.agt).has(m[1] as string)) throw new RpcError(-32002, "resource not found");
        const text = this.renderSkill(t, p.agt, m[1] as string, m[2] as string);
        if (text === undefined) throw new RpcError(-32002, "resource not found");
        return { contents: [{ uri, mimeType: "text/markdown", text }] };
      }
      case "prompts/list":
        return { prompts: [] };
      case "tools/call":
        return this.callTool(t, p, rpc.params ?? {}, requestId, signal, s.id);
      // BRIDGE §14.3 (0.2.7): app events on the agent's existing session
      case EVENT_MCP_METHODS.list:
      case EVENT_MCP_METHODS.poll:
      case EVENT_MCP_METHODS.stream:
        return this.eventMethod(t, s, rpc);
      default:
        throw new RpcError(-32601, "method not found");
    }
  }

  private eventMethod(t: Table, s: Session, rpc: RpcRequest): unknown {
    const store = this.ctx.events;
    // without a healthy event log the bridge does not declare `events`: the methods are unknown (runtimes keep their polls)
    if (!store?.available) throw new RpcError(-32601, "method not found");
    const params = isRecord(rpc.params) ? rpc.params : {};
    const paused = t.pausedWorkspace || t.pausedAgents.has(s.agt);
    if (rpc.method === EVENT_MCP_METHODS.list) return store.list(t, s.agt);
    // review round 3 (S4): like a tool call, delivery fails closed on a config older than its `exp` (C9); nothing is read, dropped or framed
    if (this.ctx.configExpired()) throw new RpcError(-32000, "config_expired", { code: "config_expired" });
    const cursor = this.eventCursor(params.cursor);
    if (rpc.method === EVENT_MCP_METHODS.poll) return store.poll(t, s.agt, cursor, pollLimit(params.limit), paused);
    const r = store.stream(s.agt, cursor, paused);
    // one subscription per session: this call replaces any earlier one and the backlog after `cursor` is framed again
    s.events = { cursor: r.cursor };
    this.scheduleFlush(s);
    return r;
  }

  private async callTool(t: Table, p: Principal, params: Record<string, unknown>, requestId: string, signal: AbortSignal, sessionId = ""): Promise<unknown> {
    const name = typeof params.name === "string" ? params.name : "";
    const args = (isRecord(params.arguments) ? params.arguments : {}) as Json;
    const meta = isRecord(params._meta) ? params._meta : {};
    const idem = meta[TOOL_NAME_RULE.idempotencyMetaKey];
    // §8.5 (G4b): an onBehalfOf claim becomes `tb.onBehalfOf` (unverified) before the before hooks; a bad or oversized
    // claim is dropped (the call proceeds) and counted (shared rule: manifest onBehalfOfFromMeta)
    const rawObo = meta[ON_BEHALF_OF_META_KEY];
    const obo = rawObo === undefined ? null : this.ctx.api.onBehalfOfFromMeta(rawObo);
    if (rawObo !== undefined && obo === null) this.ctx.reject({ kind: "claim", code: "on_behalf_of_invalid" });
    if (idem !== undefined && (typeof idem !== "string" || idem.length < 8 || idem.length > 128)) {
      return toolError("input_invalid", "idempotency key must be 8–128 chars", requestId);
    }
    const inFlight = this.callsByCon.get(p.con) ?? 0;
    if (inFlight >= this.limits.callsPerConnection) return toolError("rate_limited", "too many concurrent calls for this connection; retry shortly", requestId);
    if (this.callsInFlight >= this.limits.callsGlobal) return toolError("rate_limited", "the bridge is busy; retry shortly", requestId);
    this.callsByCon.set(p.con, inFlight + 1);
    this.callsInFlight += 1;
    try {
      // pause is gate step 1: a paused agent or workspace is told `paused`, not that the tool is unknown
      if (t.pausedWorkspace || t.pausedAgents.has(p.agt)) throw new BridgeError("paused", 403, "paused by the owner");
      let idx = await this.index(t, p.agt);
      let route = idx.routes.get(name);
      if (!route && (await this.refreshOnMiss(t, p.agt, name))) {
        // C283 A1: the owner may have just widened a row; the app's scope summary was asked again and the tool is now listed
        idx = await this.index(this.ctx.table ?? t, p.agt);
        route = idx.routes.get(name);
      }
      if (!route) {
        // a tool of an app that is temporarily unavailable (restart, update) is not "unknown" (C57)
        const app = t.appsByProduct.get(name.split("__")[0] ?? "");
        if (app && (app.down || !app.manifest) && t.grants.has(`tb:agt:${p.agt}|tb:ins:${app.entry.ins}`)) {
          throw new BridgeError("app_unavailable", 503, "the app is starting; try again in a few seconds");
        }
        throw new BridgeError("unknown_tool", 404);
      }
      // spec 0.1.66 BRIDGE §7.5: `tool` names a STATIC op of the same product in this agent's index (lazy or listed); the
      // call then IS that op's direct call (input = `arguments`; key, gate, hooks, proof, holds and receipts name the op)
      let target: { route: ToolRoute; args: Json } = { route, args };
      if (route.kind === "more_call") {
        // QA-BRIDGE20-3: the inner name gets the direct call's refresh-on-miss (C283 A1: an owner may have just admitted it)
        let more: ToolRoute = route;
        const inner = moreCallName(route.app, args);
        if (!idx.routes.has(inner) && (await this.refreshOnMiss(t, p.agt, inner))) {
          idx = await this.index(this.ctx.table ?? t, p.agt);
          const again = idx.routes.get(name);
          if (again?.kind === "more_call") more = again;
        }
        target = resolveMoreCall(idx, more.app, args);
      }
      return await this.runRoute(t, p, target.route, target.args, idem as string | undefined, requestId, signal, sessionId, obo ? { "tb.onBehalfOf": obo as JsonValue } : undefined);
    } catch (e) {
      const code = e instanceof BridgeError ? e.code : "app_error";
      const message = e instanceof BridgeError ? e.message : "internal error";
      return toolError(code, message, requestId, e instanceof BridgeError ? e.details : undefined);
    } finally {
      this.callsInFlight -= 1;
      const left = (this.callsByCon.get(p.con) ?? 1) - 1;
      if (left <= 0) this.callsByCon.delete(p.con);
      else this.callsByCon.set(p.con, left);
    }
  }

  private async runRoute(t: Table, p: Principal, route: ToolRoute, args: Json, idem: string | undefined, _requestId: string, signal: AbortSignal, sessionId = "", reservedContext?: JsonObject): Promise<unknown> {
    const caller = { type: "agent" as const, agt: p.agt, con: p.con };
    if (route.kind === "skills") {
      const skillId = isRecord(args) && typeof args.skillId === "string" ? args.skillId : undefined;
      if (!skillId) {
        const index = t.config.skills.files.filter((f) => f.product === route.app.entry.product).map((f) => ({ skillId: f.id, title: f.title, ...(f.when ? { when: f.when } : {}) }));
        return toolOk({ skills: index });
      }
      const text = this.renderSkill(t, p.agt, route.app.entry.product, skillId);
      if (text === undefined) throw new BridgeError("unknown_tool", 404, "unknown skill");
      return { content: [{ type: "text", text }], structuredContent: { skillId, text } };
    }
    if (route.kind === "more_search") {
      // spec 0.1.66 BRIDGE §7.5: answered from the agent's own index (only ops its grants make visible); no app call
      const query = isRecord(args) && typeof args.query === "string" ? args.query : "";
      if (!query || query.length > 500) throw new BridgeError("input_invalid", 400, "query required (1–500 chars)");
      const limit = isRecord(args) && typeof args.limit === "number" ? Math.min(Math.max(1, Math.floor(args.limit)), 50) : 10;
      return toolOk(searchLazy(route.lazy, query, limit) as unknown as Json);
    }
    if (route.kind === "more_call") throw new BridgeError("unknown_tool", 404); // resolved in callTool; never nested
    if (route.kind === "dynamic_search") {
      if (agentPausedOrEmpty(t, p.agt)) throw new BridgeError("paused", 403);
      const query = isRecord(args) && typeof args.query === "string" ? args.query : "";
      if (!query) throw new BridgeError("input_invalid", 400, "query required");
      const limit = isRecord(args) && typeof args.limit === "number" ? Math.min(Math.max(1, Math.floor(args.limit)), 50) : undefined;
      const grant = [...t.grants.values()].find((g) => g.claims.sub === `tb:agt:${p.agt}` && g.claims.aud === `tb:ins:${route.app.entry.ins}`);
      const entries = await this.router.search(route.app, route.op.id, query, limit, p.agt);
      // C283 A1: an entry the SDK marked `admitted: "owner"` for this agent is shown above grant.crud (display only)
      const visible = entries.filter((e) => grant && ((e.admitted === "owner" && !route.op.standard && route.op.scopeType !== undefined) || e.crud.every((c) => grant.claims.crud.includes(c))));
      return toolOk({ tools: visible.map((e) => ({ tool: e.name, title: e.title, description: e.description, inputSchema: e.inputSchema as Json, effect: e.effect })) });
    }
    let input: Json = args;
    let tool: string | undefined;
    if (route.kind === "dynamic_entry") {
      tool = route.entry;
      input = { tool: route.entry, arguments: args as Record<string, Json> };
    } else if (route.kind === "dynamic_call") {
      tool = isRecord(args) && typeof args.tool === "string" ? args.tool : undefined;
      if (!tool) throw new BridgeError("input_invalid", 400, "tool required");
    }
    // C98: model-driven MCP clients cannot set `_meta`. Without a client key the bridge derives one, so an identical
    // retry inside the window is deduplicated by the app instead of failing (`required`) or running twice. A client
    // that sends `_meta["tealbrick/idempotencyKey"]` keeps its exact semantics.
    // derived per the shared rule (manifest deriveIdempotencyKey, L1); `input` already names a dynamic tool
    const key = idem ?? (route.op.standard || route.op.idempotency === "none" ? undefined : this.ctx.api.deriveIdempotencyKey({ connection: p.con, session: sessionId, op: route.op.id, input, now: Date.now() }));
    const { result } = await this.router.route({
      caller,
      target: { app: route.app, op: route.op, ...(tool ? { tool } : {}) },
      input,
      ...(key ? { idempotencyKey: key } : {}),
      ...(reservedContext ? { reservedContext } : {}),
      signal,
    });
    if (result.status === "held") {
      const held: HeldToolResult = { status: "held", holdId: result.holdId, expiresAt: result.expiresAt, checkWith: `${route.app.entry.product}__${TOOL_NAME_RULE.holdStatusOp}` };
      return { content: [{ type: "text", text: `Waiting for the owner's approval in ${route.app.manifest?.name ?? route.app.entry.product}. ${JSON.stringify(held)}` }], structuredContent: held, isError: false };
    }
    return toolOk(result.output as Json);
  }
}

/**
 * spec 0.1.66 BRIDGE §7.5 `tb_more_call {tool, arguments}`: `tool` = `<product>__<op>` or the bare op id. Only a static op
 * route of the SAME app in this agent's index qualifies; anything else (unknown, not visible to this agent, another product,
 * a standard op, a dynamic op or entry, a `tb_*` tool) is `unknown_tool`, the answer for a name that does not exist.
 */
/** the tool name a `tb_more_call` input names (`<product>__<op>` or the bare op id of this app) */
export function moreCallName(app: ToolRoute["app"], args: Json): string {
  const tool = isRecord(args) && typeof args.tool === "string" ? args.tool : "";
  if (!tool) throw new BridgeError("input_invalid", 400, "tool required");
  if (isRecord(args) && args.arguments !== undefined && !isRecord(args.arguments)) throw new BridgeError("input_invalid", 400, "arguments must be an object");
  return tool.includes(TOOL_NAME_RULE.separator) ? tool : `${app.entry.product}${TOOL_NAME_RULE.separator}${tool}`;
}

export function resolveMoreCall(idx: ToolIndex, app: ToolRoute["app"], args: Json): { route: ToolRoute & { kind: "op" }; args: Json } {
  const route = idx.routes.get(moreCallName(app, args));
  if (route?.kind !== "op" || route.app !== app || route.op.standard || route.op.dynamic) throw new BridgeError("unknown_tool", 404);
  return { route, args: (isRecord(args) && isRecord(args.arguments) ? args.arguments : {}) as Json };
}

class RpcError extends Error {
  readonly rpcCode: number;
  readonly data: unknown;
  constructor(code: number, message: string, data?: unknown) {
    super(message);
    this.rpcCode = code;
    this.data = data;
  }
}

function toolOk(output: Json): unknown {
  const structured = isRecord(output) ? output : { value: output };
  return { content: [{ type: "text", text: JSON.stringify(output) }], structuredContent: structured };
}

function toolError(code: string, message: string, requestId: string, details?: Record<string, unknown>): unknown {
  const env = envelope(code, message, requestId, details);
  return { content: [{ type: "text", text: JSON.stringify(env) }], structuredContent: env, isError: true };
}
