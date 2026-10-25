/**
 * Deployed (full) bridge: wires state, Portal link, routing, MCP, OAuth, person surfaces and the
 * internal API onto two listeners (BRIDGE §3). Used by bridge-server and `tealbrick bridge run`.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { isIP, type Socket } from "node:net";
import { hostname } from "node:os";
import { join } from "node:path";
import type { ManifestApi } from "@opt2-tealbrick/relay";
import type { Ed25519PublicJwk } from "@opt2-tealbrick/spec/credentials";
import { CallRouter, eventHookMatches } from "./calls.ts";
import { BridgeContext } from "./context.ts";
import { openEventStore } from "./events.ts";
import { InternalApi } from "./internal.ts";
import { type McpLimits, McpServer } from "./mcp.ts";
import { OAuthServer } from "./oauth.ts";
import { messagePage, STATIC_PREFIX, sendStatic, staticFile } from "./pages.ts";
import { PersonSurfaces } from "./person.ts";
import { applyConfig, ensureEnrolled, runConfigLoop, startManifestRetry, startStatusLoop } from "./portal.ts";
import { remintStandalone, StandaloneAdmin, startStandaloneLoop } from "./standalone.ts";
import { BridgeState, keksFromEnv } from "./state.ts";
import type { Table } from "./table.ts";
import { assertOrigin, clientIp, envelope, headerValue, jsonLogger, type Logger, OpenCounter, pathOf, proxyTrusted, sendError, sendJson, setProxyTrust } from "./util.ts";
import { ViewsRoute } from "./views-route.ts";
import { VIEWS_KEY_MIN_LENGTH, type ViewsLimits } from "./views-shared.ts";

export interface BridgeServerOptions {
  api: ManifestApi;
  env?: NodeJS.ProcessEnv;
  logger?: Logger;
  fetch?: typeof fetch;
  /** own infrastructure (CLI `bridge enrol/run`) instead of a Railway deploy */
  form?: "deployed" | "own_infra";
  /** test hook: listen on these instead of env ports (0 = any free port) */
  ports?: { public: number; internal: number };
  /** test hook: listener limits (defaults: {@link DEFAULT_LIMITS}; views: 32 in flight, 2 MiB, 10 s) */
  limits?: Partial<ListenerLimits> & { mcp?: Partial<McpLimits>; views?: Partial<ViewsLimits> };
  /**
   * BSD-08 test harness only (CONFORMANCE §7): replaces this build's pinned Portal Root Keys. Never read from env;
   * the production entry (bridge-server) never passes it.
   */
  portalRootKeys?: Ed25519PublicJwk[];
  /** spec 0.1.75 BRIDGE §7.5 test harness only: run the lazy-tools path although the pinned validator predates it. Never env. */
  lazyTools?: boolean;
}

/** Listener limits against slow-body and connection exhaustion (BSD-01). */
export interface ListenerLimits {
  /** whole request (headers + body) must arrive within this; responses (SSE, long-poll) are not affected */
  requestTimeoutMs: number;
  headersTimeoutMs: number;
  /** how often Node checks the two timeouts above */
  checkIntervalMs: number;
  /** open connections on the public listener */
  maxConnections: number;
  /** open connections (direct) or open requests (behind the edge proxy) per client address */
  perClient: number;
}

export const DEFAULT_LIMITS: ListenerLimits = { requestTimeoutMs: 30_000, headersTimeoutMs: 15_000, checkIntervalMs: 5_000, maxConnections: 2000, perClient: 50 };

export interface RunningBridge {
  ctx: BridgeContext;
  publicServer: Server;
  internalServer: Server;
  stop(): Promise<void>;
  /**
   * F57a / L21: graceful stop. New tool and companion calls get `temporarily_unavailable` + Retry-After, /readyz says
   * draining, in-flight calls finish up to `boundMs`; calls still running then are aborted (each request id is still
   * answered), then stop(). Resolves with what happened.
   */
  drain(boundMs?: number): Promise<{ waitedMs: number; aborted: number }>;
}

/** F57a: default drain bound, inside a 30 s platform drain window */
export const DRAIN_BOUND_MS = 25_000;

/**
 * F57a / L21: the process signal wiring of every bridge entry (deployed image, test harness). SIGTERM (platform
 * restart, update) drains: new calls are refused retryably, in-flight calls finish up to the bound, every request id
 * is answered; SIGINT stops at once. The process exits 0 after either.
 */
export function onStopSignals(running: Pick<RunningBridge, "drain" | "stop">, logger: Logger, exit: (code: number) => void = (c) => process.exit(c)): void {
  let stopping = false;
  const stop = async (signal: "SIGTERM" | "SIGINT") => {
    if (stopping) return;
    stopping = true;
    logger.info("bridge.stopping", { signal });
    if (signal === "SIGTERM") await running.drain();
    else await running.stop();
    exit(0);
  };
  process.on("SIGTERM", () => void stop("SIGTERM"));
  process.on("SIGINT", () => void stop("SIGINT"));
}

/** One request id per request; never derived from client input. */
function requestIdOf(ctx: BridgeContext): string {
  return `req_${ctx.api.ulid()}`;
}

/**
 * Own-infrastructure bridge without a provider-generated KEK: create it once under TB_DATA_DIR
 * (0600, excluded from backups by living outside bridge/), CORE I3 / CREDENTIALS §9.1.
 */
export function ownInfraEnv(env: NodeJS.ProcessEnv, api: ManifestApi): NodeJS.ProcessEnv {
  if (env.TB_KEK || !env.TB_DATA_DIR) return env;
  const path = join(env.TB_DATA_DIR, "kek");
  if (!existsSync(path)) {
    mkdirSync(env.TB_DATA_DIR, { recursive: true, mode: 0o700 });
    writeFileSync(path, api.opaqueValue("tbe_").slice(4), { mode: 0o600, flag: "wx" });
  }
  return { ...env, TB_KEK: readFileSync(path, "utf8").trim() };
}

/** A DNS-style host label list: letters, digits, `-` and `_` (Docker service names), dots between labels; 253 characters at most. */
const INTERNAL_HOST_NAME = /^(?=.{1,253}$)[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?(\.[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)*$/;

/**
 * S1 (M1): `TB_INTERNAL_HOST` set to a NAME (not an IP address) is the stable host this bridge advertises to its
 * neighbours (`http://<name>:<port>` in the claim answer, so apps hold a `TB_BRIDGE_URL` that survives a container
 * recreate, where the container id as host name does not). A name never changes what the listener binds. Returns
 * undefined when unset or when the value is an IP address (that case stays the BRG-29 bind address). An invalid value
 * is a boot error: a wrong advertised host would silently break every app.
 */
export function internalHostName(env: NodeJS.ProcessEnv): string | undefined {
  const set = env.TB_INTERNAL_HOST?.trim();
  if (!set || isIP(set) !== 0) return undefined;
  if (!INTERNAL_HOST_NAME.test(set)) throw new Error("TB_INTERNAL_HOST must be an IP address or a host name (letters, digits, - _ and dots; no scheme, port or path)");
  return set;
}

/**
 * BRG-29: the address the internal listener (claim, status, keys, companion calls, metrics) binds. `TB_INTERNAL_HOST`
 * wins when it is an IP address. Deployed form (a Railway service on the workspace private network): `::`, the address Node bound implicitly
 * before 0.1.27 (dual stack; the private network reaches the service over it), with Node's own fallback to `0.0.0.0`
 * on a host without IPv6. own_infra (`tealbrick bridge run` on a user machine or NAS): `127.0.0.1`, never every
 * interface implicitly; a neighbour on another machine needs `TB_INTERNAL_HOST` set to the private interface.
 * S1: a `TB_INTERNAL_HOST` that is a NAME only sets the advertised host (see `internalHostName`) and binds like unset;
 * in the own_infra form that would leave the advertised name unreachable, so it is refused there.
 */
export function internalListenHost(form: "deployed" | "own_infra", env: NodeJS.ProcessEnv): { host: string; explicit: boolean } {
  const name = internalHostName(env);
  if (name && form === "own_infra") throw new Error("TB_INTERNAL_HOST as a host name needs the deployed form (the listener binds every interface there); on own_infra set an IP address");
  const set = env.TB_INTERNAL_HOST?.trim();
  if (set && !name) return { host: set, explicit: true };
  return { host: form === "own_infra" ? "127.0.0.1" : "::", explicit: false };
}

/**
 * C171: the address the public listener binds. `TB_PUBLIC_HOST` when set (e.g. `127.0.0.1` for an own-infra bridge
 * behind a local tunnel, so no other program bound to 127.0.0.1:<port> can take its IPv4 traffic). Unset: the bind
 * without a host, unchanged in both forms (Node: `::` dual stack, `0.0.0.0` on a host without IPv6).
 */
export function publicListenHost(env: NodeJS.ProcessEnv): string | undefined {
  return env.TB_PUBLIC_HOST?.trim() || undefined;
}

const WILDCARD_HOSTS = new Set(["::", "0.0.0.0"]);

function listenOn(server: Server, port: number, host: string): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    const failed = (e: Error) => reject(e);
    server.once("error", failed);
    server.listen(port, host, () => {
      server.off("error", failed);
      resolve();
    });
  });
}

/** BRG-05: a KEK rotation is visible in the log (how many records moved to TB_KEK); quiet when nothing moved. */
function logResealed(logger: Logger, records: number): void {
  if (records > 0) logger.info("bridge.kek.resealed", { records });
}

/** Enrols (or re-enrols on a new code) and stops: `tealbrick bridge enrol` (CLI.md §5). */
export async function enrolBridge(o: { api: ManifestApi; env: NodeJS.ProcessEnv; logger?: Logger; fetch?: typeof fetch; form?: "deployed" | "own_infra"; portalRootKeys?: Ed25519PublicJwk[] }): Promise<{ bridgeId: string; workspaceId: string }> {
  const env = o.env;
  if (!env.TB_DATA_DIR) throw new Error("TB_DATA_DIR is required");
  const state = new BridgeState(env.TB_DATA_DIR, o.api, keksFromEnv(env, o.api));
  logResealed(o.logger ?? jsonLogger(), state.load());
  const ctx = new BridgeContext({
    api: o.api,
    state,
    logger: o.logger ?? jsonLogger(),
    portalUrl: assertOrigin(env.TB_PORTAL_URL ?? "", "TB_PORTAL_URL"),
    publicUrl: assertOrigin(env.TB_PUBLIC_URL ?? "", "TB_PUBLIC_URL"),
    internalUrl: `http://${internalHostName(env) ?? hostname()}:${Number(env.TB_INTERNAL_PORT ?? 8788)}`,
    form: o.form ?? "own_infra",
    ...(o.portalRootKeys ? { portalRoots: o.portalRootKeys } : {}),
    ...(o.fetch ? { fetch: o.fetch } : {}),
  });
  await ensureEnrolled(ctx, env.TB_ENROL_CODE);
  if (!ctx.identity) throw new Error("enrolment failed");
  return { bridgeId: ctx.identity.bridgeId, workspaceId: ctx.identity.workspaceId };
}

export async function startBridge(o: BridgeServerOptions): Promise<RunningBridge> {
  const env = o.env ?? process.env;
  const logger = o.logger ?? jsonLogger();
  const dataDir = env.TB_DATA_DIR;
  if (!dataDir) throw new Error("TB_DATA_DIR is required");
  const portalUrl = assertOrigin(env.TB_PORTAL_URL ?? "", "TB_PORTAL_URL");
  const publicUrl = assertOrigin(env.TB_PUBLIC_URL ?? "", "TB_PUBLIC_URL");
  const keysUrl = env.TB_KEYS_PUBLIC_URL ? assertOrigin(env.TB_KEYS_PUBLIC_URL, "TB_KEYS_PUBLIC_URL") : undefined;
  if (keysUrl && new URL(keysUrl).hostname === new URL(publicUrl).hostname) throw new Error("TB_KEYS_PUBLIC_URL must use a different host name from TB_PUBLIC_URL");
  const internalPort = o.ports?.internal ?? Number(env.TB_INTERNAL_PORT ?? 8788);
  const publicPort = o.ports?.public ?? Number(env.PORT ?? 8080);
  const keks = keksFromEnv(env, o.api);
  const state = new BridgeState(dataDir, o.api, keks);
  logResealed(logger, state.load());
  const form = o.form ?? "deployed";
  // LA-1: the views key (a secret: never logged, never reported) and the tb-views origin; both optional, set by Core
  const viewsUrl = env.TB_VIEWS_PUBLIC_URL?.trim() ? assertOrigin(env.TB_VIEWS_PUBLIC_URL.trim(), "TB_VIEWS_PUBLIC_URL") : undefined;
  const viewsKeyRaw = env.TB_VIEWS_KEY?.trim();
  const viewsKey = viewsKeyRaw && viewsKeyRaw.length >= VIEWS_KEY_MIN_LENGTH ? viewsKeyRaw : undefined;
  if (viewsKeyRaw && !viewsKey) logger.warn("bridge.views.key_unusable", { code: "views_key_too_short" });
  // key rotation: the retiring key, accepted only while set (Core removes it after tb-views runs the new key)
  const viewsKeyPrevRaw = env.TB_VIEWS_KEY_PREVIOUS?.trim();
  const viewsKeyPrevious = viewsKeyPrevRaw && viewsKeyPrevRaw.length >= VIEWS_KEY_MIN_LENGTH ? viewsKeyPrevRaw : undefined;
  if (viewsKeyPrevRaw && !viewsKeyPrevious) logger.warn("bridge.views.key_unusable", { code: "views_key_previous_too_short" });
  const internalBind = internalListenHost(form, env);
  // the advertised internal address: TB_INTERNAL_HOST when it is a name (S1), else the Railway private domain, else the bound address when it is one host
  const boundHost = WILDCARD_HOSTS.has(internalBind.host) ? undefined : internalBind.host.includes(":") ? `[${internalBind.host}]` : internalBind.host;
  const privateHost = internalHostName(env) ?? (env.RAILWAY_PRIVATE_DOMAIN || boundHost || hostname());
  const ctx = new BridgeContext({
    api: o.api,
    state,
    logger,
    portalUrl,
    publicUrl,
    keysUrl,
    viewsUrl,
    viewsKey,
    viewsKeyPrevious,
    internalUrl: `http://${privateHost}:${internalPort}`,
    form,
    ownInfraOrigins: (env.TB_OWN_INFRA_ORIGINS ?? "").split(",").map((h) => h.trim()).filter(Boolean),
    ...(o.portalRootKeys ? { portalRoots: o.portalRootKeys } : {}),
    ...(o.lazyTools !== undefined ? { lazyTools: o.lazyTools } : {}),
    ...(o.fetch ? { fetch: o.fetch } : {}),
  });
  await ensureEnrolled(ctx, env.TB_ENROL_CODE);
  // BRIDGE §14 (0.2.7): the event log lives next to the bridge state; opened before the first config is applied, so the
  // table listener that releases held rows (instance resume, G2b switch) runs first, in the same step as the swap
  // A store that cannot be opened (even after moving a bad file aside) leaves the bridge WITHOUT app events: no `events` cap,
  // ingest 503, methods -32601. Event-log errors never fail a config apply or another table listener.
  // TB_EVENTS_MAX_BYTES (optional, positive integer): the size cap of the log (default EVENT_DB_LIMITS.maxBytes, 1 GiB used pages)
  const maxBytes = Number(env.TB_EVENTS_MAX_BYTES);
  const events = openEventStore({ path: join(dataDir, "bridge", "events.db"), log: logger, ...(Number.isInteger(maxBytes) && maxBytes > 0 ? { maxBytes } : {}), digestOf: (m) => o.api.manifestDigest(m), hookMatches: eventHookMatches, onHealth: () => ctx.emit("health") });
  ctx.events = events;
  ctx.on("table", (next: Table | undefined) => {
    if (!next || !events) return;
    try {
      events.onTable(next);
    } catch (e) {
      logger.error("bridge.events.table_failed", { code: e instanceof Error ? e.message.slice(0, 120) : "error" });
    }
  });
  const s2 = state.loadConfigJws();
  if (s2) {
    await applyConfig(ctx, s2, { boot: true });
    if (ctx.table?.config.standalone || state.standalone) await remintStandalone(ctx);
  }

  const router = new CallRouter(ctx);
  const mcp = new McpServer(ctx, router, o.limits?.mcp);
  const oauth = new OAuthServer(ctx, keks);
  const person = new PersonSurfaces(ctx);
  const views = new ViewsRoute(ctx, o.limits?.views);
  const internal = new InternalApi(ctx, router, views);
  const admin = new StandaloneAdmin(ctx);

  const abort = new AbortController();
  const status = startStatusLoop(ctx, abort.signal);
  for (const ev of ["claim", "keys", "health", "connection-created", "connection-revoked"]) ctx.on(ev, () => status.poke());
  void runConfigLoop(ctx, abort.signal);
  startManifestRetry(ctx, abort.signal);
  startStandaloneLoop(ctx, abort.signal);

  setProxyTrust(ctx.form, env);
  const limits: ListenerLimits = { ...DEFAULT_LIMITS, ...o.limits };
  const hsts = publicUrl.startsWith("https:");
  // Behind the edge proxy every socket comes from the proxy, so the per-client cap counts open requests per
  // client address (X-Forwarded-For, rightmost); reached directly (own_infra, or TB_TRUST_PROXY=0) it counts sockets (H-2).
  const openRequests = new OpenCounter(limits.perClient);
  const openSockets = new OpenCounter(limits.perClient);

  const publicHandler = async (req: IncomingMessage, res: ServerResponse) => {
    const requestId = requestIdOf(ctx);
    // a target URL cannot parse (e.g. `GET //`) is a 400: parsed here, before the try, a throw would be an unhandled
    // rejection and stop the process
    const path = pathOf(req.url);
    if (path === null) return sendJson(res, 400, envelope("input_invalid", "bad request target", requestId), { connection: "close" });
    res.setHeader("x-content-type-options", "nosniff");
    if (hsts) res.setHeader("strict-transport-security", "max-age=31536000");
    const release = openRequests.acquire(clientIp(req));
    if (!release) return sendJson(res, 429, envelope("rate_limited", "too many open requests from this address", requestId), { "retry-after": "5", connection: "close" });
    res.on("close", release);
    try {
      if (path === "/healthz") return sendJson(res, 200, { status: "ok" });
      if (path === "/readyz") return ctx.draining ? sendJson(res, 503, { status: "draining" }) : ctx.identity && ctx.table ? sendJson(res, 200, { status: "ready" }) : sendJson(res, 503, { status: "starting" });
      // C59: the key page lives ONLY on its own origin; that origin serves nothing else, and the main origin
      // (app UIs under /a/<product>/) never serves /keys.
      const host = (headerValue(req, "host") ?? "").replace(/:\d+$/, "").toLowerCase();
      const onKeysOrigin = !!ctx.keysUrl && host === new URL(ctx.keysUrl).hostname;
      // the pages' own font, mark and favicon, on both origins: an exact allowlist, GET/HEAD only, nothing else under it
      if (path.startsWith(STATIC_PREFIX)) {
        const file = staticFile(path);
        if (!file) return sendJson(res, 404, envelope("not_found", "not found", requestId));
        if (req.method !== "GET" && req.method !== "HEAD") return sendJson(res, 405, envelope("method_not_allowed", "GET only", requestId), { allow: "GET, HEAD" });
        return sendStatic(res, file);
      }
      if (onKeysOrigin) {
        if (path === "/keys" && (req.method === "GET" || req.method === "POST")) return await person.keys(req, res);
        return sendJson(res, 404, envelope("not_found", "not found", requestId));
      }
      if (path === "/keys") {
        if (!ctx.keysUrl)
          return messagePage(res, 503, ctx, {
            title: "Key page not configured",
            text: "This workspace bridge has no separate key-page address yet (TB_KEYS_PUBLIC_URL). Ask the workspace owner to redeploy the bridge from Portal.",
            sign: "person",
          });
        return sendJson(res, 404, envelope("not_found", "the key page is served on its own address", requestId));
      }
      if (path === "/mcp") return await mcp.handle(req, res, requestId);
      if (path === "/.well-known/oauth-protected-resource" || path === "/.well-known/oauth-protected-resource/mcp") return oauth.protectedResource(res);
      if (path === "/.well-known/oauth-authorization-server") return oauth.authorizationServer(res);
      if (path === "/oauth/register" && req.method === "POST") return await oauth.register(req, res);
      if (path === "/oauth/authorize" && (req.method === "GET" || req.method === "POST")) return await oauth.authorize(req, res);
      if (path === "/oauth/pair/callback" && req.method === "POST") return await oauth.pairCallback(req, res);
      if (path === "/oauth/token" && req.method === "POST") return await oauth.token(req, res);
      if (path === "/oauth/revoke" && req.method === "POST") return await oauth.revoke(req, res);
      if (path === "/agent/connection/revoke" && req.method === "POST") return await oauth.revokeOwnConnection(req, res, requestId);
      if (path.startsWith("/a/")) return await person.app(req, res, requestId);
      if (path.startsWith("/p/")) return await person.publicRoute(req, res, requestId);
      if (path.startsWith("/admin/v1/")) return await admin.handle(req, res, requestId);
      sendJson(res, 404, envelope("not_found", "not found", requestId));
    } catch (e) {
      sendError(res, e, requestId);
    }
  };
  const internalHandler = async (req: IncomingMessage, res: ServerResponse) => {
    const requestId = requestIdOf(ctx);
    try {
      await internal.handle(req, res, requestId);
    } catch (e) {
      sendError(res, e, requestId);
    }
  };

  const listenerOptions = { requestTimeout: limits.requestTimeoutMs, headersTimeout: limits.headersTimeoutMs, connectionsCheckingInterval: limits.checkIntervalMs };
  const publicServer = createServer(listenerOptions, (req, res) => void publicHandler(req, res));
  publicServer.maxConnections = limits.maxConnections;
  publicServer.on("connection", (socket: Socket) => {
    if (proxyTrusted()) return;
    const release = openSockets.acquire(socket.remoteAddress ?? "unknown");
    if (!release) {
      socket.destroy();
      return;
    }
    socket.once("close", release);
  });
  publicServer.on("upgrade", (req, socket, head) => person.upgrade(req, socket as never, head));
  const internalServer = createServer(listenerOptions, (req, res) => void internalHandler(req, res));
  const publicBind = publicListenHost(env);
  await Promise.all([
    publicBind ? listenOn(publicServer, publicPort, publicBind) : new Promise<void>((r) => publicServer.listen(publicPort, r)),
    listenOn(internalServer, internalPort, internalBind.host).catch((e: NodeJS.ErrnoException) => {
      // the deployed default `::` on a host without IPv6: Node's implicit fallback, kept (an explicit host never falls back)
      if (internalBind.explicit || internalBind.host !== "::" || e.code !== "EAFNOSUPPORT") throw e;
      return listenOn(internalServer, internalPort, "0.0.0.0");
    }),
  ]);
  const bound = internalServer.address();
  const boundPublic = publicServer.address();
  logger.info("bridge.listening", {
    bridge: ctx.identity?.bridgeId,
    rev: ctx.table?.rev ?? 0,
    publicHost: boundPublic && typeof boundPublic === "object" ? boundPublic.address : null,
    internalHost: bound && typeof bound === "object" ? bound.address : null,
  });

  const running: RunningBridge = {
    ctx,
    publicServer,
    internalServer,
    async drain(boundMs = DRAIN_BOUND_MS) {
      const started = Date.now();
      ctx.draining = true;
      ctx.log.info("bridge.draining", { inFlight: router.activeCount(), boundMs });
      while (router.activeCount() + views.active > 0 && Date.now() - started < boundMs) await new Promise((r) => setTimeout(r, 50));
      let aborted = 0;
      if (router.activeCount() > 0) {
        // the bound: cut off every forward still running; each call still answers its request id (app_unavailable)
        aborted = router.abortAll();
        // hooks and bridge ops are bounded at 2 s: wait for the answers to be written
        const until = Date.now() + 3_000;
        while (router.activeCount() > 0 && Date.now() < until) await new Promise((r) => setTimeout(r, 50));
      }
      // answers are written right after a call leaves the router: let the last ones flush before connections close
      await new Promise((r) => setTimeout(r, 100));
      const waitedMs = Date.now() - started;
      ctx.log.info("bridge.drained", { waitedMs, aborted, left: router.activeCount() });
      await running.stop();
      return { waitedMs, aborted };
    },
    async stop() {
      abort.abort();
      publicServer.closeAllConnections();
      internalServer.closeAllConnections();
      await Promise.all([new Promise((r) => publicServer.close(r)), new Promise((r) => internalServer.close(r))]);
      events?.close();
    },
  };
  return running;
}
