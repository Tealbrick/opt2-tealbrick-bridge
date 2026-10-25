import type { IncomingMessage, ServerResponse } from "node:http";
import { tooDeep } from "@opt2-tealbrick/relay";
import type { BridgeErrorCode, ErrorEnvelope } from "@opt2-tealbrick/spec/bridge";

/** A refusal or failure that maps to the one error envelope (CORE §8). */
export class BridgeError extends Error {
  readonly code: BridgeErrorCode | (string & {});
  readonly status: number;
  /** optional machine-readable refusal details (routes ErrorEnvelope `error.details`) */
  readonly details?: Record<string, unknown>;
  constructor(code: BridgeErrorCode | (string & {}), status = 400, message?: string, details?: Record<string, unknown>) {
    super(message ?? code);
    this.code = code;
    this.status = status;
    if (details) this.details = details;
  }
}

export const nowS = (): number => Math.floor(Date.now() / 1000);

export function envelope(code: string, message: string, requestId: string, details?: Record<string, unknown>): ErrorEnvelope {
  return { error: { code, message, requestId, ...(details ? { details } : {}) } } as ErrorEnvelope;
}

/** Default HTTP status per refuse code. */
export function statusFor(code: string): number {
  switch (code) {
    case "unauthenticated":
    case "invalid_token":
      return 401;
    case "paused":
    case "no_grant":
    case "grant_invalid":
    case "grant_expired":
    case "grant_stale":
    case "grant_revoked":
    case "crud_exceeds_grant":
    case "audience_not_agent":
    case "scope_type_unknown":
    case "not_in_workflow":
    case "hook_denied":
    case "key_not_declared":
    case "role_not_declared":
    case "role_policy_too_low":
    case "dynamic_ceiling_exceeded":
      return 403;
    case "unknown_tool":
    case "key_not_set":
    case "role_not_set":
    case "not_found":
      return 404;
    case "request_timeout":
      return 408;
    case "payload_too_large":
      return 413;
    case "rate_limited":
      return 429;
    case "config_expired":
    case "app_unavailable":
    case "hook_failed":
    case "after_failed":
    case "dynamic_resolve_failed":
      return 503;
    case "app_timeout":
      return 504;
    case "app_error":
      return 502;
    default:
      return 400;
  }
}

export interface Logger {
  info(event: string, fields?: Record<string, unknown>): void;
  warn(event: string, fields?: Record<string, unknown>): void;
  error(event: string, fields?: Record<string, unknown>): void;
}

/**
 * JSON-lines logger. Callers pass ids, codes and digests only (BRIDGE §12): never inputs, outputs,
 * tokens, tickets, codes or key values. Failures are deduplicated to one line per event+code per minute.
 */
export function jsonLogger(write: (line: string) => void = (l) => process.stderr.write(`${l}\n`)): Logger {
  const seen = new Map<string, number>();
  const emit = (level: string, event: string, fields: Record<string, unknown> = {}) => {
    try {
      if (level !== "info") {
        const key = `${event}|${String(fields.kind ?? "")}|${String(fields.code ?? "")}|${String(fields.detail ?? "")}`;
        const last = seen.get(key) ?? 0;
        const now = Date.now();
        if (now - last < 60_000) return;
        if (seen.size > 1024) seen.clear();
        seen.set(key, now);
      }
      write(JSON.stringify({ ts: new Date().toISOString(), level, event, ...fields }));
    } catch {
      /* logging never changes an outcome */
    }
  };
  return {
    info: (e, f) => emit("info", e, f),
    warn: (e, f) => emit("warn", e, f),
    error: (e, f) => emit("error", e, f),
  };
}

export const silentLogger: Logger = { info() {}, warn() {}, error() {} };

/** Default deadline for a whole request body (BSD-01); TB_BODY_DEADLINE_MS overrides it (tests). */
export const BODY_DEADLINE_MS = 15_000;

function bodyDeadlineMs(): number {
  const v = Number(process.env.TB_BODY_DEADLINE_MS);
  return Number.isFinite(v) && v > 0 ? v : BODY_DEADLINE_MS;
}

/**
 * Reads a request body with a hard size cap and a deadline: a body that is not complete in time is refused
 * with 408 `request_timeout` (a slow sender cannot hold a socket and a buffer open, BSD-01).
 */
export function readBody(req: IncomingMessage, max: number, deadlineMs = bodyDeadlineMs()): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let done = false;
    const finish = (err: Error | undefined) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      req.off("data", onData);
      req.off("end", onEnd);
      req.off("error", onError);
      req.off("close", onClose);
      if (err) {
        req.pause();
        reject(err);
      } else resolve(Buffer.concat(chunks));
    };
    const onData = (chunk: Buffer) => {
      size += chunk.length;
      if (size > max) return finish(new BridgeError("payload_too_large", 413));
      chunks.push(chunk);
    };
    const onEnd = () => finish(undefined);
    const onError = () => finish(new BridgeError("input_invalid", 400, "request body aborted"));
    const onClose = () => finish(new BridgeError("input_invalid", 400, "request body aborted"));
    const timer = setTimeout(() => finish(new BridgeError("request_timeout", 408, "request body not received in time")), deadlineMs);
    timer.unref();
    if (req.readableEnded) return finish(undefined);
    req.on("data", onData);
    req.on("end", onEnd);
    req.on("error", onError);
    req.on("close", onClose);
  });
}

/**
 * Reads a bridge→app response body with a hard cap while it streams (BSD-05): the bridge never buffers more
 * than `maxBytes` of an app's answer, whatever the app sends or claims in Content-Length.
 */
export async function readCapped(res: Response, maxBytes: number): Promise<Buffer> {
  const tooLarge = () => new BridgeError("payload_too_large", 502, "app answer too large");
  const declared = Number(res.headers.get("content-length") ?? "");
  if (Number.isFinite(declared) && declared > maxBytes) {
    await res.body?.cancel().catch(() => undefined);
    throw tooLarge();
  }
  if (!res.body) return Buffer.alloc(0);
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maxBytes) {
      await reader.cancel().catch(() => undefined);
      throw tooLarge();
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks);
}

/** Parses a capped app answer as JSON (`app_error` when it is not JSON). */
export async function readCappedJson<T>(res: Response, maxBytes: number): Promise<T> {
  const buf = await readCapped(res, maxBytes);
  let v: unknown;
  try {
    v = JSON.parse(buf.toString("utf8"));
  } catch {
    throw new BridgeError("app_error", 502, "app answered non-JSON");
  }
  if (tooDeep(v)) throw new BridgeError("app_error", 502, "app answer nested too deep");
  return v as T;
}

export function parseJson(body: Buffer): unknown {
  if (body.length === 0) return undefined;
  try {
    return JSON.parse(body.toString("utf8"));
  } catch {
    throw new BridgeError("input_invalid", 400, "body is not JSON");
  }
}

export function sendJson(res: ServerResponse, status: number, value: unknown, headers: Record<string, string> = {}): void {
  const body = JSON.stringify(value);
  res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store", ...headers });
  res.end(body);
}

export function sendError(res: ServerResponse, err: unknown, requestId: string, headers: Record<string, string> = {}): void {
  const code = err instanceof BridgeError ? err.code : "app_error";
  const status = err instanceof BridgeError ? err.status : 500;
  const message = err instanceof BridgeError ? err.message : "internal error";
  if (res.headersSent) {
    res.end();
    return;
  }
  // refused before the request body was received (deadline, size cap): close the connection instead of
  // draining the rest of a slow or huge body
  const extra: Record<string, string> = res.req && !res.req.complete ? { connection: "close" } : {};
  if (code === "rate_limited" && !headers["retry-after"]) extra["retry-after"] = "1";
  const details = err instanceof BridgeError ? err.details : undefined;
  sendJson(res, status, envelope(code, message, requestId, details), { ...extra, ...headers });
}

export function isRecord(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

/** Origin check for URLs the bridge receives in config or enrolment (https, loopback http only in tests). */
export function assertOrigin(value: string, what: string): string {
  const u = new URL(value);
  const loopback = ["127.0.0.1", "[::1]", "localhost"].includes(u.hostname);
  if ((u.protocol !== "https:" && !(u.protocol === "http:" && loopback)) || u.username || u.password || u.search || u.hash) {
    throw new BridgeError("input_invalid", 400, `${what} must be an https origin`);
  }
  return u.origin;
}

/** Simple fixed-window rate limiter keyed by a string (BRIDGE §6.3, §9.2). */
export class RateLimiter {
  private readonly windows = new Map<string, { start: number; count: number }>();
  private readonly limit: number;
  private readonly windowMs: number;
  constructor(limit: number, windowMs = 60_000) {
    this.limit = limit;
    this.windowMs = windowMs;
  }
  take(key: string): boolean {
    const now = Date.now();
    const w = this.windows.get(key);
    if (!w || now - w.start >= this.windowMs) {
      // H-2: evict oldest-first instead of clearing every bucket (a flood of fresh keys must not reset busy ones)
      if (w) this.windows.delete(key);
      while (this.windows.size >= 10_000) {
        const oldest = this.windows.keys().next().value;
        if (oldest === undefined) break;
        this.windows.delete(oldest);
      }
      this.windows.set(key, { start: now, count: 1 });
      return true;
    }
    w.count += 1;
    return w.count <= this.limit;
  }
}

/** Token bucket keyed by a string: `ratePerS` tokens per second up to `burst` (BSD-02 per-connection limit). */
export class TokenBucket {
  private readonly buckets = new Map<string, { tokens: number; at: number }>();
  private readonly ratePerS: number;
  private readonly burst: number;
  constructor(ratePerS: number, burst: number) {
    this.ratePerS = ratePerS;
    this.burst = burst;
  }
  /** Takes one token; returns 0 when granted, else the seconds until the next token. */
  take(key: string): number {
    const now = Date.now();
    let b = this.buckets.get(key);
    if (!b) {
      if (this.buckets.size > 10_000) this.buckets.clear();
      b = { tokens: this.burst, at: now };
      this.buckets.set(key, b);
    }
    b.tokens = Math.min(this.burst, b.tokens + ((now - b.at) / 1000) * this.ratePerS);
    b.at = now;
    if (b.tokens >= 1) {
      b.tokens -= 1;
      return 0;
    }
    return Math.max(1, Math.ceil((1 - b.tokens) / this.ratePerS));
  }
}

/** Counts open items (connections, requests, upgrades) per key with a cap. */
export class OpenCounter {
  private readonly open = new Map<string, number>();
  private readonly cap: number;
  constructor(cap: number) {
    this.cap = cap;
  }
  /** Returns a release function, or undefined when the key is at its cap. */
  acquire(key: string): (() => void) | undefined {
    const n = this.open.get(key) ?? 0;
    if (n >= this.cap) return undefined;
    this.open.set(key, n + 1);
    let released = false;
    return () => {
      if (released) return;
      released = true;
      const m = (this.open.get(key) ?? 1) - 1;
      if (m <= 0) this.open.delete(key);
      else this.open.set(key, m);
    };
  }
  count(key: string): number {
    return this.open.get(key) ?? 0;
  }
}

/**
 * Client address for per-client rate-limit buckets. Behind the provider's edge proxy every request comes from
 * the proxy, so the socket address would put all clients in one bucket (one client could exhaust it for
 * everyone). The edge APPENDS the client address to X-Forwarded-For, so the rightmost entry is the one the
 * trusted proxy saw; entries to its left are client-supplied and ignored. Trusted only per {@link setProxyTrust}.
 */
let proxyTrust = process.env.TB_TRUST_PROXY !== "0";

/**
 * H-2: X-Forwarded-For is trusted only behind the provider edge (deployed form) or with TB_TRUST_PROXY=1;
 * an own-infrastructure bridge counts the socket address unless told it sits behind a proxy. Set once at start.
 */
export function setProxyTrust(form: "deployed" | "own_infra", env: NodeJS.ProcessEnv): boolean {
  const v = env.TB_TRUST_PROXY ?? process.env.TB_TRUST_PROXY;
  proxyTrust = v === "1" || (v !== "0" && form === "deployed");
  return proxyTrust;
}

export function proxyTrusted(): boolean {
  return proxyTrust;
}

export function clientIp(req: IncomingMessage): string {
  if (proxyTrust) {
    const xff = headerValue(req, "x-forwarded-for");
    const last = xff?.split(",").map((s) => s.trim()).filter(Boolean).at(-1);
    if (last && last.length <= 64) return last;
  }
  return req.socket.remoteAddress ?? "unknown";
}

export function headerValue(req: IncomingMessage, name: string): string | undefined {
  const v = req.headers[name.toLowerCase()];
  return Array.isArray(v) ? v[0] : v;
}

/** The request target as a URL, or null when it does not parse (e.g. `//`); never throws (a throw in a listener stops the process). */
export function urlOf(target: string | undefined): URL | null {
  try {
    return new URL(target ?? "/", "http://x");
  } catch {
    return null;
  }
}

/** The pathname of the request target, or null when it does not parse. */
export function pathOf(target: string | undefined): string | null {
  return urlOf(target)?.pathname ?? null;
}

export const sleep = (ms: number, signal?: AbortSignal): Promise<void> =>
  new Promise((resolve) => {
    const t = setTimeout(resolve, ms);
    signal?.addEventListener("abort", () => {
      clearTimeout(t);
      resolve();
    }, { once: true });
  });

export function jitter(ms: number, fraction = 0.25): number {
  return Math.round(ms * (1 - fraction + Math.random() * fraction * 2));
}
