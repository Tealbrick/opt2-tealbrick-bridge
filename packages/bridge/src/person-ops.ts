/**
 * Person-op relay (spec 0.1.70, BRIDGE §16, PORTAL-API "v0.1.64 additions" B–C; C326, C354; introduced in spec 0.1.64). Core queues allow-listed person ops of native
 * owner sessions for this bridge; the bridge PULLS them (outbound only, like the config pull) and forwards each one ONCE to
 * the app: `POST <internalUrl>/tb/v1/person-op` with the K14 in `TB-Person-Op` and the exact body bytes Core hashed into
 * K14 `bd`. The app verifies K14 and decides; the bridge never verifies, stores or logs it, nor the input or the output.
 *
 * - ONE long-poll `GET /bridge/person-ops?wait=25` with the bridge assertion; never in standalone mode (no K14 issuer).
 * - Result `status`: the app's HTTP status; -1 = not delivered (connect refused, DNS, TLS, before any byte was sent);
 *   0 = outcome unknown (timeout or a broken answer after sending, body over `maxOutputBytes`); 409 `instance_unknown`
 *   when `ins` is not in the current config, 409 `person_op_unsupported` (spec 0.1.70, C354, fail closed) when the app's
 *   latest claim/status does not declare app cap `person_op` (proof-caps.ts); nothing forwarded for either.
 * - No retries of the forward (one pop = at most one request to the app); the result post is retried once on a network error.
 * - Pause does not stop the relay (owner access by design, like person launch). Logs: pop, ins, op, status, ms only.
 */
import { type APP_CAPS, PERSON_OP_BRIDGE_REFUSALS } from "@opt2-tealbrick/spec/bridge";
import { type BridgePersonOp, type BridgePersonOpResultInput, PERSON_OP_RELAY } from "@opt2-tealbrick/spec/routes";
import { isPreConnect } from "./calls.ts";
import type { BridgeContext } from "./context.ts";
import { portalRequest } from "./portal.ts";
import { isRecord, jitter, readCapped, sleep } from "./util.ts";

const PATH = "/api/v1/bridge/person-ops";
/** items handled at once; the loop does not pull while every slot is busy (Core caps a workspace at 8 queued or taken) */
export const RELAY_CONCURRENCY = 4;
/** an empty batch that came back sooner than this is followed by a pause (a Core or proxy that ignores `wait`) */
export const MIN_POLL_INTERVAL_MS = 1_000;
const FIRST_BACKOFF_MS = 1_000;
const MAX_BACKOFF_MS = 30_000;
/** a batch holds at most `queueMaxPerWorkspace` rows of ≤ maxInputBytes each plus their K14 */
const MAX_BATCH_BYTES = 2 * 1024 * 1024;
const RESULT_TIMEOUT_MS = 5_000;
/** pops already handled (memory): a row handed out twice is never forwarded twice */
const SEEN_MAX = 512;
/** a Core without the relay answers the pull 404: logged once per process, then at most hourly (the backoff keeps pulling) */
const NOT_FOUND_LOG_EVERY_MS = 3_600_000;

/** spec 0.1.70 (C354): the fixed refusals, and the app cap that allows a forward */
const REFUSED = PERSON_OP_BRIDGE_REFUSALS;
const APP_CAP_PERSON_OP: (typeof APP_CAPS)[number] = "person_op";
const refusal = (code: string, message: string) => ({ status: 409, body: JSON.stringify({ error: { code, message } }) });

const POP_ID = /^pop_[0-9A-Za-z]{1,64}$/;
const INS_ID = /^ins_[0-9A-Za-z]{1,64}$/;
const OP_NAME = /^[a-z][a-z0-9_.]{0,63}$/;
const COMPACT_JWS = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
/** TLS failures happen before the request is written (handshake): not delivered */
const TLS_FAILURE = /^(ERR_TLS_|ERR_SSL_|EPROTO$)|CERT|^UNABLE_TO_/;

/**
 * Not delivered (-1) vs outcome unknown (0) for a forward that threw. Only failures that are known to happen before the
 * request was written count as not delivered (calls.ts pre-connect set, plus TLS); anything else (timeout, reset, a
 * redirect answer) may come after the app read the request.
 */
export function forwardFailureStatus(e: unknown): -1 | 0 {
  if (isPreConnect(e)) return -1;
  const code = (e as { cause?: { code?: unknown } })?.cause?.code;
  return typeof code === "string" && TLS_FAILURE.test(code) ? -1 : 0;
}

/** BRIDGE §16: the relay loop. Resolves on shutdown, in standalone mode, or when draining. */
export async function runPersonOpRelay(ctx: BridgeContext, signal: AbortSignal): Promise<void> {
  const seen = new Set<string>();
  const queue: BridgePersonOp[] = [];
  let active = 0;
  let wake: (() => void) | undefined;
  const pump = () => {
    while (active < RELAY_CONCURRENCY && queue.length) {
      const item = queue.shift() as BridgePersonOp;
      active += 1;
      void relayOne(ctx, item).finally(() => {
        active -= 1;
        pump();
        wake?.();
      });
    }
  };
  // a final config with `standalone` ends the relay at once, also mid-poll
  let poll: AbortController | undefined;
  const onTable = (next: { standalone?: boolean } | undefined) => {
    if (next?.standalone) poll?.abort();
  };
  ctx.on("table", onTable);
  const onAbort = () => wake?.();
  signal.addEventListener("abort", onAbort, { once: true });
  let backoff = FIRST_BACKOFF_MS;
  let notFoundLoggedAt: number | undefined;
  // error pause: jittered, doubling 1 s → 30 s; reset by every well-formed batch
  const failed = (code: string): number => {
    if (code) ctx.log.warn("bridge.person_ops.poll_failed", { code });
    const wait = jitter(backoff);
    backoff = Math.min(backoff * 2, MAX_BACKOFF_MS);
    return wait;
  };
  try {
    while (!signal.aborted) {
      if (ctx.table?.standalone || !ctx.identity || ctx.draining) return;
      // no pull while every slot is busy: a row taken now would wait here instead of in Core's queue
      while (active + queue.length >= RELAY_CONCURRENCY && !signal.aborted) await new Promise<void>((r) => (wake = r));
      wake = undefined;
      if (signal.aborted) return;
      const started = Date.now();
      poll = new AbortController();
      let wait = 0;
      try {
        const res = await portalRequest(ctx, "GET", `${PATH}?wait=${PERSON_OP_RELAY.pollWaitS}`, undefined, (PERSON_OP_RELAY.pollWaitS + 15) * 1000, AbortSignal.any([signal, poll.signal]));
        if (res.status === 200) {
          const items = parseBatch((await readCapped(res, MAX_BATCH_BYTES)).toString("utf8"));
          if (items) {
            backoff = FIRST_BACKOFF_MS;
            for (const item of items) if (acceptItem(ctx, item, seen)) queue.push(item as BridgePersonOp);
            pump();
            // a batch with rows is followed by the next pull at once; an early empty one by a pause (no tight loop)
            if (!items.length) wait = MIN_POLL_INTERVAL_MS - (Date.now() - started);
          } else wait = failed("malformed");
        } else {
          await res.body?.cancel().catch(() => undefined);
          const ra = Number(res.headers.get("retry-after"));
          // 429 / 503: Core's Retry-After (≤ 5 min), else the error pause, at least 5 s
          if (res.status === 429 || res.status === 503) wait = Number.isFinite(ra) && ra > 0 ? Math.min(ra, 300) * 1000 : Math.max(failed(""), 5_000);
          else if (res.status === 404) {
            const quiet = notFoundLoggedAt !== undefined && Date.now() - notFoundLoggedAt < NOT_FOUND_LOG_EVERY_MS;
            if (!quiet) notFoundLoggedAt = Date.now();
            wait = failed(quiet ? "" : "http_404");
          } else wait = failed(`http_${res.status}`);
        }
      } catch {
        if (signal.aborted || poll.signal.aborted) continue;
        wait = failed("network");
      }
      if (wait > 0) await sleep(wait, signal);
    }
  } finally {
    ctx.off("table", onTable);
    signal.removeEventListener("abort", onAbort);
  }
}

function parseBatch(text: string): unknown[] | undefined {
  try {
    const b = JSON.parse(text) as unknown;
    return isRecord(b) && Array.isArray(b.items) ? b.items : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Shape check of one pulled row (L24: refuse only what the bridge would act on). A row without a usable id cannot be
 * answered (the id is a path segment) and is dropped with a log line; a row with an id but a bad `ins`, `op`, K14 or
 * body is answered -1 (not delivered) without contacting the app. A pop seen before is never handled again.
 */
function acceptItem(ctx: BridgeContext, item: unknown, seen: Set<string>): boolean {
  const id = isRecord(item) ? item.id : undefined;
  if (typeof id !== "string" || !POP_ID.test(id)) {
    ctx.log.warn("bridge.person_op.invalid", { code: "id" });
    return false;
  }
  if (seen.has(id)) {
    ctx.log.warn("bridge.person_op.duplicate", { pop: id });
    return false;
  }
  seen.add(id);
  if (seen.size > SEEN_MAX) seen.delete(seen.values().next().value as string);
  const it = item as Record<string, unknown>;
  const ok =
    typeof it.ins === "string" && INS_ID.test(it.ins) && typeof it.op === "string" && OP_NAME.test(it.op) &&
    typeof it.jws === "string" && it.jws.length <= 16_384 && COMPACT_JWS.test(it.jws) &&
    typeof it.body === "string" && Buffer.byteLength(it.body, "utf8") <= PERSON_OP_RELAY.maxInputBytes;
  if (ok) return true;
  ctx.log.warn("bridge.person_op.invalid", { pop: id, code: "shape" });
  void postResult(ctx, { pop: id as BridgePersonOp["id"], status: -1, body: "" });
  return false;
}

async function relayOne(ctx: BridgeContext, item: BridgePersonOp): Promise<void> {
  const started = Date.now();
  let result: { status: number; body: string };
  try {
    const app = ctx.table?.apps.get(item.ins);
    if (!app) result = refusal(REFUSED.instanceUnknown, "the app instance is not in this bridge's config");
    // C354: a routing hint, fail closed: only an app that declares it serves person ops gets one
    else if (!ctx.proofCaps.hasAppCap(item.ins, APP_CAP_PERSON_OP)) result = refusal(REFUSED.appUnsupported, "the app does not serve person ops");
    // BSD-07: an internalUrl outside the allow-list is never contacted
    else if (app.refused) result = { status: -1, body: "" };
    else result = await forward(ctx, app.entry.internalUrl, item);
  } catch {
    result = { status: 0, body: "" };
  }
  await postResult(ctx, { pop: item.id, ...result });
  ctx.log.info("bridge.person_op.relayed", { pop: item.id, ins: item.ins, op: item.op, status: result.status, ms: Date.now() - started });
}

/** One request to the app, never retried. The body is the UTF-8 of Core's string, unchanged (its sha256 is K14 `bd`). */
async function forward(ctx: BridgeContext, internalUrl: string, item: BridgePersonOp): Promise<{ status: number; body: string }> {
  let res: Response;
  try {
    res = await ctx.fetch(new URL("/tb/v1/person-op", internalUrl), {
      method: "POST",
      headers: { "TB-Person-Op": item.jws, "content-type": "application/json" },
      body: Buffer.from(item.body, "utf8"),
      redirect: "error",
      // the one deadline covers the answer's body too
      signal: AbortSignal.timeout(PERSON_OP_RELAY.bridgeForwardS * 1000),
    });
  } catch (e) {
    return { status: forwardFailureStatus(e), body: "" };
  }
  try {
    const buf = await readCapped(res, PERSON_OP_RELAY.maxOutputBytes);
    return { status: res.status, body: buf.toString("utf8") };
  } catch {
    // over maxOutputBytes, or the answer broke off after the app got the request: outcome unknown
    return { status: 0, body: "" };
  }
}

/** `POST /bridge/person-ops/{pop}/result`; one more try only when the first did not reach Core (network error). */
async function postResult(ctx: BridgeContext, input: BridgePersonOpResultInput): Promise<void> {
  for (let attempt = 1; attempt <= 2; attempt++) {
    try {
      const res = await portalRequest(ctx, "POST", `${PATH}/${input.pop}/result`, input, RESULT_TIMEOUT_MS);
      await res.body?.cancel().catch(() => undefined);
      if (!res.ok) ctx.log.warn("bridge.person_op.result_failed", { pop: input.pop, code: `http_${res.status}` });
      return;
    } catch {
      if (attempt === 2) ctx.log.warn("bridge.person_op.result_failed", { pop: input.pop, code: "network" });
    }
  }
}
