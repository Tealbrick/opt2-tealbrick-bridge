/**
 * Owner-draft relays (C380, DESIGN-C380 §5 step 4, cap `owner_drafts`): an app asks Portal to prepare a stop for the owner to approve.
 * The bridge decides nothing: it proves which instance asks and forwards. Core holds every other check (consent, allowed ops,
 * agents of this workspace, limits), and only the owner's browser approves. No state here: a repeat is Core's `(ins, key)` rule.
 *
 * `POST /tb/v1/owner-drafts{,/get,/withdraw}` from a claimed APP instance (TB-Assert, bound to method, path and body), forwarded
 * with the bridge assertion and `ins` = the verified instance (a body member `ins` is refused). Core's status, JSON answer and
 * `Retry-After` pass through. Never logged: the body, a title, a digest or a step.
 */
import type { IncomingMessage, ServerResponse } from "node:http";
import type { InstanceId } from "@opt2-tealbrick/spec/credentials";
import type { BridgeContext } from "./context.ts";
import { portalRequest } from "./portal.ts";
import { BridgeError, isRecord, parseJson, readBody, readCapped, sendError, sendJson, type TokenBucket } from "./util.ts";

// LOCAL COPY of spec 0.1.89 (bridge.ts, routes.ts). The bridge pins spec 0.1.78 like the manifest it pins; move the pin and drop this
// block when the manifest package pins spec >= 0.1.89 (a spec jump alone breaks the manifest's types).
export const OWNER_DRAFT_PATHS = { request: "/tb/v1/owner-drafts", get: "/tb/v1/owner-drafts/get", withdraw: "/tb/v1/owner-drafts/withdraw" } as const;
const CORE_OWNER_DRAFT_PATHS = { request: "/api/v1/bridge/owner-drafts/request", get: "/api/v1/bridge/owner-drafts/get", withdraw: "/api/v1/bridge/owner-drafts/withdraw" } as const;
const OWNER_DRAFT_KEY_PATTERN = "^pln_[A-Za-z0-9._:-]{1,124}$";
/** a relay got no usable answer from Core */
const PORTAL_UNAVAILABLE = "portal_unavailable";
const OWNER_DRAFTS_UNSUPPORTED = "owner_drafts_unsupported";

export type OwnerDraftKind = keyof typeof OWNER_DRAFT_PATHS;

/** internal listener path → relay kind */
export const OWNER_DRAFT_ROUTES: ReadonlyMap<string, OwnerDraftKind> = new Map([
  [OWNER_DRAFT_PATHS.request, "request"],
  [OWNER_DRAFT_PATHS.get, "get"],
  [OWNER_DRAFT_PATHS.withdraw, "withdraw"],
]);

/** 100 steps of about 80 bytes + title + digest: far below this */
export const OWNER_DRAFT_BODY_MAX_BYTES = 64 * 1024;
/** a `get` answer holds the output of up to 100 steps (edges and connections removed) */
export const OWNER_DRAFT_ANSWER_MAX_BYTES = 1024 * 1024;
/** no answer within this → 503 `portal_unavailable` (the json transport timeout) */
export const OWNER_DRAFT_CORE_TIMEOUT_MS = 15_000;

const KEY_RE = new RegExp(OWNER_DRAFT_KEY_PATTERN);

/** The verified TB-Assert of the request; internal.ts `assertCaller` has checked it against this exact body. */
export interface OwnerDraftCaller {
  ins: InstanceId;
  svc: string | undefined;
}

/**
 * One relay, BRIDGE §8.8. Refusals before Core: a service or a key Core has not listed yet (401 `unauthenticated`), no or expired
 * config (503), standalone (409), an instance or workspace pause (403 `paused`), a body that is not an object with a key, or that has
 * a member `ins` (400 `input_invalid`), then the app bucket (429): a refused body spends nothing. No readable answer from Core: 503 `portal_unavailable`.
 */
export async function relayOwnerDraft(ctx: BridgeContext, kind: OwnerDraftKind, caller: OwnerDraftCaller, bucket: TokenBucket, raw: Buffer, res: ServerResponse, requestId: string, timeoutMs = OWNER_DRAFT_CORE_TIMEOUT_MS): Promise<void> {
  if (caller.svc) throw new BridgeError("unauthenticated", 401, "services cannot ask for owner drafts");
  const t = ctx.table;
  if (!t || ctx.configExpired()) throw new BridgeError("config_expired", 503);
  if (t.standalone) throw new BridgeError(OWNER_DRAFTS_UNSUPPORTED, 409, "a standalone bridge has no Portal to approve an owner draft");
  if (t.pausedWorkspace || t.pausedInstances.has(caller.ins)) throw new BridgeError("paused", 403);
  // assertCaller also accepts the key of a pending claim. Core does not know that key yet, so it cannot speak for the instance here.
  if (!t.instanceKeys.has(`${caller.ins}|`)) throw new BridgeError("unauthenticated", 401, "this instance key is not listed by Portal yet");
  const body = parseJson(raw);
  if (!isRecord(body)) throw new BridgeError("input_invalid", 400, "the body must be a JSON object", { pointer: "" });
  if (Object.hasOwn(body, "ins")) throw new BridgeError("input_invalid", 400, "ins is set by the bridge", { pointer: "/ins" });
  if (typeof body.key !== "string" || !KEY_RE.test(body.key)) throw new BridgeError("input_invalid", 400, "key must be a request key", { pointer: "/key" });
  const wait = bucket.take(caller.ins);
  if (wait) return sendError(res, new BridgeError("rate_limited", 429, "too many requests from this instance; retry later"), requestId, { "retry-after": String(wait) });

  const started = Date.now();
  let status = 0;
  try {
    let r: Response;
    try {
      r = await portalRequest(ctx, "POST", CORE_OWNER_DRAFT_PATHS[kind], { ...body, ins: caller.ins }, timeoutMs);
    } catch {
      throw new BridgeError(PORTAL_UNAVAILABLE, 503, "Portal is not reachable; retry");
    }
    let answer: unknown;
    try {
      answer = JSON.parse((await readCapped(r, OWNER_DRAFT_ANSWER_MAX_BYTES)).toString("utf8"));
    } catch {
      answer = undefined;
    }
    if (!isRecord(answer)) throw new BridgeError(PORTAL_UNAVAILABLE, 503, "Portal answered without a readable body; retry");
    status = r.status;
    const retryAfter = r.headers.get("retry-after");
    sendJson(res, r.status, answer, retryAfter ? { "retry-after": retryAfter } : {});
  } finally {
    // ids and codes only
    ctx.log.info("bridge.owner_draft.relayed", { ins: caller.ins, kind, key: body.key, status, ms: Date.now() - started });
  }
}

/** Reads and size-checks a relay body (the assertion binds these exact bytes). */
export function readOwnerDraftBody(req: IncomingMessage): Promise<Buffer> {
  return readBody(req, OWNER_DRAFT_BODY_MAX_BYTES);
}
