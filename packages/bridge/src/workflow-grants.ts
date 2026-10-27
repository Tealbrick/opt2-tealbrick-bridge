/**
 * Per-workflow companion grants (C373 P1; BRIDGE §8.6, CREDENTIALS v0.1.82, specs#63 head 472560d; cap `app_workflow_grants`).
 *
 * A workflow grant is a K10 companion grant with the `wfl` claim (the CALLER app's workflow id). Core mints it on demand, for
 * 15 min, through the relays below; it is never in a slice or in the config. Withdrawal is by small config records only.
 *
 * Gate (`workflowGate`, called from calls.ts `runGate` right after `verifyGrant` and the `sub` = asserting instance check; the
 * re-gate after the before hooks runs it again on the current table). G = the presented grant:
 *  1. G has `wfl` and `exp − iat` > WORKFLOW_GRANT_TTL_SEC → 403 `grant_invalid` (counted `rejected` kind `grant`);
 *  2. G has `wfl` and the envelope `workflow` is absent or differs → 403 `workflow_mismatch`;
 *  3. the envelope has `workflow` and G has no `wfl` (a base grant) → 403 `workflow_grant_required`;
 *  4. G has `wfl`: the `grant_stale` rule is skipped (a workflow grant is never in a slice); instead 403
 *     `workflow_grant_withdrawn` when (a) a `workflowGrantsWithdrawn` record matches (`sub`, `wfl`, `aud` absent or equal,
 *     G.`iat ≤ at`), (b) G.`iat ≤ wflEpoch[sub]`, (c) `workflowGrantEdges[sub]` does not list G.`aud` (ABSENT field or entry =
 *     no edge; never `companionTargets`), (d) G.`held` lacks a family of the current `appsPolicy.held` of the caller's slice
 *     (absent = DEFAULT_HELD_FAMILIES; both sides filtered to the families this bridge knows).
 *     Rule 4 never depends on which other P1 fields the config carries; every malformed field fails closed.
 *  5. the normal `wf` / crud / held checks (gate()) run on G exactly as for a base grant (`not_in_workflow` for ops outside it).
 *
 * Relays (`WorkflowGrantRelay`): `POST /tb/v1/workflow-grants/{request,get,release}` from a claimed APP instance (TB-Assert; a
 * companion service is refused), forwarded to Core with the bridge assertion and `ins` = the verified instance (a body member `ins`
 * is refused). Core's JSON answer is passed through; the bridge never keeps or logs a grant. One bucket per instance.
 *
 * App caps (app-reported-caps.ts): `AppStatus.caps` copied into `StatusReport.apps[].caps`; the bridge itself never gates on them.
 *
 * TEMP (until the P1 manifest re-pin): the pinned manifest (0.1.30) has a CLOSED grant claim set without `wfl`, so its
 * verifyGrant / gate() refuse every workflow grant `grant_invalid` before this gate runs (fail closed). The rules here go live
 * unchanged when the bridge pins the manifest release that knows `wfl` and declares the cap.
 */
import type { IncomingMessage, ServerResponse } from "node:http";
import type { CompanionGrantClaims, InstanceId, InstanceRef } from "@opt2-tealbrick/spec/credentials";
import { DEFAULT_HELD_FAMILIES, HOLD_FAMILIES } from "@opt2-tealbrick/spec/manifest";
import type { BridgeContext } from "./context.ts";
import { portalRequest } from "./portal.ts";
import {
  CORE_WORKFLOW_GRANT_PATHS,
  PORTAL_UNAVAILABLE,
  WORKFLOW_GATE_CODES,
  WORKFLOW_GRANT_PATHS,
  WORKFLOW_GRANT_RELAY_LIMIT,
  WORKFLOW_GRANT_TTL_SEC,
  WORKFLOW_GRANTS_UNSUPPORTED,
  WORKFLOW_ID_PATTERN,
  type WorkflowConfigFields,
  type WorkflowGrantClaimsPart,
} from "./spec-p1.temp.ts";
import { type AppRuntime, insRef, type Table } from "./table.ts";
import { BridgeError, isRecord, parseJson, readBody, readCapped, sendError, sendJson, TokenBucket } from "./util.ts";

export const WORKFLOW_ID_RE = new RegExp(WORKFLOW_ID_PATTERN);

/** The bridge-decided refusal codes of the gate: never passed through from an app answer (H-7), each its own metric label (H-5). */
export const WORKFLOW_GATE_VERDICTS: readonly string[] = Object.values(WORKFLOW_GATE_CODES);

/**
 * `CallEnvelope.workflow` as the caller sent it → the workflow id, or undefined when absent. Not a string matching
 * WORKFLOW_ID_PATTERN → 400 `input_invalid` with `details.pointer` `/workflow` (the message never repeats the value).
 */
export function envelopeWorkflow(raw: unknown): string | undefined {
  if (raw === undefined) return undefined;
  if (typeof raw !== "string" || !WORKFLOW_ID_RE.test(raw)) throw new BridgeError("input_invalid", 400, "workflow must be a workflow id", { pointer: "/workflow" });
  return raw;
}

/** The signed payload of the app's current slice (K9); undefined when the bridge holds no readable slice. */
function slicePayload(app: AppRuntime | undefined): Record<string, unknown> | undefined {
  const payload = app?.entry.slice?.split(".")[1];
  if (!payload) return undefined;
  try {
    const p: unknown = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    return isRecord(p) ? p : undefined;
  } catch {
    return undefined;
  }
}

const KNOWN_FAMILIES: ReadonlySet<string> = new Set(HOLD_FAMILIES);
const knownFamilies = (v: readonly unknown[]): Set<string> => new Set(v.filter((f): f is string => typeof f === "string" && KNOWN_FAMILIES.has(f)));

/** The current `appsPolicy.held` of the caller's slice, filtered to the families this bridge knows; absent or unreadable = DEFAULT_HELD_FAMILIES. */
export function currentHeld(app: AppRuntime | undefined): Set<string> {
  const policy = slicePayload(app)?.appsPolicy;
  const held = isRecord(policy) ? policy.held : undefined;
  return knownFamilies(Array.isArray(held) ? held : DEFAULT_HELD_FAMILIES);
}

const withdrawn = (why: string): BridgeError => new BridgeError(WORKFLOW_GATE_CODES.withdrawn, 403, `this workflow grant is withdrawn (${why}); fetch a new one`);

/**
 * Has the config withdrawn this workflow grant (rules 4a, 4b)? `undefined` = no; else the reason (message only). Fails closed: a
 * `workflowGrantsWithdrawn` that is not an array, a matching record whose `at` is not a number, a `wflEpoch` that is not an
 * object or whose entry for `sub` is not a number → withdrawn.
 */
export function withdrawalReason(config: WorkflowConfigFields, g: { sub: InstanceRef; aud: string; wfl: string; iat: number }): string | undefined {
  const list: unknown = config.workflowGrantsWithdrawn;
  if (list !== undefined) {
    if (!Array.isArray(list)) return "record list unreadable";
    for (const r of list) {
      if (!isRecord(r) || r.sub !== g.sub || r.wfl !== g.wfl) continue;
      if (r.aud !== undefined && r.aud !== g.aud) continue;
      if (typeof r.at !== "number" || !Number.isFinite(r.at) || g.iat <= r.at) return "record";
    }
  }
  const epochs: unknown = config.wflEpoch;
  if (epochs !== undefined) {
    if (!isRecord(epochs)) return "epoch unreadable";
    if (Object.hasOwn(epochs, g.sub)) {
      const e = epochs[g.sub];
      if (typeof e !== "number" || !Number.isFinite(e) || g.iat <= e) return "epoch";
    }
  }
  return undefined;
}

/** Rule 4c: does `workflowGrantEdges[sub]` list `aud`? An absent field, a non-object, an absent or malformed entry: no. */
export function hasWorkflowEdge(config: WorkflowConfigFields, sub: InstanceRef, aud: string): boolean {
  const edges: unknown = config.workflowGrantEdges;
  if (!isRecord(edges) || !Object.hasOwn(edges, sub)) return false;
  const list = edges[sub];
  return Array.isArray(list) && list.includes(aud);
}

/** Rule 4d: does the grant's `held` cover every family of the current `appsPolicy.held`? A `held` that is not an array: no. */
export function heldCoversPolicy(grantHeld: unknown, current: ReadonlySet<string>): boolean {
  if (!Array.isArray(grantHeld)) return false;
  const have = knownFamilies(grantHeld);
  for (const f of current) if (!have.has(f)) return false;
  return true;
}

/**
 * BRIDGE §8.6 rule 2 for an APP caller, on the VERIFIED claims of the presented grant (`sub` = asserting instance). Returns true
 * when the grant is a workflow grant (then the slice-membership `grant_stale` rule does not apply). Throws the refusal.
 */
export function workflowGate(ctx: Pick<BridgeContext, "reject">, t: Table, callerIns: InstanceId, claims: CompanionGrantClaims & WorkflowGrantClaimsPart, workflow: string | undefined): boolean {
  if (!Object.hasOwn(claims, "wfl")) {
    if (workflow !== undefined) throw new BridgeError(WORKFLOW_GATE_CODES.required, 403, "a workflow call needs a workflow grant, not the base grant");
    return false;
  }
  const wfl = claims.wfl;
  // the manifest verifier shape-checks `wfl`; defence in depth before it is compared or logged
  if (typeof wfl !== "string" || !WORKFLOW_ID_RE.test(wfl)) throw new BridgeError("grant_invalid", 403);
  if (typeof claims.exp !== "number" || typeof claims.iat !== "number" || claims.exp - claims.iat > WORKFLOW_GRANT_TTL_SEC) {
    ctx.reject({ kind: "grant", code: "grant_invalid", ins: callerIns, detail: "wfl grant lifetime" });
    throw new BridgeError("grant_invalid", 403);
  }
  if (workflow !== wfl) throw new BridgeError(WORKFLOW_GATE_CODES.mismatch, 403, "the call's workflow is not the workflow of the presented grant");
  const config = t.config as WorkflowConfigFields;
  const sub = insRef(callerIns);
  const why = withdrawalReason(config, { sub, aud: claims.aud, wfl, iat: claims.iat });
  if (why) throw withdrawn(why);
  if (!hasWorkflowEdge(config, sub, claims.aud)) throw withdrawn("no companion edge");
  if (!heldCoversPolicy(claims.held, currentHeld(t.apps.get(callerIns)))) throw withdrawn("held families");
  return true;
}

// ── relays (app → bridge → Core) ──

export type WorkflowGrantRelayKind = keyof typeof CORE_WORKFLOW_GRANT_PATHS;

/** internal listener path → relay kind */
export const WORKFLOW_GRANT_ROUTES: ReadonlyMap<string, WorkflowGrantRelayKind> = new Map([
  [WORKFLOW_GRANT_PATHS.workflowGrantRequest, "request"],
  [WORKFLOW_GRANT_PATHS.workflowGrantGet, "get"],
  [WORKFLOW_GRANT_PATHS.workflowGrantRelease, "release"],
]);

/** a request body holds ≤ 8 targets × 64 ops + title + reason: far below this */
export const WORKFLOW_GRANT_BODY_MAX_BYTES = 64 * 1024;
/** Core's answer (status + one minted grant) */
const CORE_ANSWER_MAX_BYTES = 64 * 1024;
/** no answer within this → 503 `portal_unavailable` (the json transport timeout) */
export const CORE_TIMEOUT_MS = 15_000;

export class WorkflowGrantRelay {
  private readonly ctx: BridgeContext;
  private readonly bucket = new TokenBucket(WORKFLOW_GRANT_RELAY_LIMIT.perMinute / 60, WORKFLOW_GRANT_RELAY_LIMIT.burst);

  constructor(ctx: BridgeContext) {
    this.ctx = ctx;
  }

  /**
   * One relay. `caller` is the verified TB-Assert of the request (internal.ts `assertCaller`, bound to method, path and body).
   * Refusals before Core: a service (403 `no_grant`), the bucket (429), no config (503), standalone (409), a paused instance
   * (403 `paused`, all three relays: the owner revokes in Portal), a body that is not an object with a workflow id `wfl` or that
   * has a member `ins` (400 `input_invalid`). Core unreachable, or no readable answer in time: 503 `portal_unavailable`.
   */
  async handle(kind: WorkflowGrantRelayKind, caller: { ins: InstanceId; svc: string | undefined }, raw: Buffer, res: ServerResponse, requestId: string): Promise<void> {
    const ctx = this.ctx;
    if (caller.svc) throw new BridgeError("no_grant", 403, "a companion service cannot use workflow grants");
    const wait = this.bucket.take(caller.ins);
    if (wait) return sendError(res, new BridgeError("rate_limited", 429, "too many workflow grant requests from this instance; retry later"), requestId, { "retry-after": String(wait) });
    const t = ctx.table;
    if (!t || ctx.configExpired()) throw new BridgeError("config_expired", 503);
    if (t.standalone) throw new BridgeError(WORKFLOW_GRANTS_UNSUPPORTED, 409, "a standalone bridge has no Portal to approve workflow grants");
    if (!t.apps.has(caller.ins)) throw new BridgeError("app_not_claimed", 503, "this instance is not in the bridge's config yet; retry");
    if (t.pausedWorkspace || t.pausedInstances.has(caller.ins)) throw new BridgeError("paused", 403);
    const body = parseJson(raw);
    if (!isRecord(body)) throw new BridgeError("input_invalid", 400, "the body must be a JSON object", { pointer: "" });
    if (Object.hasOwn(body, "ins")) throw new BridgeError("input_invalid", 400, "ins is set by the bridge", { pointer: "/ins" });
    if (typeof body.wfl !== "string" || !WORKFLOW_ID_RE.test(body.wfl)) throw new BridgeError("input_invalid", 400, "wfl must be a workflow id", { pointer: "/wfl" });
    // `ins` = the instance that signed TB-Assert
    const relayed = { ...body, ins: caller.ins };
    const started = Date.now();
    let status = 0;
    try {
      let r: Response;
      try {
        r = await portalRequest(ctx, "POST", CORE_WORKFLOW_GRANT_PATHS[kind], relayed, CORE_TIMEOUT_MS);
      } catch {
        throw new BridgeError(PORTAL_UNAVAILABLE, 503, "Portal is not reachable; retry");
      }
      let answer: unknown;
      try {
        answer = JSON.parse((await readCapped(r, CORE_ANSWER_MAX_BYTES)).toString("utf8"));
      } catch {
        answer = undefined;
      }
      if (!isRecord(answer)) throw new BridgeError(PORTAL_UNAVAILABLE, 503, "Portal answered without a readable body; retry");
      status = r.status;
      sendJson(res, r.status, answer);
    } finally {
      // ids and codes only: never the body, a title, a reason or a minted grant
      ctx.log.info("bridge.workflow_grant.relayed", { ins: caller.ins, kind, wfl: body.wfl, status, ms: Date.now() - started });
    }
  }
}

/** Reads and size-checks a relay body (the assertion binds these exact bytes). */
export function readRelayBody(req: IncomingMessage): Promise<Buffer> {
  return readBody(req, WORKFLOW_GRANT_BODY_MAX_BYTES);
}
