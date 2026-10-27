/**
 * TEMP (C373 P1, per-workflow companion grants): a mirror of what this bridge needs from the spec PR specs#63
 * (`spec/c373-p1-workflow-grants`, head 2a3cbae, package/SPEC_VERSION 0.1.84, doc label v0.1.82; BRIDGE §8.6, CREDENTIALS v0.1.82,
 * CORE v0.1.82) until the bridge pins the spec release that contains it. Every name and value here is IDENTICAL to that branch
 * (`packages/spec/src/{credentials,bridge,routes}.ts`); the file named in each comment is where it lives there. At the re-pin, delete
 * this file and import the same names from `@opt2-tealbrick/spec/{bridge,credentials,routes}` (L1: one owner); nothing else changes.
 */
import type { CompactJws, EpochS, IsoTime } from "@opt2-tealbrick/spec/bridge";
import type { InstanceId, InstanceRef, Sha256Digest } from "@opt2-tealbrick/spec/credentials";
import type { CrudAction, ProductId, SnakeId } from "@opt2-tealbrick/spec/manifest";

// ── credentials.ts ──

/** The workflow id of the CALLER app (`wfl` claim). Not `wf` (the allowed op ids). */
export type WorkflowId = string;
/** `wfl` claim, `CallEnvelope.workflow`, withdrawal records: 3..40 chars. */
export const WORKFLOW_ID_PATTERN = "^[a-z][a-z0-9-]{2,39}$";
/** Lifetime of a per-workflow companion grant (a K10 grant with `wfl`), exp − iat, seconds. */
export const WORKFLOW_GRANT_TTL_SEC = 900;
/** `WorkflowGrantClaims` (the part the bridge reads): `CompanionGrantClaims & { wfl?: WorkflowId }`. */
export interface WorkflowGrantClaimsPart {
  wfl?: WorkflowId;
  prd?: ProductId;
}

// ── bridge.ts ──

/** `BRIDGE_CAPS` gains `"app_workflow_grants"`; the cap name of per-workflow companion grants. */
export const WORKFLOW_GRANTS_CAP = "app_workflow_grants" as const;
/** Live withdrawal records per caller instance that Core keeps in the config (a further one becomes a `wflEpoch` bump). */
export const WORKFLOW_WITHDRAWN_MAX = 64;

/** `WorkflowGrantWithdrawal`: one config `workflowGrantsWithdrawn` record. */
export interface WorkflowGrantWithdrawal {
  sub: InstanceRef;
  wfl: WorkflowId;
  /** absent = every target of that workflow */
  aud?: InstanceRef;
  at: EpochS;
}

/** `ConfigCredentialFields` additions: sent only to a bridge that declares `app_workflow_grants`. */
export interface WorkflowConfigFields {
  workflowGrantsWithdrawn?: WorkflowGrantWithdrawal[];
  /** per caller instance ref: every wfl grant of that caller with `iat ≤` the value is withdrawn */
  wflEpoch?: Record<InstanceRef, EpochS>;
  /** per caller instance ref: the target instance refs whose companion edge is enabled and licensed AND whose entry has `perWorkflow` */
  workflowGrantEdges?: Record<InstanceRef, InstanceRef[]>;
}

/** `BridgeErrorCode` additions decided by the bridge gate (BRIDGE §8.6). */
export const WORKFLOW_GATE_CODES = {
  mismatch: "workflow_mismatch",
  required: "workflow_grant_required",
  withdrawn: "workflow_grant_withdrawn",
} as const;
/** `BridgeErrorCode` additions: 409 when the gate is off (standalone included). */
export const WORKFLOW_GRANTS_UNSUPPORTED = "workflow_grants_unsupported";
/** `BridgeErrorCode` additions: 503, a relay got no answer from Core. */
export const PORTAL_UNAVAILABLE = "portal_unavailable";

/** `APP_CAPS` (spec 0.1.77 has `person_op` only) and `APP_CAPS_LIMITS` (unchanged). */
export const APP_CAPS = ["person_op", "app_workflow_grants", "grant_wfl"] as const;
export type AppCap = (typeof APP_CAPS)[number];
export const APP_CAPS_LIMITS = { maxEntries: 16, maxLength: 32 } as const;

/** `WORKFLOW_GRANT_REQUEST_LIMITS` */
export const WORKFLOW_GRANT_REQUEST_LIMITS = { titleMaxChars: 120, reasonMaxChars: 280, targetsMax: 8, opsPerTargetMax: 64 } as const;
/** The bridge's own bucket for the three relays, per caller instance (separate from the call bucket). */
export const WORKFLOW_GRANT_RELAY_LIMIT = { perMinute: 240, burst: 60 } as const;

export interface WorkflowGrantTarget {
  product: ProductId;
  ops: SnakeId[];
  crud: CrudAction[];
}
/** `POST /tb/v1/workflow-grants/request` body (app → bridge); the bridge adds `ins`, a body field `ins` is refused. */
export interface WorkflowGrantRequestBody {
  wfl: WorkflowId;
  title: string;
  targets: WorkflowGrantTarget[];
  reason?: string;
}
/** `POST /tb/v1/workflow-grants/get` body. Without `aud` = status only. */
export interface WorkflowGrantGetBody {
  wfl: WorkflowId;
  aud?: InstanceId;
}
/** `POST /tb/v1/workflow-grants/release` body. */
export interface WorkflowGrantReleaseBody {
  wfl: WorkflowId;
}
export type WorkflowGrantState = "none" | "requested" | "applied" | "rejected" | "withdrawn";
/** The answer of all three relays. */
export interface WorkflowGrantStatus {
  wfl: WorkflowId;
  state: WorkflowGrantState;
  title: string | null;
  applied: WorkflowGrantTarget[] | null;
  appliedDigest: Sha256Digest | null;
  pending: { digest: Sha256Digest; targets: WorkflowGrantTarget[]; reviewUrl: string } | null;
  rejectedDigest: Sha256Digest | null;
  updatedAt: IsoTime | null;
}
/** Answer of `workflow-grants/get`. */
export interface WorkflowGrantGetResult {
  status: WorkflowGrantStatus;
  grant?: CompactJws;
}

/** `BRIDGE_INTERNAL_PATHS` additions: the three relays (app → bridge, TB-Assert). */
export const WORKFLOW_GRANT_PATHS = {
  workflowGrantRequest: "/tb/v1/workflow-grants/request",
  workflowGrantGet: "/tb/v1/workflow-grants/get",
  workflowGrantRelease: "/tb/v1/workflow-grants/release",
} as const;

// ── routes.ts ──

/**
 * ROUTES rows `bridge_api.workflow_grant_request|get|release` (`method: "POST"`, `auth: ["bridge"]`, `transport: "json"`): the paths
 * are relative to the Core API prefix (`/api/v1`, as `bridge_api.person_ops` `/bridge/person-ops`).
 */
export const CORE_WORKFLOW_GRANT_PATHS = {
  request: "/api/v1/bridge/workflow-grants/request",
  get: "/api/v1/bridge/workflow-grants/get",
  release: "/api/v1/bridge/workflow-grants/release",
} as const;
