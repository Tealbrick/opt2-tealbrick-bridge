/**
 * Bridge capabilities (spec 0.1.54, C292): what THIS build implements, reported in every StatusReport as
 * `bridge.caps`. Core copies the set into the slices it signs (`slice.bridge.caps`), the SDK passes it to the app as
 * `ctx.bridgeCaps()`, and a standalone bridge writes it into the slices it re-mints itself (standalone.ts). Apps decide
 * by capability, never by bridge version. Caps are ADVISORY: they never widen access (the SDK authorizes every call).
 *
 * RULE: a cap is listed here ONLY together with the code path it names, in the same change. Never list one ahead of its
 * code, and remove it when the code goes (a bridge that declares a cap it lacks makes apps show a feature that does not
 * work). `test/caps.test.ts` keeps a probe for every entry: it fails when the probe's behaviour is missing, and when an
 * entry has no probe.
 *
 *  - `owner_rows` = the C283 A1 owner-row filter (SDK-API v0.1.50): tools/list lists a scoped static op above grant.crud
 *    that the app's scope summary names in `admittedOps` (tools.ts `visibleOps`, internal.ts `refreshScopeSummary`); the
 *    dynamic catalog body carries `agent` and an entry marked `admitted: "owner"` is listed (calls.ts `catalog`, tools.ts
 *    `buildToolIndex`); and gate() is the manifest >= 0.1.27 gate that skips `op.crud ⊆ grant.crud` for scoped ops.
 *  - `events` = app events, ALL of BRIDGE §14 (spec 0.1.57, bridge 0.2.7): ingest `POST /tb/v1/events` (internal.ts
 *    `ingestEvents`), the per-agent log with fan-out, retention, holds, re-ids and purges (events.ts `EventStore`), and
 *    `tealbrick/events/{list,poll,stream}` + `notifications/tealbrick/event` frames on the agent's `/mcp` session (mcp.ts).
 *    Reported only while the event log is available ({@link bridgeCaps}).
 *  - `model_roles` = ALL of BRIDGE §15 (spec 0.1.63, bridge 0.2.9): S11 bindings beside the key store (state.ts), the "Keys
 *    and models" page (models-page.ts), `GET /tb/v1/model-roles/<role>` (internal.ts, model-roles.ts `resolveForCaller`),
 *    `StatusReport.roles` (model-roles.ts `roleStatuses`) and the persona in instructions + `tb://agent/persona` (mcp.ts).
 *    Core sends `agents[].persona` and `modelRoleRequirements[]` only to a bridge that declares it.
 *  - `hook_tool` (spec 0.1.68, bridge 0.2.10, BRIDGE v0.1.68) = on all three dynamic call paths (a listed entry, `<op>_call`,
 *    the relay's dynamic call; all through calls.ts `route`) the hook `call.target.tool` is the resolution's canonical tool
 *    with its crud/effect/holdFamily, absent for static ops; a resolution whose tool differs from the requested name or is not
 *    `^[a-z][a-z0-9_]{1,62}$` is refused `dynamic_resolve_failed` (calls.ts `resolve`, `effectiveOp`).
 *  - `app_hold_status` (spec 0.1.77, bridge 0.2.11, BRIDGE §8.3, C367 P3) = on the companion path the standard op `tb.hold_status` is
 *    routed when the presented grant's `wf` lists it (calls.ts `runGate`; the I4 CRUD skip of gate() applies), and only to a
 *    target whose last reported `sdkVersion` is at least `APP_HOLD_STATUS_MIN_SDK` (app-calls.ts); otherwise `not_in_workflow`
 *    and the target is not called. Agent calls are unchanged.
 *  - `acting_agents` (spec 0.1.88, bridge 0.2.13, BRIDGE §8.7, C378) = context `tb.acting` on a companion call from the open-call table (target only) and from K15 tickets
 *    (`acting.ts`, calls.ts `route`), `POST /tb/v1/acting-tickets` and `POST /tb/v1/policy-recheck` (internal.ts). Acting facts narrow only: nothing here reads them for access.
 *  - `owner_drafts` (spec 0.1.89, bridge 0.2.14, C380) = the three relays `POST /tb/v1/owner-drafts{,/get,/withdraw}` to Core (owner-drafts.ts, internal.ts). Only Core and the
 *    owner decide. Not reported by a standalone bridge: it has no Portal to approve a draft ({@link bridgeCaps}).
 *  - `app_call_context` (spec 0.1.77, bridge 0.2.11, BRIDGE §8.5, C367 P4) = a companion `CallEnvelope.context` is validated against
 *    the presented grant's verified `prd` (400 `input_invalid` + `details.pointer`), merged into the op body `context` before the
 *    before hooks and bound by the op proof's `ctx` digest (calls.ts `route`, app-calls.ts `callerContextKeys`).
 *  - `secret_output` (spec 0.1.68, MANIFEST M-OP-12) is NOT declared yet (C354, BRIDGE23-3): the secretOutput code paths are in
 *    (tools.ts `visibleOps`, calls.ts `route` / `forward`), but declaring it is its own change (C354). The pinned manifest 0.1.32
 *    accepts a well-formed `secretOutput` manifest with `requires.bridgeCaps: ["secret_output"]`; this build refuses it at
 *    registration (`missingBridgeCap` → `bridge_cap_missing`) because the cap is not declared, so no such app runs here.
 */
import type { BridgeCap } from "@opt2-tealbrick/spec/bridge";
import { ACTING_AGENTS_CAP } from "./acting.ts";

/** spec 0.1.77: `BRIDGE_CAPS` carries every cap this build names (`hook_tool` and `secret_output` since 0.1.68), so a misspelt entry fails to compile. */
// LOCAL COPY of spec 0.1.89 (bridge.ts), like ACTING_AGENTS_CAP: drop it with the spec pin move. Here, not in owner-drafts.ts: that module needs portal.ts, which needs this one.
export const OWNER_DRAFTS_CAP = "owner_drafts";
export type DeclaredCap = BridgeCap | typeof ACTING_AGENTS_CAP | typeof OWNER_DRAFTS_CAP;

export const BRIDGE_CAPS_DECLARED: readonly DeclaredCap[] = ["owner_rows", "events", "model_roles", "hook_tool", "app_hold_status", "app_call_context", ACTING_AGENTS_CAP, OWNER_DRAFTS_CAP];

/**
 * The caps to report NOW (StatusReport, re-minted standalone slices): the build's set, without `events` while the event log
 * is not available (bridge 0.2.7, events.ts: not open, or unhealthy for 5 min until 3 good probes), and without `owner_drafts`
 * on a standalone bridge (no Portal, so an app must not offer the feature). A copy.
 */
export function bridgeCaps(ctx: { events?: { available: boolean } | undefined; table?: { standalone: boolean } | undefined; state?: { standalone: unknown } | undefined }): DeclaredCap[] {
  const standalone = ctx.table?.standalone === true || !!ctx.state?.standalone;
  return BRIDGE_CAPS_DECLARED.filter((c) => (c !== "events" || ctx.events?.available === true) && (c !== OWNER_DRAFTS_CAP || !standalone));
}

/**
 * spec 0.1.68 (C354, MANIFEST `requires.bridgeCaps`, QA-C354-2): the first bridge capability a manifest needs that this build does
 * not declare, else undefined. Needed = `requires.bridgeCaps` plus the caps its features imply (a `secretOutput` op →
 * `secret_output`), exactly as manifest `requiredBridgeCaps()` (sdk#51) computes them; that function is used when the pinned
 * manifest API has it, else the fields are read structurally (`// spec 0.1.68`) until the re-pin. Compared with the build's
 * declared set (never with a version). Only ever refuses: it never widens what an app may do.
 */
export function missingBridgeCap(manifest: unknown, api: object = {}, declared: readonly string[] = BRIDGE_CAPS_DECLARED): string | undefined {
  const shared = (api as { requiredBridgeCaps?: (m: unknown) => string[] }).requiredBridgeCaps;
  const needed = typeof shared === "function" ? shared(manifest) : requiredCapsStructural(manifest);
  return needed.find((c) => !declared.includes(c));
}

function requiredCapsStructural(manifest: unknown): string[] {
  const m = (manifest ?? {}) as { requires?: { bridgeCaps?: unknown }; operations?: unknown };
  const caps = new Set<string>(Array.isArray(m.requires?.bridgeCaps) ? m.requires.bridgeCaps.filter((c): c is string => typeof c === "string") : []);
  if (Array.isArray(m.operations) && m.operations.some((o) => (o as { secretOutput?: unknown } | null)?.secretOutput === true)) caps.add("secret_output");
  return [...caps].sort();
}
