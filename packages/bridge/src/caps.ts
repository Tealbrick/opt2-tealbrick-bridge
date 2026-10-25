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
 */
import type { BridgeCap } from "@opt2-tealbrick/spec/bridge";

export const BRIDGE_CAPS_DECLARED: readonly BridgeCap[] = ["owner_rows", "events", "model_roles"];

/**
 * The caps to report NOW (StatusReport, re-minted standalone slices): the build's set, without `events` while the event log
 * is not available (bridge 0.2.7, events.ts: not open, or unhealthy for 5 min until 3 good probes). A copy.
 */
export function bridgeCaps(ctx: { events?: { available: boolean } | undefined }): BridgeCap[] {
  return BRIDGE_CAPS_DECLARED.filter((c) => c !== "events" || ctx.events?.available === true);
}
