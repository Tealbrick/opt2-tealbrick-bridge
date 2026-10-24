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
 *  - `hook_tool` (spec 0.1.68, bridge 0.2.8, BRIDGE v0.1.68) = on all three dynamic call paths (a listed entry, `<op>_call`,
 *    the relay's dynamic call; all through calls.ts `route`) the hook `call.target.tool` is the resolution's canonical tool
 *    with its crud/effect/holdFamily, absent for static ops; a resolution whose tool differs from the requested name or is not
 *    `^[a-z][a-z0-9_]{1,62}$` is refused `dynamic_resolve_failed` (calls.ts `resolve`, `effectiveOp`).
 *  - `secret_output` (spec 0.1.68, MANIFEST M-OP-12) is NOT declared yet (C354, BRIDGE23-3): the secretOutput code paths are in
 *    (tools.ts `visibleOps`, calls.ts `route` / `forward`), but this build pins a manifest validator (0.1.30) that refuses a
 *    manifest with `secretOutput`, so no such app can run here. Declare it in the change that re-pins manifest >= 0.1.31.
 */
import type { BridgeCap } from "@opt2-tealbrick/spec/bridge";

/** spec 0.1.68: `hook_tool` joins `BRIDGE_CAPS`; local until the spec pin carries it (`secret_output` waits for the manifest re-pin). */
export type DeclaredCap = BridgeCap | "hook_tool";

export const BRIDGE_CAPS_DECLARED: readonly DeclaredCap[] = ["owner_rows", "events", "hook_tool"];

/**
 * The caps to report NOW (StatusReport, re-minted standalone slices): the build's set, without `events` while the event log
 * is not available (bridge 0.2.7, events.ts: not open, or unhealthy for 5 min until 3 good probes). A copy.
 */
export function bridgeCaps(ctx: { events?: { available: boolean } | undefined }): BridgeCap[] {
  // spec 0.1.68: the wire type is the pinned BridgeCap until the re-pin; the wire schema takes any cap matching its pattern
  return BRIDGE_CAPS_DECLARED.filter((c) => c !== "events" || ctx.events?.available === true) as BridgeCap[];
}
