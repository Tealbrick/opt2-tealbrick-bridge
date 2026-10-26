/**
 * App-caller additions of BRIDGE v0.1.77 (spec 0.1.77, C367): `tb.hold_status` on the companion path (P3, cap `app_hold_status`,
 * §8.3) and the caller context of a companion call (P4, cap `app_call_context`, §8.5). Pure helpers; `calls.ts` applies them
 * in `route`.
 */
import { callerContextProblem } from "@opt2-tealbrick/manifest";
import type { JsonObject, JsonValue } from "@opt2-tealbrick/spec/bridge";
import { BridgeError, isRecord } from "./util.ts";

/** The standard op an app caller may read the status of its own holds with (MANIFEST M-CP-3, SDK-API §4.7). */
export const APP_HOLD_STATUS_OP = "tb.hold_status";

/**
 * PK-D6 / QA-SPEC58-3 (BRIDGE §8.3): the first miniapp-sdk release that implements SDK-API §4.7 (the target answers an app caller
 * only for the holds that caller raised). The bridge routes `tb.hold_status` for an APP caller only to a target whose last reported
 * `sdkVersion` is at least this; a lower or unknown one is refused `not_in_workflow` and the target is not called.
 */
// reservation; set to the released miniapp-sdk that ships SDK-API §4.7 (C367) at merge
export const APP_HOLD_STATUS_MIN_SDK = "0.1.41";

/** `major.minor.patch` with an optional `-prerelease` / `+build` tail; anything else is not a version. */
const SEMVER = /^(\d{1,9})\.(\d{1,9})\.(\d{1,9})(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;

/**
 * Is `version` at least `min`? A missing, non-string or malformed `version` is not (fail closed). Semver order for the numbers;
 * a prerelease of `min` itself is lower than `min` (`0.1.41-rc.1` < `0.1.41`) and a prerelease of a higher number is higher.
 */
export function sdkVersionAtLeast(version: unknown, min: string): boolean {
  if (typeof version !== "string") return false;
  const v = SEMVER.exec(version);
  const m = SEMVER.exec(min);
  if (!v || !m) return false;
  for (let i = 1; i <= 3; i++) {
    const a = Number(v[i]);
    const b = Number(m[i]);
    if (a !== b) return a > b;
  }
  return v[4] === undefined || m[4] !== undefined;
}

/**
 * BRIDGE §8.5 (cap `app_call_context`): the caller keys to merge into the op body `context`, or none.
 * `raw` is `CallEnvelope.context` as the caller sent it (`undefined` = absent). Absent or `{}` → none. Else
 * `callerContextProblem(<verified product>, raw)` (the one validator, manifest package): a problem is `400 input_invalid` with
 * `details.pointer`; the message never repeats a value. `verifiedProduct` is the `prd` of the presented companion grant, never
 * anything from the envelope; `null` when the grant has none (a non-empty context is then refused).
 */
export function callerContextKeys(raw: unknown, verifiedProduct: string | null): JsonObject | undefined {
  if (raw === undefined) return undefined;
  const problem = callerContextProblem(verifiedProduct, raw);
  if (problem) throw new BridgeError("input_invalid", 400, problem.message, { pointer: problem.pointer });
  if (!isRecord(raw) || Object.keys(raw).length === 0) return undefined;
  return { ...(raw as Record<string, JsonValue>) };
}
