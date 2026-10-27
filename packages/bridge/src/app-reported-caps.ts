/**
 * App-reported capabilities (C373 P1, BRIDGE §8.6 rule 7; C354 capability gate). The bridge copies each app INSTANCE's
 * `AppStatus.caps` (claim, then every push), normalised by the APP_CAPS rules, into `StatusReport.apps[].caps`. Core's
 * workflow-grant gate reads `app_workflow_grants` (caller) and `grant_wfl` (target) there. The bridge never gates on them
 * itself, and a cap never widens anything (it is a self-report). A companion service never reaches this class. In memory.
 */
import type { InstanceId } from "@opt2-tealbrick/spec/credentials";
import { APP_CAPS, APP_CAPS_LIMITS, type AppCap } from "./spec-p1.temp.ts";
import type { Table } from "./table.ts";

const KNOWN_APP_CAPS: readonly string[] = APP_CAPS;

/**
 * `AppStatus.caps` normalised by the APP_CAPS rules: unknown entries dropped; not an array of strings within APP_CAPS_LIMITS
 * (entries, length) → undefined (= omitted, fail closed). A copy, sorted, without duplicates.
 */
export function normaliseAppCaps(v: unknown): AppCap[] | undefined {
  if (!Array.isArray(v) || v.length > APP_CAPS_LIMITS.maxEntries) return undefined;
  if (!v.every((e) => typeof e === "string" && e.length <= APP_CAPS_LIMITS.maxLength)) return undefined;
  return [...new Set(v as string[])].filter((e) => KNOWN_APP_CAPS.includes(e)).sort() as AppCap[];
}

/** What each app INSTANCE last reported (claim, then every push). */
export class AppCaps {
  private readonly byIns = new Map<InstanceId, { caps: AppCap[] | undefined; iat?: number }>();

  /** the normalised caps of the instance; undefined = none reported or malformed */
  get(ins: InstanceId): AppCap[] | undefined {
    return this.byIns.get(ins)?.caps;
  }

  onClaim(ins: InstanceId, caps: unknown): void {
    this.byIns.set(ins, { caps: normaliseAppCaps(caps) });
  }

  /** a status push replaces the stored value, unless its assertion is older than the last accepted push (a held-back old push) */
  onStatus(ins: InstanceId, caps: unknown, iat: number): void {
    const stored = this.byIns.get(ins);
    if (stored?.iat !== undefined && iat < stored.iat) return;
    this.byIns.set(ins, { caps: normaliseAppCaps(caps), iat });
  }

  onTable(next: Table): void {
    for (const ins of this.byIns.keys()) if (!next.apps.has(ins)) this.byIns.delete(ins);
  }
}

/** The `caps` member of the status report entry; absent when the app reported none or a malformed value. */
export function reportedCaps(caps: AppCap[] | undefined): { caps?: never } {
  // TEMP: the pinned spec types `StatusReport.apps[].caps` as `AppCap[]` of spec 0.1.77 (`person_op` only)
  return (caps ? { caps } : {}) as { caps?: never };
}
