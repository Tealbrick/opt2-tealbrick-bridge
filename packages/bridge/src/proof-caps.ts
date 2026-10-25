/**
 * Hook call proof capabilities of the hook apps (spec 0.1.52, C268 B / C268b / C268c; BRIDGE hooks step 6).
 *
 * The call proof of a hook request carries `bd` = sha256 of the exact request body bytes ONLY to an app whose stored
 * capability set lists `"bd"`: the app declares it in `ClaimRequest.proofClaims` and every `AppStatus.proofClaims`
 * (miniapp-sdk 0.1.36+). It is never inferred from `sdkVersion`. A missing value, a non-array and unknown entries mean none.
 *
 * What may change the stored set (and nothing else, so a network attacker cannot lever a downgrade):
 *  - a CONFIG change of that app's `manifestDigest`, `version`, `candidateManifestDigest` or `candidateVersion` (an update
 *    attempt starts or ends, an E3 rollback included) → dropped;
 *  - a re-CLAIM of the app instance → the claim's set;
 *  - an AppStatus PUSH of the app instance whose `version` or set differs from the stored ones → the push's set, only for a version the
 *    config names for the app and not older (assertion `iat`) than the last accepted push (S3-1: a held-back old push cannot downgrade).
 * NEVER a connect failure, a timeout or a 401 of a hook call (callers of this module do not touch it on those), and a hook
 * call refused 401 is never retried without `bd`. Only an APP-INSTANCE claim or push counts: a companion service (claim or
 * push with a `service`) never reaches this module. A stale capability fails CLOSED: an older app refuses the proof and the
 * hook ends `hook_failed` until its first push.
 *
 * In memory: after a bridge restart the set is empty (no `bd`, which every verifier accepts) until the app's next push.
 *
 * App caps (spec 0.1.70, C354): what an app SERVES (`ClaimRequest.caps`, every `AppStatus.caps`; `person_op` = it serves
 * `POST /tb/v1/person-op`) are stored with the proof claims under the same rules (claim, accepted push, config change). A routing
 * hint only, never an authority: the person-op relay forwards only to an app whose stored caps list `person_op` (fail closed).
 * A value that is not an array of strings within the limits is NO caps; unknown entries are ignored.
 */
import type { InstanceId } from "@opt2-tealbrick/spec/credentials";
import type { Table } from "./table.ts";

/** the capabilities this bridge understands; any other entry is ignored */
const KNOWN_PROOF_CLAIMS: readonly string[] = ["bd"];

/** the known entries of a claim/push `proofClaims` member (missing, non-array and unknown entries: none) */
export function knownProofClaims(v: unknown): ReadonlySet<string> {
  const out = new Set<string>();
  if (Array.isArray(v)) for (const e of v) if (typeof e === "string" && KNOWN_PROOF_CLAIMS.includes(e)) out.add(e);
  return out;
}

/** spec 0.1.70 `APP_CAPS` / `APP_CAPS_LIMITS` (bridge.ts); the same values here while the bridge pins spec 0.1.64 */
const KNOWN_APP_CAPS: readonly string[] = ["person_op"];
const APP_CAPS_MAX_ENTRIES = 16;
const APP_CAPS_MAX_LENGTH = 32;

/** the known entries of a claim/push `caps` member; a non-array, a non-string entry, over 16 entries or an entry over 32 chars: none */
export function knownAppCaps(v: unknown): ReadonlySet<string> {
  const out = new Set<string>();
  if (!Array.isArray(v) || v.length > APP_CAPS_MAX_ENTRIES || v.some((e) => typeof e !== "string" || e.length > APP_CAPS_MAX_LENGTH)) return out;
  for (const e of v as string[]) if (KNOWN_APP_CAPS.includes(e)) out.add(e);
  return out;
}

const same = (a: ReadonlySet<string>, b: ReadonlySet<string>): boolean => a.size === b.size && [...a].every((x) => b.has(x));

export class ProofCaps {
  private readonly byIns = new Map<InstanceId, { version: string | undefined; caps: ReadonlySet<string>; appCaps: ReadonlySet<string>; iat?: number }>();

  /** does the stored set of this app instance list `bd`? */
  hasBd(ins: InstanceId): boolean {
    return this.byIns.get(ins)?.caps.has("bd") ?? false;
  }

  /** does the stored app cap set of this app instance list `cap` (spec 0.1.70 APP_CAPS)? */
  hasAppCap(ins: InstanceId, cap: string): boolean {
    return this.byIns.get(ins)?.appCaps.has(cap) ?? false;
  }

  /** a (re-)claim of the app instance: the claim's sets replace whatever was stored */
  onClaim(ins: InstanceId, version: unknown, proofClaims: unknown, appCaps?: unknown): void {
    this.byIns.set(ins, { version: typeof version === "string" ? version : undefined, caps: knownProofClaims(proofClaims), appCaps: knownAppCaps(appCaps) });
  }

  /**
   * A status push of the app instance: its set replaces the stored one only when the version or the set differs, AND only when
   * (S3-1) the push reports a version the config names for the app (`allowedVersions`: the serving version or the update
   * candidate) and its assertion `iat` is not older than the last accepted push. Otherwise the caps of that push are ignored and
   * the stored set stays: a network attacker who holds back an old push (up to its 60 s validity) and delivers it after an update
   * cannot take `bd` away.
   */
  onStatus(ins: InstanceId, version: unknown, proofClaims: unknown, iat: number, allowedVersions: readonly (string | undefined)[], appCaps?: unknown): void {
    const v = typeof version === "string" ? version : undefined;
    if (v === undefined || !allowedVersions.includes(v)) return;
    const caps = knownProofClaims(proofClaims);
    const app = knownAppCaps(appCaps);
    const stored = this.byIns.get(ins);
    if (stored?.iat !== undefined && iat < stored.iat) return;
    if (!stored ? caps.size === 0 && app.size === 0 : stored.version === v && same(stored.caps, caps) && same(stored.appCaps, app)) {
      if (stored) stored.iat = iat;
      return;
    }
    this.byIns.set(ins, { version: v, caps, appCaps: app, iat });
  }

  /** a new table: an app whose manifest digest, version or update candidate changed (or that left the config) loses its set */
  onTable(next: Table, prev: Table | undefined): void {
    if (!prev) return;
    for (const [ins, was] of prev.apps) {
      const now = next.apps.get(ins);
      if (!now || now.entry.manifestDigest !== was.entry.manifestDigest || now.entry.version !== was.entry.version || now.entry.candidateManifestDigest !== was.entry.candidateManifestDigest || now.entry.candidateVersion !== was.entry.candidateVersion) {
        this.byIns.delete(ins);
      }
    }
  }
}
