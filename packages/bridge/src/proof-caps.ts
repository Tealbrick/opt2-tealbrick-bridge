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
 *  - an AppStatus PUSH of the app instance whose `version` or set differs from the stored ones → the push's set.
 * NEVER a connect failure, a timeout or a 401 of a hook call (callers of this module do not touch it on those), and a hook
 * call refused 401 is never retried without `bd`. Only an APP-INSTANCE claim or push counts: a companion service (claim or
 * push with a `service`) never reaches this module. A stale capability fails CLOSED: an older app refuses the proof and the
 * hook ends `hook_failed` until its first push.
 *
 * In memory: after a bridge restart the set is empty (no `bd`, which every verifier accepts) until the app's next push.
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

const same = (a: ReadonlySet<string>, b: ReadonlySet<string>): boolean => a.size === b.size && [...a].every((x) => b.has(x));

export class ProofCaps {
  private readonly byIns = new Map<InstanceId, { version: string | undefined; caps: ReadonlySet<string> }>();

  /** does the stored set of this app instance list `bd`? */
  hasBd(ins: InstanceId): boolean {
    return this.byIns.get(ins)?.caps.has("bd") ?? false;
  }

  /** a (re-)claim of the app instance: the claim's set replaces whatever was stored */
  onClaim(ins: InstanceId, version: unknown, proofClaims: unknown): void {
    this.byIns.set(ins, { version: typeof version === "string" ? version : undefined, caps: knownProofClaims(proofClaims) });
  }

  /** a status push of the app instance: its set replaces the stored one only when the version or the set differs */
  onStatus(ins: InstanceId, version: unknown, proofClaims: unknown): void {
    const v = typeof version === "string" ? version : undefined;
    const caps = knownProofClaims(proofClaims);
    const stored = this.byIns.get(ins);
    if (!stored ? v === undefined && caps.size === 0 : stored.version === v && same(stored.caps, caps)) return;
    this.byIns.set(ins, { version: v, caps });
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
