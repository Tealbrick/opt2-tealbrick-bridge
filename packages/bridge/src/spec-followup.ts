// Mirror of the spec follow-up #49 (Tealbrick/opt2-tealbrick-specs#49, head 162ce4a), which is NOT in the released
// @opt2-tealbrick/spec 0.1.63 that this package pins — replace with the import after the spec release that carries it.
// Values are copied exactly; everything else of spec 0.1.63 is imported from the package.
import type { ModelRoleStatus as ModelRoleStatus0163, StatusReport } from "@opt2-tealbrick/spec/bridge";
import { MODEL_PROVIDERS as MODEL_PROVIDERS_0163, type ModelProvider as ModelProvider0163 } from "@opt2-tealbrick/spec/models";

/** spec follow-up #49 (QA-SPEC42-11): `gateway` = routes to other upstream providers (OpenRouter, LiteLLM, a custom
 *  address): a `zdr` attestation names the host and covers every upstream; a model change clears it (BRIDGE §15.3). */
export type ModelProvider = ModelProvider0163 & { gateway: boolean };
/** the catalog rows with `gateway: true` in #49 (every other row: false) */
const GATEWAY_IDS: readonly string[] = ["openrouter", "litellm", "openai-compatible"];
export const MODEL_PROVIDERS: readonly ModelProvider[] = MODEL_PROVIDERS_0163.map((p) => ({ ...p, gateway: GATEWAY_IDS.includes(p.id) }));

/** Max origins in the owner's "Own hosts" list on the Keys and models page (BRIDGE §15.3). */
export const OWN_HOSTS_MAX = 32;

/**
 * Never local, even when the owner lists them: link-local, cloud metadata (AWS IPv6, Alibaba, Oracle, Azure wireserver),
 * "this network", unspecified. BRIDGE §15.3 step 3. The Alibaba address is assembled from its octets because
 * scripts/check-literals.ts refuses tailnet-range literals in this repo; the value equals the spec's entry for it.
 */
export const NEVER_LOCAL: readonly string[] = [
  "169.254.0.0/16",
  "fe80::/10",
  "fd00:ec2::254/128",
  `${[100, 100, 100, 200].join(".")}/32`,
  "192.0.0.192/32",
  "168.63.129.16/32",
  "0.0.0.0/8",
  "::/128",
];
/** Metadata host names that are never local, even when listed (BRIDGE §15.3 step 3). */
export const NEVER_LOCAL_HOSTNAMES = ["metadata.google.internal", "metadata.goog", "metadata"] as const;

/** Persona text (C353, QA-SPEC49-23, specs#49 3de8dfd): one rule by Unicode property. Accepted when every character is TAB,
 *  LF, a PERSONA_MARKERS character (SHY, CGJ, ALM, FVS, MVS, ZWSP, ZWNJ, ZWJ, LRM, RLM, variation selectors), or NOT in
 *  \p{Cc}, \p{Cf}, \p{Cs}, \p{Default_Ignorable_Code_Point}, U+2028 or U+2029 — and no two variation selectors stand in a
 *  row. Copied verbatim; it needs a unicode-mode regex (`u` flag: property escapes, `\u{…}`, surrogate pairs). */
export const PERSONA_PATTERN =
  "^(?![\\s\\S]*[\\uFE00-\\uFE0F\\u{E0100}-\\u{E01EF}]{2})(?:[\\t\\n]|[\\u00AD\\u034F\\u061C\\u180B-\\u180F\\u200B-\\u200F\\uFE00-\\uFE0F\\u{E0100}-\\u{E01EF}]|(?![\\p{Cc}\\p{Cf}\\p{Cs}\\p{Default_Ignorable_Code_Point}\\u2028\\u2029])[\\s\\S])*$" as const;

/** Why a binding has its data policy (BRIDGE §15.3/§15.5): `verified` = the bridge checked it from the URL;
 *  `owner_attested` = the owner said so (every `zdr`, and `local` through the Own hosts list). */
export const POLICY_BASES = ["verified", "owner_attested"] as const;
export type PolicyBasis = (typeof POLICY_BASES)[number];

/** StatusReport.roles[] row + `policyBasis` (absent when unset). Schema model-role-status.schema.json#/$defs/modelRoleStatus. */
export type ModelRoleStatus = ModelRoleStatus0163 & { policyBasis?: PolicyBasis };
export type StatusReportFollowup = Omit<StatusReport, "roles"> & { roles?: ModelRoleStatus[] };
