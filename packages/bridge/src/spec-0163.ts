// Mirror of @opt2-tealbrick/spec 0.1.63 (specs#42) — replace with the import after the spec release.
// Synced with specs#42 head 9db11fe (QA-SPEC42 fixes).
// Source: packages/spec/src/models.ts (whole file) and the v0.1.63 parts of bridge.ts, credentials.ts (BRIDGE §15).
// Values are copied exactly; the types extend the 0.1.57 shapes this package pins with the optional 0.1.63 members.
import type { AgentEntry, BridgeCap, StatusReport, WorkspaceConfig } from "@opt2-tealbrick/spec/bridge";
import type { InstanceId, PersonTicketKeysClaims } from "@opt2-tealbrick/spec/credentials";
import type { ProductId } from "@opt2-tealbrick/spec/manifest";

// ── models.ts ──

/** What a model call is for. One binding per role (workspace default, optional per-app override). "Chat" = `reasoning`. */
export const MODEL_ROLES = ["embeddings", "rerank", "reasoning", "utility", "dreaming", "summarize", "vision", "transcribe"] as const;
export type ModelRole = (typeof MODEL_ROLES)[number];

/**
 * Where inference runs and what the provider may keep.
 * - `local`: base URL on the owner's private network or own server; the bridge checks the URL (BRIDGE §15.3).
 * - `zdr`: rented inference under a zero-data-retention contract; the owner attests it per binding (not verifiable).
 * - `standard`: any other.
 */
export const DATA_POLICIES = ["local", "zdr", "standard"] as const;
export type DataPolicy = (typeof DATA_POLICIES)[number];

/** Higher = stricter. A binding satisfies `minPolicy` when `DATA_POLICY_RANK[binding] >= DATA_POLICY_RANK[minPolicy]`. */
export const DATA_POLICY_RANK: Readonly<Record<DataPolicy, number>> = { standard: 0, zdr: 1, local: 2 };

export interface ModelProvider {
  /** stable id, stored in bindings */
  id: string;
  label: string;
  /** roles the provider serves (from provider docs; the app's first real call is the proof — the bridge calls no model) */
  roles: readonly ModelRole[];
  /** an API key is needed (false for local servers without auth) */
  keyNeeded: boolean;
  /** runs on the owner's machine or network: binding defaults to `local` and needs a base URL */
  local: boolean;
  /** the owner may attest a zero-data-retention contract for it (C336 Q3: owner-attested; gateways and custom addresses
   *  included, because the owner, not Tealbrick, holds the upstream contract) */
  zdrOffered: boolean;
  /** speaks the OpenAI HTTP API (chat/embeddings) at `baseUrl` */
  openaiCompatible: boolean;
  /** absent = the owner must enter a base URL */
  defaultBaseUrl?: string;
}

/**
 * Compatible providers per role. A wrong row is a spec patch, never app code. Role support is from provider docs and the
 * v1 Knowledge "Models" step; UNVERIFIED by test call.
 */
export const MODEL_PROVIDERS: readonly ModelProvider[] = [
  { id: "openai", label: "OpenAI", roles: ["embeddings", "reasoning", "utility", "dreaming", "summarize", "vision", "transcribe"], keyNeeded: true, local: false, zdrOffered: true, openaiCompatible: true, defaultBaseUrl: "https://api.openai.com/v1" },
  { id: "anthropic", label: "Anthropic", roles: ["reasoning", "utility", "dreaming", "summarize", "vision"], keyNeeded: true, local: false, zdrOffered: true, openaiCompatible: false, defaultBaseUrl: "https://api.anthropic.com" },
  { id: "google", label: "Google Gemini", roles: ["embeddings", "reasoning", "utility", "dreaming", "summarize", "vision", "transcribe"], keyNeeded: true, local: false, zdrOffered: false, openaiCompatible: false, defaultBaseUrl: "https://generativelanguage.googleapis.com" },
  { id: "voyage", label: "Voyage AI", roles: ["embeddings", "rerank"], keyNeeded: true, local: false, zdrOffered: false, openaiCompatible: false, defaultBaseUrl: "https://api.voyageai.com/v1" },
  { id: "openrouter", label: "OpenRouter", roles: ["embeddings", "rerank", "reasoning", "utility", "dreaming", "summarize", "vision"], keyNeeded: true, local: false, zdrOffered: true, openaiCompatible: true, defaultBaseUrl: "https://openrouter.ai/api/v1" },
  { id: "deepseek", label: "DeepSeek", roles: ["reasoning", "utility", "dreaming", "summarize"], keyNeeded: true, local: false, zdrOffered: false, openaiCompatible: true, defaultBaseUrl: "https://api.deepseek.com/v1" },
  { id: "together", label: "Together AI", roles: ["embeddings", "rerank", "reasoning", "utility", "dreaming", "summarize", "vision"], keyNeeded: true, local: false, zdrOffered: false, openaiCompatible: true, defaultBaseUrl: "https://api.together.xyz/v1" },
  { id: "mistral", label: "Mistral AI", roles: ["embeddings", "reasoning", "utility", "dreaming", "summarize", "vision"], keyNeeded: true, local: false, zdrOffered: false, openaiCompatible: true, defaultBaseUrl: "https://api.mistral.ai/v1" },
  { id: "azure-openai", label: "Azure OpenAI", roles: ["embeddings", "reasoning", "utility", "dreaming", "summarize", "vision", "transcribe"], keyNeeded: true, local: false, zdrOffered: true, openaiCompatible: true },
  { id: "ollama", label: "Ollama (own server)", roles: ["embeddings", "reasoning", "utility", "dreaming", "summarize", "vision"], keyNeeded: false, local: true, zdrOffered: false, openaiCompatible: true },
  { id: "llama-server", label: "llama.cpp server (own server)", roles: ["embeddings", "rerank", "reasoning", "utility", "dreaming", "summarize"], keyNeeded: false, local: true, zdrOffered: false, openaiCompatible: true },
  { id: "lm-studio", label: "LM Studio (own machine)", roles: ["embeddings", "reasoning", "utility", "dreaming", "summarize", "vision"], keyNeeded: false, local: true, zdrOffered: false, openaiCompatible: true },
  { id: "litellm", label: "LiteLLM proxy", roles: ["embeddings", "rerank", "reasoning", "utility", "dreaming", "summarize", "vision", "transcribe"], keyNeeded: true, local: false, zdrOffered: true, openaiCompatible: true },
  { id: "openai-compatible", label: "OpenAI-compatible (custom address)", roles: ["embeddings", "rerank", "reasoning", "utility", "dreaming", "summarize", "vision", "transcribe"], keyNeeded: true, local: false, zdrOffered: true, openaiCompatible: true },
];

/** App attention codes for model roles (MANIFEST §7.1). The bridge only forwards them (AppStatus.attention). */
export const MODEL_ROLE_ATTENTION = ["model_role_missing", "model_role_optional", "embeddings_changed"] as const;

/** `provider` everywhere (bindings, status rows, hints, K11 claim) is a `MODEL_PROVIDERS` id of this form. */
export const PROVIDER_ID_PATTERN = "^[a-z][a-z0-9-]{1,31}$" as const;
/** `model` labels (bindings, status rows, hints): 1..128 chars, no whitespace, control characters or `//`, so a pasted key
 *  sentence or a URL with spaces cannot pass as a label; the bridge page refuses anything else (BRIDGE §15.2). */
export const MODEL_ID_PATTERN = "^(?!.*//)[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}$" as const;
/** Max role hints in `tickets.keys` input and the K11 `roles` claim. */
export const MODEL_ROLE_HINTS_MAX = 8;

/** Agent card persona (PORTAL-API v0.1.63): markdown, the system-prompt fragment the owner edits. The limit counts UTF-16
 *  code units (JavaScript `.length`); a longer persona in a config is dropped for that agent (BRIDGE §15.6). */
export const PERSONA_MAX_CHARS = 8000;

/** MCP resource URI under which the bridge serves the calling agent's persona (BRIDGE §15.6). */
export const PERSONA_RESOURCE_URI = "tb://agent/persona" as const;

// ── bridge.ts (v0.1.63 parts) ──

/** v0.1.63 (QA-SPEC42-1): BRIDGE_CAPS + `model_roles` = the bridge implements BRIDGE §15 in full. The bridge's own set lives
 *  in caps.ts (the one place that names caps). */
export type BridgeCap0163 = BridgeCap | "model_roles";

/** v0.1.63 (C330(4), BRIDGE §15.4): model-role resolve refusals (BridgeErrorCode members) */
export type ModelRoleErrorCode = "role_not_declared" | "role_not_set" | "role_policy_too_low";

/** v0.1.63: one declared model role of one instance (BRIDGE §15). */
export interface ModelRoleRequirementEntry {
  role: ModelRole;
  ins: InstanceId;
  product: ProductId;
  required: boolean;
  minPolicy: DataPolicy;
  /** `"app"` or a service id */
  usedBy: string[];
}

/** WorkspaceConfig with the v0.1.63 member: manifest `settings.modelRoles[]` per instance. Absent (older Core) = none. */
export type WorkspaceConfig0163 = WorkspaceConfig & { modelRoleRequirements?: ModelRoleRequirementEntry[] };

/** AgentEntry with the v0.1.63 member: the card's persona (markdown, ≤ PERSONA_MAX_CHARS); absent = none. BRIDGE §15.6. */
export type AgentEntry0163 = AgentEntry & { persona?: string };

/** v0.1.63 (BRIDGE §15.5): presence + labels of one declared role; `provider`/`model`/`dataPolicy` null when unset. */
export interface ModelRoleStatus {
  role: ModelRole;
  ins: InstanceId;
  set: boolean;
  policyOk: boolean;
  provider: string | null;
  model: string | null;
  dataPolicy: DataPolicy | null;
}

/** v0.1.63 rejected code: kind `config` + code `persona_too_long` = an agent persona over PERSONA_MAX_CHARS, dropped. */
export const PERSONA_TOO_LONG = "persona_too_long" as const;

/** StatusReport with the v0.1.63 members: `roles[]` (labels only, exactly the keys of schema
 *  `model-role-status.schema.json#/$defs/modelRoleStatus`) and the `model_roles` cap. */
export type StatusReport0163 = Omit<StatusReport, "bridge"> & { bridge: Omit<StatusReport["bridge"], "caps"> & { caps?: BridgeCap0163[] }; roles?: ModelRoleStatus[] };

/** v0.1.63 (BRIDGE §15.4): `GET /tb/v1/model-roles/<role>` with `TB-Assert`; `Cache-Control: no-store`. */
export interface ModelRoleFetchResponse {
  role: ModelRole;
  /** MODEL_PROVIDERS id */
  provider: string;
  model: string;
  baseUrl: string | null;
  /** the bound key's value; null for a provider that needs no key */
  key: string | null;
  dataPolicy: DataPolicy;
  /** embeddings only: vector size, when the owner set it */
  dims: number | null;
  /** one revision for keys AND role bindings */
  keysRev: number;
}

/** BRIDGE_INTERNAL_PATHS.modelRoles (v0.1.63, BRIDGE §15.4) */
export const MODEL_ROLES_PATH = "/tb/v1/model-roles/{role}" as const;

// ── credentials.ts (v0.1.63 parts) ──

/** K11 `pur: keys` with the v0.1.63 member: role bindings the key page pre-fills (display only, never applied without submit). */
export type PersonTicketKeysClaims0163 = PersonTicketKeysClaims & { roles?: { role: ModelRole; provider?: string; model?: string; dataPolicy?: DataPolicy }[] };
