/**
 * Workspace model-role registry (v0.1.63, BRIDGE §15): the declared roles of the signed config, the data policy check
 * (§15.3), resolve for apps (§15.4) and the label-only status rows (§15.5). The bindings live in S11 (state.ts), the key
 * values in S3. The bridge never calls a model or a provider (§1.1): it stores, checks and hands over.
 */
import { isIPv4, isIPv6 } from "node:net";
import type { InstanceId } from "@opt2-tealbrick/spec/credentials";
import type { BridgeContext } from "./context.ts";
import {
  DATA_POLICIES,
  DATA_POLICY_RANK,
  type DataPolicy,
  MODEL_PROVIDERS,
  MODEL_ROLES,
  type ModelProvider,
  type ModelRole,
  type ModelRoleFetchResponse,
  type ModelRoleRequirementEntry,
  type ModelRoleStatus,
  type WorkspaceConfig0163,
} from "./spec-0163.ts";
import type { ModelBinding } from "./state.ts";
import type { Table } from "./table.ts";
import { BridgeError } from "./util.ts";

export const isModelRole = (v: unknown): v is ModelRole => typeof v === "string" && (MODEL_ROLES as readonly string[]).includes(v);
export const isDataPolicy = (v: unknown): v is DataPolicy => typeof v === "string" && (DATA_POLICIES as readonly string[]).includes(v);
export const providerById = (id: string): ModelProvider | undefined => MODEL_PROVIDERS.find((p) => p.id === id);

/**
 * The config's `modelRoleRequirements[]` (absent = none). An entry with a role or policy this build does not know is left
 * out (fail closed: its role is "not declared" here, never served under a weaker policy).
 */
export function roleRequirements(t: Table | undefined): ModelRoleRequirementEntry[] {
  const list = (t?.config as WorkspaceConfig0163 | undefined)?.modelRoleRequirements;
  if (!Array.isArray(list)) return [];
  return list.filter((e) => !!e && isModelRole(e.role) && isDataPolicy(e.minPolicy) && typeof e.ins === "string" && Array.isArray(e.usedBy));
}

/** Railway private host names */
const RAILWAY_PRIVATE = /\.railway\.internal$/;
/** tailnet (MagicDNS) host names */
const TAILNET = /\.ts\.net$/;

/** IPv4 local ranges (§15.3 step 3): 127/8, 10/8, 172.16/12, 192.168/16 and CGNAT 100.64/10 (tailnet addresses) */
function localIpv4(host: string): boolean {
  if (!isIPv4(host)) return false;
  const [a, b] = host.split(".").map(Number) as [number, number];
  return a === 127 || a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
}

/** IPv6 local forms: `::1`, fc00::/7 (RFC 4193) and an IPv4-mapped address whose IPv4 passes; never `::` or fe80::/10 */
function localIpv6(host: string): boolean {
  if (!isIPv6(host)) return false;
  if (host === "::1") return true;
  const mapped = /^::ffff:(?:([0-9a-f]{1,4}):([0-9a-f]{1,4})|(\d+\.\d+\.\d+\.\d+))$/.exec(host);
  if (mapped) {
    if (mapped[3]) return localIpv4(mapped[3]);
    const hi = Number.parseInt(mapped[1] as string, 16);
    const lo = Number.parseInt(mapped[2] as string, 16);
    return localIpv4(`${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`);
  }
  const first = Number.parseInt(host.split(":")[0] || "0", 16);
  return (first & 0xfe00) === 0xfc00;
}

/**
 * §15.3 (QA-SPEC42-5), by text only (no DNS): WHATWG parse, http(s) only, no userinfo; host = `hostname` (lower case,
 * IP literals canonical) minus one trailing dot. Local = `localhost`, a Railway private host, a tailnet name, an origin of
 * TB_OWN_INFRA_ORIGINS, a private / loopback / CGNAT IPv4, `::1`, fc00::/7 or an IPv4-mapped local address. Link-local
 * (cloud metadata), `0.0.0.0`, `::` and every other address or name are not local.
 */
export function localUrlOk(url: string | null | undefined, ownInfraOrigins: readonly string[]): boolean {
  if (!url) return false;
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return false;
  }
  if ((u.protocol !== "http:" && u.protocol !== "https:") || u.username || u.password) return false;
  const host = u.hostname.replace(/^\[(.*)\]$/, "$1").replace(/\.$/, "");
  if (host === "localhost" || RAILWAY_PRIVATE.test(host) || TAILNET.test(host) || localIpv4(host) || localIpv6(host)) return true;
  return ownInfraOrigins.some((o) => {
    try {
      return new URL(o.trim()).origin === u.origin;
    } catch {
      return false;
    }
  });
}

/** The URL apps use: the binding's own base URL, else the provider default (null when neither). */
export const baseUrlOf = (b: ModelBinding): string | null => b.baseUrl ?? providerById(b.provider)?.defaultBaseUrl ?? null;

/**
 * The policy a stored binding has NOW, re-checked at every resolve and status: `local` only while its URL passes §15.3 (an
 * env change can take that away), `zdr` only while the provider offers it and the owner's attestation is stored; anything
 * else counts as `standard`.
 */
export function effectivePolicy(b: ModelBinding, ownInfraOrigins: readonly string[]): DataPolicy {
  if (b.dataPolicy === "local") return localUrlOk(baseUrlOf(b), ownInfraOrigins) ? "local" : "standard";
  if (b.dataPolicy === "zdr") return providerById(b.provider)?.zdrOffered && b.zdrAttestedAt ? "zdr" : "standard";
  return "standard";
}

export const policyMeets = (have: DataPolicy, needed: DataPolicy): boolean => DATA_POLICY_RANK[have] >= DATA_POLICY_RANK[needed];

/** §15.1 resolve order: the instance's override, then the workspace default. An override is used even when it fails the
 *  policy (§15.4 step 2: no fall back to the default; the owner set it on purpose). */
export function resolveBinding(bindings: readonly ModelBinding[], ins: InstanceId, role: ModelRole): ModelBinding | undefined {
  return bindings.find((b) => b.role === role && b.ins === ins) ?? bindings.find((b) => b.role === role && !b.ins);
}

/** The bound key's value: null for a provider without keys; undefined when a needed key is not set (or the provider is unknown). */
export function boundKey(b: ModelBinding, values: Readonly<Record<string, string>>): string | null | undefined {
  const p = providerById(b.provider);
  if (!p) return undefined;
  if (!p.keyNeeded) return null;
  return b.keyName && Object.hasOwn(values, b.keyName) ? values[b.keyName] : undefined;
}

/**
 * §15.5: one row per `modelRoleRequirements[]` entry, labels only (provider id, model, data policy), never a base URL, key
 * name or key value. `set` = a binding resolves and its key is set; the labels are null when not set.
 */
export function roleStatuses(ctx: BridgeContext): ModelRoleStatus[] {
  const { bindings, keyStore } = ctx.state;
  return roleRequirements(ctx.table).map((e) => {
    const b = resolveBinding(bindings, e.ins, e.role);
    const set = !!b && boundKey(b, keyStore.values) !== undefined;
    const have = b && set ? effectivePolicy(b, ctx.ownInfraOrigins) : null;
    return { role: e.role, ins: e.ins, set, policyOk: !!have && policyMeets(have, e.minPolicy), provider: set && b ? b.provider : null, model: set && b ? b.model : null, dataPolicy: have };
  });
}

/**
 * §15.4 checks in order for one verified caller (`user` = "app" or the service id): declared → a binding resolves → policy
 * (refusal carries {needed, have} and nothing of the binding) → key set. The caller checks pause first.
 */
export function resolveForCaller(ctx: BridgeContext, t: Table, ins: InstanceId, user: string, role: string): ModelRoleFetchResponse {
  const entries = isModelRole(role) ? roleRequirements(t).filter((e) => e.ins === ins && e.role === role && e.usedBy.includes(user)) : [];
  if (!entries.length || !isModelRole(role)) {
    // C69, as for keys: mid-deploy (app down or its manifest not loaded) a role the next revision adds may not be listed yet
    const app = t.apps.get(ins);
    if (app && (app.down || !app.manifest)) throw new BridgeError("app_unavailable", 503, "the app is updating; retry");
    throw new BridgeError("role_not_declared", 403);
  }
  const needed = entries.map((e) => e.minPolicy).reduce((a, b) => (DATA_POLICY_RANK[b] > DATA_POLICY_RANK[a] ? b : a));
  const b = resolveBinding(ctx.state.bindings, ins, role);
  if (!b || !providerById(b.provider)) throw new BridgeError("role_not_set", 404);
  const have = effectivePolicy(b, ctx.ownInfraOrigins);
  if (!policyMeets(have, needed)) throw new BridgeError("role_policy_too_low", 403, "the bound model does not meet the app's data policy", { needed, have });
  const key = boundKey(b, ctx.state.keyStore.values);
  if (key === undefined) throw new BridgeError("role_not_set", 404);
  return { role, provider: b.provider, model: b.model, baseUrl: baseUrlOf(b), key, dataPolicy: have, dims: role === "embeddings" ? (b.dims ?? null) : null, keysRev: ctx.state.keyStore.keysRev };
}
