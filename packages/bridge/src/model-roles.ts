/**
 * Workspace model-role registry (v0.1.63, BRIDGE §15): the declared roles of the signed config, the data policy check
 * (§15.3), resolve for apps (§15.4) and the label-only status rows (§15.5). The bindings live in S11 (state.ts), the key
 * values in S3. The bridge never calls a model or a provider (§1.1), and never resolves a name: it classifies by text,
 * stores, checks and hands over.
 */
import { isIPv4, isIPv6 } from "node:net";
import type { ModelRoleFetchResponse, ModelRoleRequirementEntry, ModelRoleStatus } from "@opt2-tealbrick/spec/bridge";
import type { InstanceId } from "@opt2-tealbrick/spec/credentials";
import { DATA_POLICIES, DATA_POLICY_RANK, type DataPolicy, MODEL_PROVIDERS, MODEL_ROLES, type ModelProvider, type ModelRole, NEVER_LOCAL_HOSTNAMES, type PolicyBasis } from "@opt2-tealbrick/spec/models";
import type { BridgeContext } from "./context.ts";
import { isProviderKeyName, type ModelBinding } from "./state.ts";
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
  const list = t?.config.modelRoleRequirements;
  if (!Array.isArray(list)) return [];
  return list.filter((e) => !!e && isModelRole(e.role) && isDataPolicy(e.minPolicy) && typeof e.ins === "string" && Array.isArray(e.usedBy));
}

// ── §15.3 local check (spec follow-up #49, QA-SPEC49-1/-2): one algorithm for base URLs and Own hosts, text only ──

/** step 0, input hygiene: `\`, `@`, their look-alikes (U+FF20, U+FE6B, U+FF3C) and percent forms (`%40`, `%5C`, any case),
 *  whitespace, `?` and `#` are refused anywhere (parser differentials) … */
const UNSAFE_INPUT = /[\\@\s?#\uff20\ufe6b\uff3c]|%40|%5c/i;
/** … and control characters U+0000–U+001F and U+007F (NUL and DEL included) anywhere */
const hasControl = (s: string) => [...s].some((ch) => (ch.codePointAt(0) as number) < 0x20 || ch.codePointAt(0) === 0x7f);

/** steps 0–1: the parsed URL, or undefined (refused). Only http(s). */
export function parseModelUrl(input: string): URL | undefined {
  if (!input || UNSAFE_INPUT.test(input) || hasControl(input)) return undefined;
  try {
    const u = new URL(input);
    return u.protocol === "http:" || u.protocol === "https:" ? u : undefined;
  } catch {
    return undefined;
  }
}

interface HostInfo {
  /** lower case, one trailing dot removed, IPv6 brackets stripped, an IPv4-mapped IPv6 turned into dotted IPv4 */
  host: string;
  ip4: string | null;
  ip6: string | null;
}

/** step 2: Node prints an IPv4-mapped IPv6 in hex (`[::ffff:808:808]`): the last 32 bits become dotted IPv4 BEFORE step 3 */
function hostInfo(u: URL): HostInfo {
  let host = u.hostname.toLowerCase().replace(/\.$/, "");
  if (host.startsWith("[")) host = host.slice(1, -1);
  const mapped = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(host);
  if (mapped) {
    const n = Number.parseInt(mapped[1] as string, 16) * 65536 + Number.parseInt(mapped[2] as string, 16);
    host = [24, 16, 8, 0].map((s) => (n >>> s) & 255).join(".");
  }
  if (isIPv4(host)) return { host, ip4: host, ip6: null };
  return { host, ip4: null, ip6: isIPv6(host) ? host : null };
}

const ip4Num = (ip: string) => ip.split(".").reduce((n, p) => n * 256 + Number(p), 0);
/** IPv4 in `base/bits` */
const in4 = (ip: string, base: string, bits: number) => (bits === 0 ? true : Math.floor(ip4Num(ip) / 2 ** (32 - bits)) === Math.floor(ip4Num(base) / 2 ** (32 - bits)));
const hextet1 = (ip6: string) => Number.parseInt(ip6.split(":")[0] || "0", 16);
const PRIVATE4: readonly [string, number][] = [
  ["127.0.0.0", 8],
  ["10.0.0.0", 8],
  ["172.16.0.0", 12],
  ["192.168.0.0", 16],
];
/** CGNAT 100.64/10 (tailnet addresses): local only when owner-listed; written as numbers (scripts/check-literals.ts) */
const CGNAT: [string, number] = [[100, 64, 0, 0].join("."), 10];

/** step 3: NEVER_LOCAL addresses and NEVER_LOCAL_HOSTNAMES (link-local, cloud metadata, "this network", unspecified) */
function neverLocal(h: HostInfo): boolean {
  if ((NEVER_LOCAL_HOSTNAMES as readonly string[]).includes(h.host)) return true;
  if (h.ip4) {
    const [a, b, c, d] = h.ip4.split(".").map(Number) as [number, number, number, number];
    return (a === 169 && b === 254) || (a === 100 && b === 100 && c === 100 && d === 200) || h.ip4 === "192.0.0.192" || h.ip4 === "168.63.129.16" || a === 0;
  }
  if (h.ip6) return h.ip6 === "::" || h.ip6 === "fd00:ec2::254" || (hextet1(h.ip6) & 0xffc0) === 0xfe80;
  return false;
}

/** private / loopback addresses of step 4 */
function privateAddress(h: HostInfo): boolean {
  if (h.ip4) return PRIVATE4.some(([base, bits]) => in4(h.ip4 as string, base, bits));
  if (h.ip6) return h.ip6 === "::1" || (hextet1(h.ip6) & 0xfe00) === 0xfc00;
  return false;
}

/** an own-network IP literal (Transport rule): private IPv4, CGNAT or fc00::/7 */
function ownNetIpLiteral(h: HostInfo): boolean {
  if (h.ip4) return [...PRIVATE4, CGNAT].some(([base, bits]) => in4(h.ip4 as string, base, bits));
  return !!h.ip6 && (hextet1(h.ip6) & 0xfe00) === 0xfc00;
}

const originOf = (raw: string): string | undefined => {
  try {
    return new URL(raw.trim()).origin;
  } catch {
    return undefined;
  }
};

/** The two lists step 4 and 5 compare origins with: machine-managed TB_OWN_INFRA_ORIGINS, the owner's Own hosts (S11). */
export interface OwnNet {
  infra: readonly string[];
  hosts: readonly string[];
}
export const ownNet = (ctx: Pick<BridgeContext, "ownInfraOrigins" | "state">): OwnNet => ({ infra: ctx.ownInfraOrigins, hosts: ctx.state.ownHosts ?? [] });

export type LocalClass = "verified" | "owner_listed" | "not_local";

/**
 * §15.3 for a base URL: refused (`reason`) or the class + the canonical form (`href`, the only form stored and served).
 * Transport: `http:` only for a verified host or an owner-listed own-network IP literal.
 */
export function classifyBase(input: string, own: OwnNet): { cls: LocalClass; href: string } | { refused: string } {
  const u = parseModelUrl(input);
  if (!u) return { refused: "the base URL must be an http or https address without a user name, password, spaces, query or fragment." };
  const h = hostInfo(u);
  // `.railway.internal` is an exact suffix including the dot, after the trailing dot is gone: `railway.internal`,
  // `xrailway.internal` and `a.railway.internal.evil.com` are not local
  const verified = h.host === "localhost" || h.host.endsWith(".railway.internal") || privateAddress(h) || own.infra.some((o) => originOf(o) === u.origin);
  const listed = own.hosts.some((o) => originOf(o) === u.origin);
  const cls: LocalClass = neverLocal(h) ? "not_local" : verified ? "verified" : listed ? "owner_listed" : "not_local";
  if (u.protocol === "http:" && !(cls === "verified" || (cls === "owner_listed" && ownNetIpLiteral(h)))) return { refused: "use an https address; plain http is allowed only on your own network." };
  return { cls, href: u.href };
}

/** §15.3 for an Own hosts entry: an exact origin (no path); names need https; NEVER_LOCAL refused; a public IP is a warning. */
export function classifyOwnHost(input: string): { href: string; origin: string; warnPublic: boolean } | { refused: string } {
  const u = parseModelUrl(input);
  if (!u) return { refused: "enter an http or https origin without a user name, password, spaces, query or fragment." };
  if (u.pathname !== "/") return { refused: "enter the origin only (scheme, host and port), without a path." };
  const h = hostInfo(u);
  if (neverLocal(h)) return { refused: "this address is link-local, cloud metadata or unspecified; it never counts as your own network." };
  if (u.protocol === "http:" && !ownNetIpLiteral(h)) return { refused: "use https for a name or a public address; plain http is allowed only for a private or tailnet IP address." };
  // a public IPv4 or IPv6 literal is accepted with a warning: traffic to it crosses the internet
  return { href: u.href, origin: u.origin, warnPublic: (!!h.ip4 || !!h.ip6) && !ownNetIpLiteral(h) };
}

/** The class of a stored URL now (env and list changes re-classify it); a URL that would now be refused is not local. */
export function localClass(url: string | null | undefined, own: OwnNet): LocalClass {
  const r = url ? classifyBase(url, own) : undefined;
  return r && "cls" in r ? r.cls : "not_local";
}

/** The canonical URL apps get: the binding's own base URL, else the provider default (null when neither). */
export function baseUrlOf(b: ModelBinding): string | null {
  const raw = b.baseUrl ?? providerById(b.provider)?.defaultBaseUrl;
  if (!raw) return null;
  return parseModelUrl(raw)?.href ?? raw;
}

/**
 * Effective gateway (QA-SPEC49-4): the provider routes to other upstreams, has no default address, or the binding points
 * somewhere else than its default. Its zdr tick names the host, and a model change needs a new attestation.
 */
export function effectiveGateway(p: ModelProvider, baseUrl: string | undefined): boolean {
  if (p.gateway || !p.defaultBaseUrl) return true;
  return !!baseUrl && baseUrl !== parseModelUrl(p.defaultBaseUrl)?.href;
}

/**
 * The policy a stored binding has NOW and why, re-checked at every resolve and status: `local` while its URL is verified or
 * owner-listed (an env or list change can take that away), `zdr` while the provider offers it and the owner's attestation
 * is stored; else `standard`. `zdr` and owner-listed `local` are `owner_attested`.
 */
export function effectivePolicy(b: ModelBinding, own: OwnNet): { policy: DataPolicy; basis: PolicyBasis } {
  if (b.dataPolicy === "local") {
    const cls = localClass(baseUrlOf(b), own);
    if (cls === "verified") return { policy: "local", basis: "verified" };
    if (cls === "owner_listed") return { policy: "local", basis: "owner_attested" };
  }
  if (b.dataPolicy === "zdr" && providerById(b.provider)?.zdrOffered && b.zdrAttestedAt) return { policy: "zdr", basis: "owner_attested" };
  return { policy: "standard", basis: "verified" };
}

/**
 * §15.3 (specs#49 3129040): an `http:` binding whose URL no longer passes the transport rule (its host stopped being local:
 * env or Own hosts change) is not served at all (resolve `role_not_set`, status `set: false`): a key never goes in clear
 * text to a host that is not on the owner's network.
 */
export function servable(b: ModelBinding, own: OwnNet): boolean {
  const url = baseUrlOf(b);
  return !url?.startsWith("http:") || "cls" in classifyBase(url, own);
}

export const policyMeets = (have: DataPolicy, needed: DataPolicy): boolean => DATA_POLICY_RANK[have] >= DATA_POLICY_RANK[needed];

/** §15.1 resolve order: the instance's override, then the workspace default. An override is used even when it fails the
 *  policy (§15.4 step 2: no fall back to the default; the owner set it on purpose). */
export function resolveBinding(bindings: readonly ModelBinding[], ins: InstanceId, role: ModelRole): ModelBinding | undefined {
  return bindings.find((b) => b.role === role && b.ins === ins) ?? bindings.find((b) => b.role === role && !b.ins);
}

/**
 * The bound key's value: null for a provider without keys; undefined when a needed key is missing — not set, the provider
 * unknown, or the binding names something that is not a provider key (spec 0.1.69 / QA-BRIDGE22-1: a requirement key never
 * satisfies a binding, e.g. a binding stored by the earlier 0.2.8 shape that names an app key).
 */
export function boundKey(b: ModelBinding, values: Readonly<Record<string, string>>): string | null | undefined {
  const p = providerById(b.provider);
  if (!p) return undefined;
  if (!p.keyNeeded) return null;
  return b.keyName && isProviderKeyName(b.keyName) && Object.hasOwn(values, b.keyName) ? values[b.keyName] : undefined;
}

/**
 * §15.5: one row per `modelRoleRequirements[]` entry, labels only (provider id, model, data policy, policy basis), never a
 * base URL, key name or key value. `set` = a binding resolves and its key is set; the labels are null (basis absent) when not.
 */
export function roleStatuses(ctx: BridgeContext): ModelRoleStatus[] {
  const { bindings, keyStore } = ctx.state;
  return roleRequirements(ctx.table).map((e) => {
    const b = resolveBinding(bindings, e.ins, e.role);
    const own = ownNet(ctx);
    const set = !!b && servable(b, own) && boundKey(b, keyStore.values) !== undefined;
    const eff = b && set ? effectivePolicy(b, own) : null;
    return {
      role: e.role,
      ins: e.ins,
      set,
      policyOk: !!eff && policyMeets(eff.policy, e.minPolicy),
      provider: set && b ? b.provider : null,
      model: set && b ? b.model : null,
      dataPolicy: eff?.policy ?? null,
      ...(eff ? { policyBasis: eff.basis } : {}),
    };
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
  const own = ownNet(ctx);
  // step 2: no binding, an unknown provider, or an http binding that may no longer be served
  if (!b || !providerById(b.provider) || !servable(b, own)) throw new BridgeError("role_not_set", 404);
  const have = effectivePolicy(b, own).policy;
  if (!policyMeets(have, needed)) throw new BridgeError("role_policy_too_low", 403, "the bound model does not meet the app's data policy", { needed, have });
  const key = boundKey(b, ctx.state.keyStore.values);
  if (key === undefined) throw new BridgeError("role_not_set", 404);
  return { role, provider: b.provider, model: b.model, baseUrl: baseUrlOf(b), key, dataPolicy: have, dims: role === "embeddings" ? (b.dims ?? null) : null, keysRev: ctx.state.keyStore.keysRev };
}
