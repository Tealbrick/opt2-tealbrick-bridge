/**
 * One key per provider (spec 0.1.92, BRIDGE "v0.1.92 — one key per provider"; Martin 2026-11-06: "input a key once … and it
 * will disperse it for all the apps that need it"). The provider key lives in S3 under `pk:@<providerId>` (the provider-key
 * namespace, so an older bridge serves bindings that name it). A requirement name is LINKED to a provider when every
 * account_default entry with that name declares the same keyNeeded provider (id or label). A linked name resolves to the
 * value stored under it, else to the provider key. Values that follow the provider key are mirrored under their own names
 * so a rollback to a bridge before 0.2.16 serves the same values. Nothing here logs, renders or returns a value to a page.
 */

import type { InstanceId } from "@opt2-tealbrick/spec/credentials";
import { MODEL_PROVIDERS, type ModelProvider } from "@opt2-tealbrick/spec/models";
import type { BridgeState, ModelBinding } from "./state.ts";
import { isProviderKeyName, PROVIDER_KEY_PREFIX } from "./state.ts";
import { keyRequirements, type Table } from "./table.ts";

/** spec 0.1.92 `PROVIDER_DEFAULT_KEY_PREFIX` (the bridge pins an older spec package; same value) */
export const PROVIDER_DEFAULT_KEY_PREFIX = "pk:@";
export const providerSlot = (providerId: string): string => `${PROVIDER_DEFAULT_KEY_PREFIX}${providerId}`;
export const isProviderSlot = (name: string): boolean => name.startsWith(PROVIDER_DEFAULT_KEY_PREFIX);
/** an owner-named key of a bridge before 0.2.16 ("older named key"): `pk:<label>`, not a provider slot */
export const isNamedKey = (name: string): boolean => isProviderKeyName(name) && !isProviderSlot(name);
export const namedLabel = (name: string): string => name.slice(PROVIDER_KEY_PREFIX.length);

/** spec 0.1.92 `keyProviderOf`: the keyNeeded provider a requirement's `provider` names (id or full label) */
export function keyProviderOf(provider: unknown): ModelProvider | undefined {
  if (typeof provider !== "string") return undefined;
  const v = provider.trim().replace(/\s+/g, " ").toLowerCase();
  if (!v) return undefined;
  return MODEL_PROVIDERS.find((p) => p.keyNeeded && (p.id === v || p.label.toLowerCase() === v));
}

export const keyedProviders = (): ModelProvider[] => MODEL_PROVIDERS.filter((p) => p.keyNeeded);

/** one requirement name as the page and the resolver see it */
export interface KeyName {
  name: string;
  label: string;
  /** the linked provider; undefined = a plain app key */
  provider?: ModelProvider;
  products: string[];
  ins: InstanceId[];
  required: boolean;
}

/** every account_default requirement name, linked (item 2) or plain, sorted by name */
export function keyNames(t: Pick<Table, "config"> | undefined): KeyName[] {
  if (!t) return [];
  const all = keyRequirements(t);
  const byName = new Map<string, typeof all>();
  for (const k of all) byName.set(k.name, [...(byName.get(k.name) ?? []), k]);
  const out: KeyName[] = [];
  for (const [name, entries] of byName) {
    if (!entries.every((e) => e.source === "account_default")) {
      // a name some app keeps as app_own is never linked; the account_default part stays a plain key
      const ad = entries.filter((e) => e.source === "account_default");
      if (ad.length) out.push(plain(name, ad));
      continue;
    }
    const providers = entries.map((e) => keyProviderOf(e.provider)?.id);
    const first = providers[0];
    const provider = first && providers.every((p) => p === first) ? keyProviderOf(first) : undefined;
    out.push({ ...plain(name, entries), ...(provider ? { provider } : {}) });
  }
  return out.sort((a, b) => a.name.localeCompare(b.name));
}

function plain(name: string, entries: ReturnType<typeof keyRequirements>): KeyName {
  return {
    name,
    label: entries[0]?.label ?? name,
    products: [...new Set(entries.map((e) => e.product))].sort(),
    ins: [...new Set(entries.map((e) => e.ins))],
    required: entries.some((e) => e.required),
  };
}

export const linkedNames = (t: Pick<Table, "config"> | undefined, providerId?: string): KeyName[] =>
  keyNames(t).filter((k) => k.provider && (!providerId || k.provider.id === providerId));

/** the owner's explicit overrides that still count (item 7): a linked name with a stored value */
export function overridesOf(state: Pick<BridgeState, "keyStore">, t: Pick<Table, "config"> | undefined): Set<string> {
  const linked = new Set(linkedNames(t).map((k) => k.name));
  const list = Array.isArray(state.keyStore.overrides) ? state.keyStore.overrides : [];
  return new Set(list.filter((n) => typeof n === "string" && linked.has(n) && !isProviderKeyName(n) && Object.hasOwn(state.keyStore.values, n)));
}

/** item 4: the value an app gets for a requirement name (undefined = not set) */
export function resolveAppKey(state: Pick<BridgeState, "keyStore">, t: Pick<Table, "config"> | undefined, name: string): string | undefined {
  const values = state.keyStore.values;
  if (Object.hasOwn(values, name)) return values[name];
  const k = keyNames(t).find((x) => x.name === name);
  if (!k?.provider) return undefined;
  const slot = providerSlot(k.provider.id);
  return Object.hasOwn(values, slot) ? values[slot] : undefined;
}

/** how one linked name stands against its provider key */
export type LinkState = "follows" | "override" | "differs" | "own";
export function linkState(state: Pick<BridgeState, "keyStore">, t: Pick<Table, "config"> | undefined, k: KeyName): LinkState {
  if (!k.provider) return "own";
  const values = state.keyStore.values;
  if (overridesOf(state, t).has(k.name)) return "override";
  if (!Object.hasOwn(values, k.name)) return "follows";
  const slot = providerSlot(k.provider.id);
  if (!Object.hasOwn(values, slot)) return "differs";
  return values[k.name] === values[slot] ? "follows" : "differs";
}

/** the S3 name a binding's key resolves from (item 6); undefined = a provider without keys or an unknown provider */
export function bindingKeyName(b: Pick<ModelBinding, "provider" | "keyName">): string | undefined {
  const p = MODEL_PROVIDERS.find((x) => x.id === b.provider);
  if (!p?.keyNeeded) return undefined;
  if (!b.keyName) return providerSlot(p.id);
  if (isProviderSlot(b.keyName)) return b.keyName === providerSlot(p.id) ? b.keyName : undefined;
  return isProviderKeyName(b.keyName) ? b.keyName : undefined;
}

/** one source of a stored value for a provider (item 8) */
export interface ValueSource {
  kind: "provider" | "app" | "named";
  /** S3 name */
  ref: string;
}

/** item 8: the sources of one provider grouped by equal value (order: provider key first, then page order); values never leave */
export function valueGroups(state: Pick<BridgeState, "keyStore" | "bindings">, t: Pick<Table, "config"> | undefined, providerId: string): ValueSource[][] {
  const values = state.keyStore.values;
  const sources: ValueSource[] = [];
  const slot = providerSlot(providerId);
  if (Object.hasOwn(values, slot)) sources.push({ kind: "provider", ref: slot });
  const ov = overridesOf(state, t);
  for (const k of linkedNames(t, providerId)) if (Object.hasOwn(values, k.name) && !ov.has(k.name)) sources.push({ kind: "app", ref: k.name });
  const named = new Set<string>();
  for (const b of state.bindings) if (b.provider === providerId && b.keyName && isNamedKey(b.keyName) && Object.hasOwn(values, b.keyName)) named.add(b.keyName);
  for (const n of [...named].sort()) sources.push({ kind: "named", ref: n });
  const groups: ValueSource[][] = [];
  for (const s of sources) {
    const g = groups.find((x) => values[(x[0] as ValueSource).ref] === values[s.ref]);
    if (g) g.push(s);
    else groups.push([s]);
  }
  return groups;
}

/** the S3 changes of "Save for all apps" (item 5a); `value` null = delete the provider key (item 5c) */
export function providerKeyChanges(state: Pick<BridgeState, "keyStore" | "bindings">, t: Pick<Table, "config"> | undefined, providerId: string, value: string | null): { values: Record<string, string | null>; bindings?: ModelBinding[] } {
  const store = state.keyStore.values;
  const slot = providerSlot(providerId);
  const old = Object.hasOwn(store, slot) ? store[slot] : undefined;
  const ov = overridesOf(state, t);
  const changes: Record<string, string | null> = { [slot]: value };
  for (const k of linkedNames(t, providerId)) {
    if (ov.has(k.name)) continue;
    const has = Object.hasOwn(store, k.name);
    if (value === null) {
      if (has && old !== undefined && store[k.name] === old) changes[k.name] = null;
    } else if (!has || (old !== undefined && store[k.name] === old)) changes[k.name] = value;
  }
  if (value === null) return { values: changes };
  // bindings of this provider without a key name get it written (a rollback resolves them); older named keys whose value is
  // now the provider key's value are switched to it (same value, and they follow it from now on)
  let touched = false;
  const bindings = state.bindings.map((b) => {
    if (b.provider !== providerId || !keyProviderOf(providerId)) return b;
    if (!b.keyName || (isNamedKey(b.keyName) && store[b.keyName] === value)) {
      touched = true;
      return { ...b, keyName: slot };
    }
    return b;
  });
  return touched ? { values: changes, bindings } : { values: changes };
}

/** item 5b: unset linked names whose provider key is set (an app installed later); no keysRev bump */
export function mirrorFills(state: Pick<BridgeState, "keyStore">, t: Pick<Table, "config"> | undefined): Record<string, string> {
  const store = state.keyStore.values;
  const out: Record<string, string> = {};
  for (const k of linkedNames(t)) {
    const slot = providerSlot((k.provider as ModelProvider).id);
    if (!Object.hasOwn(store, k.name) && Object.hasOwn(store, slot)) out[k.name] = store[slot] as string;
  }
  return out;
}

/** "Used by" of a provider key: "App · role" for bindings that resolve to it, "App · NAME" for linked names that follow it */
export interface UsedBy {
  roles: { ins: InstanceId; product: string; role: string }[];
  names: { name: string; products: string[] }[];
}
