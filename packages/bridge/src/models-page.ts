/**
 * The "Keys and models" page (v0.1.63 BRIDGE §15.2; spec 0.1.92 "one key per provider"): 1 provider keys (one key per
 * provider for all apps), 2 workspace defaults per declared role, 3 overrides per app and role, older named keys and Own
 * hosts. person.ts owns the ticket, session, CSRF and CSP (§9.3) and the "Other app keys" section; this module renders the
 * rest and applies their form posts. Every dynamic value goes through `esc`; key values are
 * write-only; logs carry role, instance, provider id and policy only (never a base URL, key name or value). The bridge
 * never calls a provider: there is no "test" button (§1.1).
 */
import type { ServerResponse } from "node:http";
import type { ModelRoleRequirementEntry } from "@opt2-tealbrick/spec/bridge";
import type { InstanceId, PersonTicketKeysClaims } from "@opt2-tealbrick/spec/credentials";
import { DATA_POLICY_RANK, type DataPolicy, MODEL_ID_PATTERN, MODEL_PROVIDERS, MODEL_ROLE_HINTS_MAX, MODEL_ROLES, type ModelProvider, type ModelRole, OWN_HOSTS_MAX, type PolicyBasis } from "@opt2-tealbrick/spec/models";
import type { BridgeContext } from "./context.ts";
import {
  baseUrlOf,
  boundKey,
  classifyBase,
  classifyOwnHost,
  effectiveGateway,
  effectivePolicy,
  isDataPolicy,
  isModelRole,
  type OwnNet,
  ownNet,
  policyMeets,
  providerById,
  resolveBinding,
  roleRequirements,
  servable,
} from "./model-roles.ts";
import { appChip, esc, htmlPage, ink, linkButton, type PageApp, pageApp } from "./pages.ts";
import {
  bindingKeyName,
  isNamedKey,
  isProviderSlot,
  keyedProviders,
  type LinkState,
  linkedNames,
  linkState,
  namedLabel,
  overridesOf,
  PROVIDER_DEFAULT_KEY_PREFIX,
  providerKeyChanges,
  providerSlot,
  type ValueSource,
  valueGroups,
} from "./provider-keys.ts";
import { isProviderKeyName, type ModelBinding, PROVIDER_KEY_PREFIX, providerKeyName } from "./state.ts";
import type { Table } from "./table.ts";

/** a suggested binding from the ticket (K11 `roles[]`): shown, never stored without the owner's submit */
export interface RoleHint {
  role: ModelRole;
  provider?: string;
  model?: string;
  dataPolicy?: DataPolicy;
}

/** what a models post did: saved (flash on the next view), refused (plain page), or a question first (confirm page) */
export type ModelsOutcome =
  | { kind: "saved"; flash: string }
  | { kind: "refused"; code: string; reason: string }
  | { kind: "confirm"; title: string; text: string; fields: Record<string, string>; button: string; /** a change was stored before the question */ saved?: true };

export const PROVIDER_KEY_LABEL_MAX = 60;
export const PROVIDER_KEYS_MAX = 32;
/** S11 size bound (BRIDGE §1.2) */
export const BINDINGS_MAX_BYTES = 64 * 1024;
const VALUE_MAX_BYTES = 16 * 1024;
/** spec MODEL_ID_PATTERN: 1..128 chars, no whitespace, control characters or `//` */
const MODEL_ID = new RegExp(MODEL_ID_PATTERN);
const MODEL_MAX = 128;
const URL_MAX = 512;
const CONTROL = /\p{Cc}/u;

export const ROLE_LABEL: Record<ModelRole, string> = {
  embeddings: "Embeddings",
  rerank: "Rerank",
  reasoning: "Reasoning (chat)",
  utility: "Utility",
  dreaming: "Dreaming",
  summarize: "Summarize",
  vision: "Vision",
  transcribe: "Transcribe",
};
/** spec follow-up #49 (RM-18): every `zdr` label reads "zero data retention (owner-attested)" */
const POLICY_LABEL: Record<DataPolicy, string> = { local: "local (own network)", zdr: "zero data retention (owner-attested)", standard: "standard" };
/** spec follow-up #49 (QA-SPEC49-2): the label of a policy as it holds now; owner-listed local is not verified */
const policyText = (e: { policy: DataPolicy; basis: PolicyBasis }) => (e.policy === "local" && e.basis === "owner_attested" ? "local (owner-listed, not verified)" : POLICY_LABEL[e.policy]);
const ZDR_TICK = "I confirm a zero-data-retention contract with this provider";
/** spec follow-up #49 (QA-SPEC42-11): a gateway attestation names the host */
const gatewayTick = (host: string) => `I confirm that my contract with ${host} keeps no data for every model it routes this role to`;
const REINDEX_WARNING = "Apps must re-index their memory after this change; each app asks you first";

/** ticket `roles[]` → at most MODEL_ROLE_HINTS_MAX well-formed hints (unknown values dropped) */
export function hintsFrom(claims: PersonTicketKeysClaims): RoleHint[] {
  if (!Array.isArray(claims.roles)) return [];
  const out: RoleHint[] = [];
  for (const h of claims.roles.slice(0, MODEL_ROLE_HINTS_MAX)) {
    if (!h || !isModelRole(h.role)) continue;
    out.push({
      role: h.role,
      ...(typeof h.provider === "string" && providerById(h.provider) ? { provider: h.provider } : {}),
      ...(typeof h.model === "string" && MODEL_ID.test(h.model) ? { model: h.model } : {}),
      ...(isDataPolicy(h.dataPolicy) ? { dataPolicy: h.dataPolicy } : {}),
    });
  }
  return out;
}

// ── shared views of the config ──

interface RoleView {
  role: ModelRole;
  entries: ModelRoleRequirementEntry[];
  products: string[];
  required: boolean;
  minPolicy: DataPolicy;
}

function roleViews(t: Table): RoleView[] {
  const reqs = roleRequirements(t);
  return MODEL_ROLES.filter((r) => reqs.some((e) => e.role === r)).map((role) => {
    const entries = reqs.filter((e) => e.role === role);
    return {
      role,
      entries,
      products: [...new Set(entries.map((e) => e.product))].sort(),
      required: entries.some((e) => e.required),
      minPolicy: entries.map((e) => e.minPolicy).reduce((a, b) => (DATA_POLICY_RANK[b] > DATA_POLICY_RANK[a] ? b : a)),
    };
  });
}

const appName = (ctx: BridgeContext, product: string) => pageApp(ctx, product).name;
const productOf = (t: Table, ins: InstanceId) => t.apps.get(ins)?.entry.product ?? roleRequirements(t).find((e) => e.ins === ins)?.product ?? ins;
const appsText = (ctx: BridgeContext, products: readonly string[]) => [...new Set(products.map((p) => appName(ctx, p)))].sort().join(", ");
const hasValue = (ctx: BridgeContext, name: string) => Object.hasOwn(ctx.state.keyStore.values, name);

/** "reasoning (Notes, Tasks); embeddings (Notes)": which roles and apps one key serves (bindings that resolve to it) */
export function servesText(ctx: BridgeContext, t: Table, keyName: string): string {
  const parts: string[] = [];
  for (const role of MODEL_ROLES) {
    const products = roleRequirements(t)
      .filter((e) => e.role === role)
      .filter((e) => {
        const b = resolveBinding(ctx.state.bindings, e.ins, e.role);
        return !!b && bindingKeyName(b) === keyName;
      })
      .map((e) => e.product);
    if (products.length) parts.push(`${role} (${appsText(ctx, products)})`);
  }
  // a binding of an app that no longer declares the role still names the key
  if (!parts.length && ctx.state.bindings.some((b) => bindingKeyName(b) === keyName)) parts.push("a saved model");
  return parts.join("; ");
}

/** "Used by" of a provider key: app · role for bindings that resolve to it, app · NAME for linked names that follow it */
function usedByText(ctx: BridgeContext, t: Table, providerId: string): string {
  const slot = providerSlot(providerId);
  const out: string[] = [];
  for (const e of roleRequirements(t)) {
    const b = resolveBinding(ctx.state.bindings, e.ins, e.role);
    if (b && bindingKeyName(b) === slot) out.push(`${appName(ctx, e.product)} · ${ROLE_LABEL[e.role]}`);
  }
  for (const k of linkedNames(t, providerId)) if (linkState(ctx.state, t, k) === "follows") out.push(`${appsText(ctx, k.products)} · ${k.name}`);
  return [...new Set(out)].join("; ");
}

/** providers the page shows a row for: set, linked by a requirement, named by a binding, or holding an older named key */
function providersInUse(ctx: BridgeContext, t: Table): ModelProvider[] {
  const ids = new Set<string>();
  for (const p of keyedProviders()) if (hasValue(ctx, providerSlot(p.id))) ids.add(p.id);
  for (const k of linkedNames(t)) ids.add((k.provider as ModelProvider).id);
  for (const b of ctx.state.bindings) if (bindingKeyName(b)) ids.add(b.provider);
  return keyedProviders().filter((p) => ids.has(p.id));
}

const hidden = (fields: Record<string, string>) =>
  Object.entries(fields)
    .map(([k, v]) => `<input type="hidden" name="${esc(k)}" value="${esc(v)}">`)
    .join("");

const postForm = (csrf: string, fields: Record<string, string>, label: string, cls = "tb-btn") => `<form class="bp-form-del" method="post" action="/keys">${hidden({ csrf, ...fields })}<button class="${cls}" type="submit">${ink(label)}</button></form>`;

/** the labels of every owner-named key (`pk:<label>`, provider keys `@<id>` included), sorted: the S3 count limit */
const providerLabels = (ctx: BridgeContext): string[] =>
  Object.keys(ctx.state.keyStore.values)
    .filter(isProviderKeyName)
    .map((k) => k.slice(PROVIDER_KEY_PREFIX.length))
    .sort();

/** the labels of the older owner-named keys (`pk:<label>`, not a provider key), sorted */
const namedKeys = (ctx: BridgeContext): string[] => Object.keys(ctx.state.keyStore.values).filter(isNamedKey).sort();

/** a key name as the page shows it */
const keyLabel = (name: string): string => (isProviderSlot(name) ? `${providerById(name.slice(PROVIDER_DEFAULT_KEY_PREFIX.length))?.label ?? name} key` : isNamedKey(name) ? `older key "${namedLabel(name)}"` : name);

// ── 1. Providers ──

function sourceText(ctx: BridgeContext, t: Table, s: ValueSource, provider: ModelProvider): string {
  if (s.kind === "provider") return `the ${provider.label} key for all apps`;
  if (s.kind === "app") {
    const k = linkedNames(t, provider.id).find((x) => x.name === s.ref);
    return `${s.ref} (${appsText(ctx, k?.products ?? [])})`;
  }
  const serves = servesText(ctx, t, s.ref);
  return `${keyLabel(s.ref)}${serves ? ` (${serves})` : ""}`;
}

/** item 8: the conflict block of one provider (values never shown) */
function conflictBlock(ctx: BridgeContext, t: Table, csrf: string, p: ModelProvider): string {
  const groups = valueGroups(ctx.state, t, p.id);
  const slotSet = hasValue(ctx, providerSlot(p.id));
  if (!groups.length) return "";
  if (!slotSet && groups.length === 1) {
    const g = groups[0] as ValueSource[];
    return `
    <div class="tb-notice needs-you" role="group" aria-label="Existing ${esc(p.label)} key found"><span>Found an existing ${esc(p.label)} key in: ${esc(g.map((s) => sourceText(ctx, t, s, p)).join("; "))}.</span>${postForm(csrf, { action: "prov_adopt", provider: p.id, from: (g[0] as ValueSource).ref }, "Use it for all apps", "tb-btn primary")}</div>`;
  }
  if (groups.length < 2) return "";
  const items = groups
    .map((g, i) => {
      const isSlot = g.some((s) => s.kind === "provider");
      const actions: string[] = [];
      if (!isSlot) actions.push(postForm(csrf, { action: "prov_adopt", provider: p.id, from: (g[0] as ValueSource).ref }, "Use this value for all apps", "tb-btn primary"));
      for (const s of g) {
        if (s.kind === "app" && !isSlot) {
          const apps = appsText(ctx, linkedNames(t, p.id).find((x) => x.name === s.ref)?.products ?? []);
          if (slotSet) actions.push(postForm(csrf, { action: "akey_follow", name: s.ref }, `Use the ${p.label} key for ${s.ref}`));
          actions.push(postForm(csrf, { action: "akey_keep", name: s.ref }, `Keep ${s.ref} as an override for ${apps}`));
        }
        if (s.kind === "named" && !isSlot && slotSet) actions.push(postForm(csrf, { action: "pkey_switch", provider: p.id, label: namedLabel(s.ref) }, `Switch these models to the ${p.label} key`));
      }
      return `\n        <li><strong>Value ${i + 1}</strong>${isSlot ? "" : ' <span class="tb-tag needs-you">differs</span>'}: ${esc(g.map((s) => sourceText(ctx, t, s, p)).join("; "))}${actions.length ? `<div class="bp-form">${actions.join("")}</div>` : ""}</li>`;
    })
    .join("");
  return `
    <div class="tb-notice needs-you" role="group" aria-label="${esc(p.label)} keys differ"><span><strong>These ${esc(p.label)} keys differ.</strong> Choose which one each app uses. The bridge never shows a value.</span>
      <ol class="tb-list">${items}
      </ol>
    </div>`;
}

function providerRow(ctx: BridgeContext, t: Table, csrf: string, p: ModelProvider): string {
  const slot = providerSlot(p.id);
  const set = hasValue(ctx, slot);
  const used = usedByText(ctx, t, p.id);
  const id = `pv-${p.id}`;
  const tag = set ? `<span class="tb-tag live">${ink("Set")}</span>` : `<span class="tb-tag ${used || linkedNames(t, p.id).some((k) => k.required) ? "needs-you" : "idle"}">${ink("Not set")}</span>`;
  return `
  <section class="bp-key" id="provider-${esc(p.id)}" aria-labelledby="${id}">
    <div class="bp-key-head"><h3 id="${id}">${esc(p.label)}</h3>${tag}</div>
    <div class="bp-used"><span>Used by:</span><span>${esc(used || "no app yet")}</span></div>${conflictBlock(ctx, t, csrf, p)}
    <div class="bp-form"><form class="bp-form-del" method="post" action="/keys">${hidden({ csrf, action: "prov_save", provider: p.id })}<label class="tb-sr" for="${id}-v">${esc(p.label)} key</label><input class="tb-input" id="${id}-v" name="value" type="password" autocomplete="off" required placeholder="${set ? `Replace the ${esc(p.label)} key` : `Enter the ${esc(p.label)} key`}"><button class="tb-btn${set ? "" : " primary"}" type="submit">${ink("Save for all apps")}</button></form>${set ? postForm(csrf, { action: "prov_delete", provider: p.id }, "Delete", "tb-btn danger") : ""}</div>
  </section>`;
}

/** Section 1: one key per provider, entered once for every app (spec 0.1.92 items 1–8). */
export function renderProviders(ctx: BridgeContext, t: Table, csrf: string): string {
  const shown = providersInUse(ctx, t);
  const rest = keyedProviders().filter((p) => !shown.includes(p));
  const add = rest.length
    ? `
    <form class="bp-form" method="post" action="/keys" data-addprovider>${hidden({ csrf, action: "prov_save" })}<label class="tb-label" for="pv-add-p">Add a provider</label><select class="tb-select-native" id="pv-add-p" name="provider" required>${rest.map((p) => `<option value="${esc(p.id)}">${esc(p.label)}</option>`).join("")}</select><label class="tb-label" for="pv-add-v">Key</label><input class="tb-input" id="pv-add-v" name="value" type="password" autocomplete="off" required placeholder="Enter the key"><button class="tb-btn primary" type="submit">${ink("Save for all apps")}</button></form>`
    : "";
  return `
  <section class="bp-card wide" aria-labelledby="h-pv">
    <h2 id="h-pv">1 · Provider keys</h2>
    <p class="tb-soft">Enter each provider's key once. Every app and every model that uses this provider gets it, also apps you add later. To use another model or provider for one app, see Overrides below.</p>
    <div class="bp-keys">${shown.map((p) => providerRow(ctx, t, csrf, p)).join("")}
    </div>${add}
  </section>`;
}

// ── 2. Defaults and 3. Overrides: the binding form ──

/** provider choices for a role; local providers first (C336 Q3) */
function providerChoices(role: ModelRole): typeof MODEL_PROVIDERS {
  const list = MODEL_PROVIDERS.filter((p) => p.roles.includes(role));
  return [...list.filter((p) => p.local), ...list.filter((p) => !p.local)];
}

interface FormInit {
  provider?: string | undefined;
  model?: string | undefined;
  baseUrl?: string | undefined;
  keyName?: string | undefined;
  dataPolicy?: DataPolicy | undefined;
  dims?: number | undefined;
}

/** the key line under the provider choice; the script rewrites it from the option's data-keyline */
function keyLine(ctx: BridgeContext, p: ModelProvider | undefined): string {
  if (!p) return "";
  if (!p.keyNeeded) return "No key needed.";
  return hasValue(ctx, providerSlot(p.id)) ? `Key: your ${p.label} key (set).` : `Key: your ${p.label} key is not set yet. Enter it under Provider keys.`;
}

function bindingForm(ctx: BridgeContext, csrf: string, v: RoleView, id: string, init: FormInit, scope: { ins?: InstanceId; label: string }, isSet: boolean): string {
  const choices = providerChoices(v.role);
  const chosen = choices.find((p) => p.id === init.provider) ?? choices[0];
  const opts = choices
    .map(
      (p) =>
        `<option value="${esc(p.id)}"${p.id === chosen?.id ? " selected" : ""} data-keyline="${esc(keyLine(ctx, p))}" data-url="${p.defaultBaseUrl ? "0" : "1"}" data-zdr="${p.zdrOffered ? "1" : "0"}" data-key="${p.keyNeeded ? "1" : "0"}">${esc(p.label)}${p.keyNeeded ? "" : " (no key)"}${p.defaultBaseUrl ? "" : " (needs an address)"}</option>`,
    )
    .join("");
  const pol = (["", "local", "zdr", "standard"] as const)
    .map((p) => `<option value="${p}"${(init.dataPolicy ?? "") === p ? " selected" : ""}>${esc(p ? POLICY_LABEL[p] : "Automatic (local for a private address)")}</option>`)
    .join("");
  const zdrNames = MODEL_PROVIDERS.filter((p) => p.zdrOffered && p.roles.includes(v.role)).map((p) => p.label);
  const field = (name: string, label: string, control: string, hint?: string, attr = "") => `<div class="tb-field"${attr}><label class="tb-label" for="${id}-${name}">${esc(label)}</label>${control}${hint ? `<span class="tb-hint">${esc(hint)}</span>` : ""}</div>`;
  const named = namedKeys(ctx);
  const keyOpts = [`<option value="">${esc("The provider's key for all apps")}</option>`, ...named.map((n) => `<option value="${esc(n)}"${n === init.keyName ? " selected" : ""}>${esc(keyLabel(n))}</option>`)].join("");
  return `<form class="bp-form" method="post" action="/keys" data-binding>${hidden({ csrf, action: "bind", role: v.role, ...(scope.ins ? { ins: scope.ins } : {}) })}
      ${field("provider", "Provider", `<select class="tb-select-native" id="${id}-provider" name="provider" required data-provider>${opts}</select>`)}
      <p class="tb-hint" data-keyline>${esc(keyLine(ctx, chosen))}</p>
      ${field("model", "Model", `<input class="tb-input" id="${id}-model" name="model" maxlength="${MODEL_MAX}" autocomplete="off" required value="${esc(init.model ?? "")}">`)}
      ${field("baseUrl", "Base URL", `<input class="tb-input" id="${id}-baseUrl" name="baseUrl" maxlength="${URL_MAX}" autocomplete="off" inputmode="url" value="${esc(init.baseUrl ?? "")}">`, "Leave empty to use the provider's own address. Own servers and custom addresses need one.", " data-urlfield")}
      <button class="tb-btn" type="button" data-showurl hidden>${ink("Use another address")}</button>
      <details><summary>More: data policy, key${v.role === "embeddings" ? ", vector size" : ""}</summary>
      ${field("dataPolicy", "Data policy", `<select class="tb-select-native" id="${id}-dataPolicy" name="dataPolicy">${pol}</select>`, `Local needs an address on your own network. ${POLICY_LABEL.zdr}: ${zdrNames.join(", ") || "no provider for this role"}; the bridge cannot check a contract. For a gateway (OpenRouter, LiteLLM, a custom address) you confirm on the next page, naming its host.`)}
      <label class="tb-check" data-zdr><input type="checkbox" name="zdr" value="1"> ${esc(ZDR_TICK)}</label>
      <div data-keyfield>${named.length ? field("keyName", "Key", `<select class="tb-select-native" id="${id}-keyName" name="keyName">${keyOpts}</select>`, "Older named keys from before one key per provider.") : ""}
      ${field("newKey", `Key for ${scope.label} only (optional)`, `<input class="tb-input" id="${id}-newKey" name="newKey" type="password" autocomplete="off" placeholder="Leave empty to use the provider's key">`, "Only for this setting, for example a second account or a custom address.")}</div>${
        v.role === "embeddings"
          ? `\n      ${field("dims", "Vector size (optional)", `<input class="tb-input" id="${id}-dims" name="dims" inputmode="numeric" pattern="[0-9]*" value="${init.dims ?? ""}">`)}${isSet ? `\n      <p class="tb-notice needs-you">${esc(`${REINDEX_WARNING}.`)}</p><label class="tb-check"><input type="checkbox" name="reindex" value="1"> I understand</label>` : ""}`
          : ""
      }
      </details>
      <button class="tb-btn primary" type="submit">${ink(scope.ins ? `Save for ${scope.label} only` : "Save for all apps")}</button></form>`;
}

function bindingText(ctx: BridgeContext, b: ModelBinding): string {
  const p = providerById(b.provider);
  const name = bindingKeyName(b);
  const key = p && !p.keyNeeded ? "no key" : name && boundKey(b, ctx.state.keyStore.values) !== undefined ? keyLabel(name) : "key not set";
  return [p?.label ?? b.provider, b.model, baseUrlOf(b) ?? "no address", key, policyText(effectivePolicy(b, ownNet(ctx)))].join(" · ");
}

function roleTag(ctx: BridgeContext, v: RoleView, def: ModelBinding | undefined, overrides: ModelBinding[]): string {
  const states = v.entries.map((e) => {
    const b = overrides.find((o) => o.ins === e.ins) ?? def;
    if (!b || !servable(b, ownNet(ctx)) || boundKey(b, ctx.state.keyStore.values) === undefined) return "unset";
    return policyMeets(effectivePolicy(b, ownNet(ctx)).policy, e.minPolicy) ? "ok" : "low";
  });
  if (states.includes("low")) return `<span class="tb-tag needs-you">${ink("Policy too low")}</span>`;
  if (states.every((s) => s === "ok")) return `<span class="tb-tag live">${ink("Set")}</span>`;
  return `<span class="tb-tag ${v.required ? "needs-you" : "idle"}">${ink("Not set")}</span>`;
}

/** Section 2: one workspace default per declared role ("Save for all apps"). */
export function renderDefaults(ctx: BridgeContext, t: Table, csrf: string, hints: RoleHint[], apps: Map<string, PageApp>): string {
  const views = roleViews(t);
  if (!views.length) return "";
  const { bindings } = ctx.state;
  const rows = views
    .map((v) => {
      const id = `r-${v.role}`;
      const def = bindings.find((b) => b.role === v.role && !b.ins);
      const overrides = bindings.filter((b) => b.role === v.role && b.ins && v.entries.some((e) => e.ins === b.ins));
      const chips = v.products
        .map((p) => {
          const a = apps.get(p) ?? pageApp(ctx, p);
          apps.set(p, a);
          return appChip(a);
        })
        .join("");
      const hint = hints.find((h) => h.role === v.role);
      const init: FormInit = def ?? { provider: hint?.provider, model: hint?.model, dataPolicy: hint?.dataPolicy };
      const suggested = hint && (hint.provider || hint.model) ? `\n    <p class="tb-hint">Suggested: ${esc([hint.provider ? (providerById(hint.provider)?.label ?? hint.provider) : "", hint.model ?? "", hint.dataPolicy ? POLICY_LABEL[hint.dataPolicy] : ""].filter(Boolean).join(" · "))}. Nothing is saved until you save it.</p>` : "";
      const ovText = overrides.length ? `\n    <p class="tb-hint">${esc(`Overridden for: ${overrides.map((b) => appName(ctx, productOf(t, b.ins as InstanceId))).join(", ")} (see Overrides).`)}</p>` : "";
      return `
  <section class="bp-key" aria-labelledby="${id}">
    <div class="bp-key-head"><h3 id="${id}">${esc(ROLE_LABEL[v.role])}${v.required ? "" : " <small>(optional)</small>"}</h3>${roleTag(ctx, v, def, overrides)}</div>
    <div class="bp-used"><span class="tb-mono">${esc(v.role)}</span><span>used by</span>${chips}<span>at least: ${esc(POLICY_LABEL[v.minPolicy])}</span></div>
    <p class="tb-soft">Workspace default: ${esc(def ? bindingText(ctx, def) : "not set")}</p>${ovText}${suggested}
    ${bindingForm(ctx, csrf, v, `${id}-d`, init, { label: "all apps" }, !!def)}${def ? `\n    ${postForm(csrf, { action: "unbind", role: v.role }, "Remove the default", "tb-btn danger")}` : ""}
  </section>`;
    })
    .join("");
  return `
  <section class="bp-card wide" aria-labelledby="h-models">
    <h2 id="h-models">2 · Models: workspace defaults</h2>
    <p class="tb-soft">Choose which provider and model each kind of work uses in every app. Apps get the model, the address and the provider's key from your workspace; Tealbrick Portal sees only the names of the provider and the model.</p>
    <div class="bp-keys">${rows}
    </div>
  </section>`;
}

const LINK_TAG: Record<Exclude<LinkState, "own">, string> = { follows: "live", override: "busy", differs: "needs-you" };

/** the linked names of one app in the Overrides tree */
function linkedRows(ctx: BridgeContext, t: Table, csrf: string, product: string): string {
  return linkedNames(t)
    .filter((k) => k.products.includes(product))
    .map((k) => {
      const p = k.provider as ModelProvider;
      const st = linkState(ctx.state, t, k) as Exclude<LinkState, "own">;
      const apps = appsText(ctx, k.products);
      const text = st === "follows" ? `Follows the ${p.label} key` : st === "override" ? "Override" : "Differs";
      const slotSet = hasValue(ctx, providerSlot(p.id));
      const id = `ak-${product}-${k.name}`;
      const actions = [
        st !== "follows" && slotSet ? postForm(csrf, { action: "akey_follow", name: k.name }, `Use the ${p.label} key`) : "",
        st === "differs" ? postForm(csrf, { action: "akey_keep", name: k.name }, "Keep as an override") : "",
      ].join("");
      return `
      <li><strong class="tb-mono">${esc(k.name)}</strong> <span class="tb-tag ${LINK_TAG[st]}">${ink(text)}</span>${actions ? `<div class="bp-form">${actions}</div>` : ""}
        <details${st === "override" ? " open" : ""}><summary>${esc(st === "override" ? `Replace the key for ${apps}` : `Use a different key for ${apps} only`)}</summary>
        <form class="bp-form" method="post" action="/keys">${hidden({ csrf, name: k.name })}<label class="tb-sr" for="${esc(id)}">${esc(k.label)}</label><input class="tb-input" id="${esc(id)}" name="value" type="password" autocomplete="off" required placeholder="Enter a key for ${esc(apps)} only"><button class="tb-btn" type="submit">${ink(`Save for ${apps} only`)}</button></form></details></li>`;
    })
    .join("");
}

/** Section 3: per app, per role: "Workspace default" or "Override" (Martin: override → app → portion → model / provider). */
export function renderOverrides(ctx: BridgeContext, t: Table, csrf: string): string {
  const views = roleViews(t);
  const insList: InstanceId[] = [];
  for (const v of views) for (const e of v.entries) if (!insList.includes(e.ins)) insList.push(e.ins);
  for (const k of linkedNames(t)) for (const i of k.ins) if (!insList.includes(i)) insList.push(i);
  if (!insList.length) return "";
  const byProduct = new Map<string, InstanceId[]>();
  for (const ins of insList) byProduct.set(productOf(t, ins), [...(byProduct.get(productOf(t, ins)) ?? []), ins]);
  const blocks = [...byProduct.entries()]
    .sort((a, b) => appName(ctx, a[0]).localeCompare(appName(ctx, b[0])))
    .map(([product, list]) => {
      const name = appName(ctx, product);
      let count = 0;
      const roleRows = views
        .flatMap((v) => list.filter((ins) => v.entries.some((e) => e.ins === ins)).map((ins) => ({ v, ins })))
        .map(({ v, ins }) => {
          const def = ctx.state.bindings.find((b) => b.role === v.role && !b.ins);
          const own = ctx.state.bindings.find((b) => b.role === v.role && b.ins === ins);
          if (own) count += 1;
          const scope = `${name} · ${ROLE_LABEL[v.role]}`;
          const current = own ?? def;
          const id = `o-${ins}-${v.role}`;
          return `
      <li><strong>${esc(ROLE_LABEL[v.role])}</strong> <span class="tb-tag ${own ? "busy" : "idle"}">${ink(own ? "Override" : "Workspace default")}</span> <span class="tb-soft">${esc(current ? bindingText(ctx, current) : "not set")}</span>${own ? `<div class="bp-form">${postForm(csrf, { action: "unbind", role: v.role, ins }, "Use the workspace default")}</div>` : ""}
        <details${own ? " open" : ""}><summary>${esc(`Change for ${scope} only`)}</summary>
        ${bindingForm(ctx, csrf, v, id, current ? { ...current } : {}, { ins, label: scope }, v.role === "embeddings" && !!current)}
        </details></li>`;
        })
        .join("");
      const keyRows = linkedRows(ctx, t, csrf, product);
      return `
  <section class="bp-key" aria-labelledby="ov-${esc(product)}">
    <div class="bp-key-head"><h3 id="ov-${esc(product)}">${appChip(pageApp(ctx, product))}</h3><span class="tb-tag ${count ? "busy" : "idle"}">${ink(count ? `${count} override${count === 1 ? "" : "s"}` : "Uses the defaults")}</span></div>
    <ul class="tb-list">${roleRows}${keyRows}
    </ul>
  </section>`;
    })
    .join("");
  return `
  <section class="bp-card wide" aria-labelledby="h-ov">
    <h2 id="h-ov">3 · Overrides for one app</h2>
    <p class="tb-soft">Each app uses the workspace defaults and the provider keys above. Change a provider, a model or a key for one app and one kind of work only; everything else stays the same.</p>
    <div class="bp-keys">${blocks}
    </div>
  </section>`;
}

/** Section 5: older named keys that no model uses: adopt one as a provider key, or delete it. */
export function renderOlderKeys(ctx: BridgeContext, t: Table, csrf: string): string {
  const unused = namedKeys(ctx).filter((n) => !servesText(ctx, t, n));
  if (!unused.length) return "";
  const providers = keyedProviders();
  const rows = unused
    .map((n, i) => {
      const label = namedLabel(n);
      return `
      <li><strong>${esc(label)}</strong> <span class="tb-tag idle">${ink("Not used")}</span>
        <div class="bp-form"><form class="bp-form-del" method="post" action="/keys">${hidden({ csrf, action: "prov_adopt", from: n })}<label class="tb-sr" for="old-${i}">Provider</label><select class="tb-select-native" id="old-${i}" name="provider">${providers.map((p) => `<option value="${esc(p.id)}">${esc(p.label)}</option>`).join("")}</select><button class="tb-btn" type="submit">${ink("Use for all apps of this provider")}</button></form>${postForm(csrf, { action: "pkey_delete", label }, "Delete", "tb-btn danger")}</div></li>`;
    })
    .join("");
  return `
  <section class="bp-card wide" aria-labelledby="h-old">
    <h2 id="h-old">Older named keys</h2>
    <p class="tb-soft">Keys you named before one key per provider. No model uses them. Use one as a provider's key for all apps, or delete it.</p>
    <ul class="tb-list">${rows}
    </ul>
  </section>`;
}

/** the page's one script (spec 0.1.92 item 12): shows and hides fields, rewrites labels, sends nothing; forms work without it */
export const KEYS_SCRIPT = `(function(){
  if (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches) document.documentElement.setAttribute("data-theme", "dark");
  function each(sel, fn){ Array.prototype.forEach.call(document.querySelectorAll(sel), fn); }
  each("form[data-binding]", function(form){
    var sel = form.querySelector("select[data-provider]"); if (!sel) return;
    var line = form.querySelector("[data-keyline]"), url = form.querySelector("[data-urlfield]"), show = form.querySelector("[data-showurl]");
    var zdr = form.querySelector("[data-zdr]"), key = form.querySelector("[data-keyfield]");
    var urlInput = url ? url.querySelector("input") : null, opened = false;
    function update(){
      var o = sel.options[sel.selectedIndex]; if (!o) return;
      if (line) line.textContent = o.getAttribute("data-keyline") || "";
      var needs = o.getAttribute("data-url") === "1";
      if (url) url.hidden = !(needs || opened || (urlInput && urlInput.value));
      if (show) show.hidden = !url || !url.hidden;
      if (zdr) zdr.hidden = o.getAttribute("data-zdr") !== "1";
      if (key) key.hidden = o.getAttribute("data-key") !== "1";
    }
    if (show) show.addEventListener("click", function(){ opened = true; update(); if (urlInput) urlInput.focus(); });
    sel.addEventListener("change", update); update();
  });
  each("form[data-addprovider]", function(form){
    var sel = form.querySelector("select"), inp = form.querySelector("input[type=password]");
    function update(){ var o = sel.options[sel.selectedIndex]; if (o && inp) inp.placeholder = "Enter the " + o.textContent + " key"; }
    sel.addEventListener("change", update); update();
  });
})();`;

/** page CSS in the nonce'd <style> (the kit already makes `[hidden]` win over its display rules) */
export const KEYS_CSS = ".tb-list li{margin-block:.5rem}.tb-list details{margin-block-start:.25rem}";

/** the "asks first" page (deleting a key that serves models): the same form again with confirm=1, or back */
export function confirmPage(res: ServerResponse, ctx: Pick<BridgeContext, "table">, csrf: string, c: Extract<ModelsOutcome, { kind: "confirm" }>): void {
  htmlPage(res, 200, {
    title: c.title,
    workspace: ctx.table?.config.workspace.name,
    main: `
  <section class="bp-card" aria-labelledby="h">
    <span class="bp-sign is-person" aria-hidden="true"></span>
    <h1 id="h">${esc(c.title)}</h1>
    <p class="tb-soft">${esc(c.text)}</p>
    <div class="tb-ctas"><form method="post" action="/keys">${hidden({ ...c.fields, csrf, confirm: "1" })}<button class="tb-btn danger" type="submit">${ink(c.button)}</button></form>${linkButton("/keys", "Back to the keys")}</div>
  </section>`,
  });
}

/** the question before deleting a key that bindings use (BRIDGE §15.2) */
export function deleteQuestion(ctx: BridgeContext, t: Table, name: string, display: string, fields: Record<string, string>): ModelsOutcome | undefined {
  const serves = servesText(ctx, t, name);
  if (!serves) return undefined;
  return { kind: "confirm", title: `Delete ${display}?`, text: `This key serves: ${serves}. ${isNamedKey(name) ? "Those models use their provider's key for all apps from now on." : "Those models stay without a key until you enter it again."}`, fields, button: "Delete the key" };
}

// ── apply a post ──

const refused = (code: string, reason: string): ModelsOutcome => ({ kind: "refused", code, reason });

/** Applies a models post (`action` pkey | pkey_delete | bind | unbind); undefined = not a models action. */
export function applyModelsPost(ctx: BridgeContext, t: Table, form: URLSearchParams): ModelsOutcome | undefined {
  const action = form.get("action");
  if (action === "pkey") return saveProviderKey(ctx, form);
  if (action === "pkey_delete") return deleteProviderKey(ctx, t, form);
  if (action === "bind") return bind(ctx, t, form);
  if (action === "unbind") return unbind(ctx, t, form);
  if (action === "host_add") return addOwnHost(ctx, form);
  if (action === "host_remove") return removeOwnHost(ctx, t, form);
  if (action === "prov_save") return saveForAll(ctx, t, form.get("provider") ?? "", form.get("value") ?? "");
  if (action === "prov_delete") return deleteProviderSlot(ctx, t, form);
  if (action === "prov_adopt") return adopt(ctx, t, form);
  if (action === "akey_follow") return follow(ctx, t, form.get("name") ?? "");
  if (action === "akey_keep") return keep(ctx, t, form.get("name") ?? "");
  if (action === "pkey_switch") return switchNamed(ctx, form);
  return undefined;
}

function saveProviderKey(ctx: BridgeContext, form: URLSearchParams): ModelsOutcome {
  const label = (form.get("label") ?? "").trim();
  const value = (form.get("value") ?? "").trim();
  const store = ctx.state.keyStore;
  const named = providerLabels(ctx);
  if (!label || label.length > PROVIDER_KEY_LABEL_MAX || CONTROL.test(label)) return refused("label_invalid", `the name must be 1 to ${PROVIDER_KEY_LABEL_MAX} characters.`);
  // spec 0.1.92 item 1: `@<id>` is the provider key namespace
  if (label.startsWith("@")) return refused("label_invalid", "a name cannot start with @.");
  if (!named.includes(label) && named.length >= PROVIDER_KEYS_MAX) return refused("too_many_keys", `at most ${PROVIDER_KEYS_MAX} provider keys.`);
  if (!value) return refused("empty_value", "enter a value.");
  if (Buffer.byteLength(value) > VALUE_MAX_BYTES) return refused("too_large", "the value is too large (at most 16 KB).");
  // its own namespace (QA-BRIDGE22-1): a label equal to an app key name never reaches that app
  ctx.state.setKey(providerKeyName(label), value);
  ctx.log.info("bridge.models.key_saved", { keysRev: store.keysRev });
  return { kind: "saved", flash: `Saved ${label}.` };
}

function deleteProviderKey(ctx: BridgeContext, t: Table, form: URLSearchParams): ModelsOutcome {
  const label = form.get("label") ?? "";
  if (!Object.hasOwn(ctx.state.keyStore.values, providerKeyName(label))) return refused("unknown_key", "this key does not exist.");
  if (form.get("confirm") !== "1") {
    const q = deleteQuestion(ctx, t, providerKeyName(label), label, { action: "pkey_delete", label });
    if (q) return q;
  }
  ctx.state.setKey(providerKeyName(label), null);
  ctx.log.info("bridge.models.key_deleted", { keysRev: ctx.state.keyStore.keysRev });
  return { kind: "saved", flash: `Deleted ${label}.` };
}

function bind(ctx: BridgeContext, t: Table, form: URLSearchParams): ModelsOutcome {
  const role = form.get("role");
  if (!isModelRole(role)) return refused("role_unknown", "this kind of model is unknown.");
  const entries = roleRequirements(t).filter((e) => e.role === role);
  if (!entries.length) return refused("role_not_declared", "no app uses this kind of model.");
  const insRaw = form.get("ins") ?? "";
  const ins = insRaw ? (insRaw as InstanceId) : undefined;
  if (ins && !entries.some((e) => e.ins === ins)) return refused("app_unknown", "this app does not use this kind of model.");
  const provider = providerById(form.get("provider") ?? "");
  if (!provider?.roles.includes(role)) return refused("provider_invalid", "choose a provider from the list.");
  const model = (form.get("model") ?? "").trim();
  if (!MODEL_ID.test(model)) return refused("model_invalid", `enter a model name: at most ${MODEL_MAX} letters, digits and . _ : / @ + - (no spaces, no "//").`);
  // §15.3: input hygiene, transport rule and the canonical form (the only form stored and served)
  const raw = form.get("baseUrl") ?? "";
  if (raw.length > URL_MAX) return refused("base_url_invalid", `the base URL is too long (at most ${URL_MAX} characters).`);
  if (!raw && !provider.defaultBaseUrl) return refused("base_url_missing", `${provider.label} needs a base URL.`);
  const checked = classifyBase(raw || (provider.defaultBaseUrl as string), ownNet(ctx));
  if ("refused" in checked) return refused("base_url_invalid", checked.refused);
  const baseUrl = raw ? checked.href : undefined;
  const url = checked.href;
  const local = checked.cls !== "not_local";
  // spec 0.1.92 item 6: the provider key by default (`pk:@<provider>`, stored explicitly), an older named key, or a new key
  // for this one setting; a requirement (app) key never satisfies a binding (spec 0.1.69, QA-BRIDGE22-1)
  const picked = (form.get("keyName") ?? "").trim();
  const newKey = (form.get("newKey") ?? "").trim();
  if (picked && (!isProviderKeyName(picked) || (isProviderSlot(picked) ? picked !== providerSlot(provider.id) : !Object.hasOwn(ctx.state.keyStore.values, picked)))) return refused("key_unknown", "choose a key from the list.");
  if (Buffer.byteLength(newKey) > VALUE_MAX_BYTES) return refused("too_large", "the value is too large (at most 16 KB).");
  const insName = ins ? appName(ctx, productOf(t, ins)) : "Workspace";
  const newLabel = `${provider.label} · ${insName} · ${ROLE_LABEL[role]}`.slice(0, PROVIDER_KEY_LABEL_MAX);
  if (provider.keyNeeded && newKey && !Object.hasOwn(ctx.state.keyStore.values, providerKeyName(newLabel)) && providerLabels(ctx).length >= PROVIDER_KEYS_MAX) return refused("too_many_keys", `at most ${PROVIDER_KEYS_MAX} keys for one setting.`);
  const keyName = !provider.keyNeeded ? undefined : newKey ? providerKeyName(newLabel) : picked || providerSlot(provider.id);
  const asked = form.get("dataPolicy") ?? "";
  if (asked && !isDataPolicy(asked)) return refused("policy_invalid", "choose a data policy from the list.");
  const dataPolicy: DataPolicy = asked ? (asked as DataPolicy) : local ? "local" : "standard";
  if (dataPolicy === "local" && !local) return refused("policy_local_refused", "Local needs a base URL on your own network (a private address, a Railway private host, or an origin in Own hosts or TB_OWN_INFRA_ORIGINS). Tailnet names and addresses count only when listed in Own hosts.");
  if (dataPolicy === "zdr" && !provider.zdrOffered) return refused("policy_zdr_refused", `${provider.label} does not offer a zero-data-retention contract.`);
  const prev = ctx.state.bindings.find((b) => b.role === role && b.ins === ins);
  // §15.3: an attestation survives a save only for the same provider and base URL (and, for an effective gateway, the same
  // model); an effective gateway (QA-SPEC49-4) attests on a page that names its host
  const gateway = effectiveGateway(provider, baseUrl);
  const host = new URL(url).hostname;
  const attestedNow = dataPolicy === "zdr" && (gateway ? form.get("zdr_host") === host : form.get("zdr") === "1");
  const kept = prev?.dataPolicy === "zdr" && prev.zdrAttestedAt && prev.provider === provider.id && (prev.baseUrl ?? "") === (baseUrl ?? "") && (!gateway || prev.model === model) ? prev.zdrAttestedAt : undefined;
  const zdrAttestedAt = dataPolicy !== "zdr" ? undefined : attestedNow ? new Date().toISOString() : kept;
  if (dataPolicy === "zdr" && !zdrAttestedAt && !gateway) return refused("policy_zdr_unconfirmed", `tick "${ZDR_TICK}".`);
  const dimsRaw = (form.get("dims") ?? "").trim();
  const dims = role === "embeddings" && dimsRaw ? Number(dimsRaw) : undefined;
  if (dims !== undefined && !(Number.isInteger(dims) && dims >= 1 && dims <= 65536)) return refused("dims_invalid", "the vector size must be a whole number from 1 to 65536.");
  const next: ModelBinding = {
    role,
    ...(ins ? { ins } : {}),
    provider: provider.id,
    model,
    ...(baseUrl ? { baseUrl } : {}),
    ...(keyName ? { keyName } : {}),
    dataPolicy,
    ...(zdrAttestedAt ? { zdrAttestedAt } : {}),
    ...(dims !== undefined ? { dims } : {}),
  };
  // MANIFEST §7.1: a changed embeddings model means a re-index; the owner confirms the warning first
  if (role === "embeddings" && prev && (prev.provider !== next.provider || prev.model !== next.model || prev.dims !== next.dims) && form.get("reindex") !== "1") {
    return refused("reindex_unconfirmed", `${REINDEX_WARNING}. Tick "I understand" to change it.`);
  }
  const bindings = [...ctx.state.bindings.filter((b) => b !== prev), next];
  if (Buffer.byteLength(JSON.stringify(bindings)) > BINDINGS_MAX_BYTES) return refused("too_many_models", "too many model settings. Remove an override first.");
  if (provider.keyNeeded && newKey) ctx.state.commitKeys({ [providerKeyName(newLabel)]: newKey }, { bindings });
  else ctx.state.saveBindings(bindings);
  ctx.log.info("bridge.models.bound", { role, ...(ins ? { ins } : {}), provider: provider.id, dataPolicy, keysRev: ctx.state.keyStore.keysRev });
  if (dataPolicy === "zdr" && !zdrAttestedAt) {
    // an effective gateway without a current attestation: stored, counts as `standard` until the owner confirms for this host
    const fields = Object.fromEntries([...form].filter(([k]) => k !== "csrf" && k !== "confirm"));
    return { kind: "confirm", saved: true, title: "Confirm zero data retention", text: `${gatewayTick(host)}. Until you confirm, this model counts as standard.`, fields: { ...fields, zdr_host: host }, button: "I confirm" };
  }
  return { kind: "saved", flash: ins ? `Saved ${ROLE_LABEL[role]} for ${appName(ctx, productOf(t, ins))} only.` : `Saved ${ROLE_LABEL[role]} for all apps.` };
}

function unbind(ctx: BridgeContext, t: Table, form: URLSearchParams): ModelsOutcome {
  const role = form.get("role");
  const ins = (form.get("ins") || undefined) as InstanceId | undefined;
  const prev = isModelRole(role) ? ctx.state.bindings.find((b) => b.role === role && b.ins === ins) : undefined;
  if (!prev || !isModelRole(role)) return refused("binding_unknown", "this model setting does not exist.");
  ctx.state.saveBindings(ctx.state.bindings.filter((b) => b !== prev));
  ctx.log.info("bridge.models.unbound", { role, ...(ins ? { ins } : {}), keysRev: ctx.state.keyStore.keysRev });
  return { kind: "saved", flash: ins ? `${appName(ctx, productOf(t, ins))} uses the workspace default for ${ROLE_LABEL[role]} again.` : `Removed the workspace default for ${ROLE_LABEL[role]}.` };
}

// ── "Own hosts" (spec follow-up #49, §15.3): origins the owner states are on their own network ──

function addOwnHost(ctx: BridgeContext, form: URLSearchParams): ModelsOutcome {
  const raw = form.get("origin") ?? "";
  if (raw.length > URL_MAX) return refused("own_host_invalid", `the address is too long (at most ${URL_MAX} characters).`);
  const r = classifyOwnHost(raw);
  if ("refused" in r) return refused("own_host_invalid", r.refused);
  const hosts = ctx.state.ownHosts;
  if (hosts.includes(r.href)) return { kind: "saved", flash: `${r.href} is already in Own hosts.` };
  if (hosts.length >= OWN_HOSTS_MAX) return refused("own_hosts_full", `at most ${OWN_HOSTS_MAX} own hosts. Remove one first.`);
  ctx.state.saveOwnHosts([...hosts, r.href]);
  // the origin is a base URL host: never logged (RM-13)
  ctx.log.info("bridge.models.own_hosts", { count: ctx.state.ownHosts.length, keysRev: ctx.state.keyStore.keysRev });
  return { kind: "saved", flash: `Added ${r.href} to Own hosts.${r.warnPublic ? " This is a public address: traffic to it crosses the internet." : ""}` };
}

/** "role (app)" for every declared role whose binding meets its policy now and would not under `after` (or not be served) */
function fallBelow(ctx: BridgeContext, t: Table, after: OwnNet): string[] {
  const out: string[] = [];
  for (const e of roleRequirements(t)) {
    const b = resolveBinding(ctx.state.bindings, e.ins, e.role);
    if (!b || boundKey(b, ctx.state.keyStore.values) === undefined) continue;
    const ok = (own: OwnNet) => servable(b, own) && policyMeets(effectivePolicy(b, own).policy, e.minPolicy);
    if (ok(ownNet(ctx)) && !ok(after)) out.push(`${e.role} (${appName(ctx, e.product)})`);
  }
  return out;
}

function removeOwnHost(ctx: BridgeContext, t: Table, form: URLSearchParams): ModelsOutcome {
  const origin = form.get("origin") ?? "";
  if (!ctx.state.ownHosts.includes(origin)) return refused("own_host_unknown", "this address is not in Own hosts.");
  const rest = ctx.state.ownHosts.filter((h) => h !== origin);
  if (form.get("confirm") !== "1") {
    // §15.2: before a removal is confirmed, the page names every binding and app that falls below its minPolicy
    const below = fallBelow(ctx, t, { infra: ctx.ownInfraOrigins, hosts: rest });
    const text = below.length ? `These models fall below their app's data policy: ${below.join("; ")}. Those apps stop getting them until you choose another model.` : "No model falls below its app's data policy. Local models at this address count as standard from now on.";
    return { kind: "confirm", title: `Remove ${origin}?`, text, fields: { action: "host_remove", origin }, button: "Remove the address" };
  }
  // local bindings on it count as standard from the next resolve on (effectivePolicy)
  ctx.state.saveOwnHosts(rest);
  ctx.log.info("bridge.models.own_hosts", { count: ctx.state.ownHosts.length, keysRev: ctx.state.keyStore.keysRev });
  return { kind: "saved", flash: `Removed ${origin} from Own hosts.` };
}

/** The Own hosts section: exact origins the owner states are on their own network (tailnet names and addresses need it). */
export function renderOwnHosts(ctx: BridgeContext, csrf: string): string {
  const rows = ctx.state.ownHosts
    .map((o) => `\n      <li><span class="tb-mono">${esc(o)}</span> <form class="bp-form-del" method="post" action="/keys">${hidden({ csrf, action: "host_remove", origin: o })}<button class="tb-btn" type="submit">${ink("Remove")}</button></form></li>`)
    .join("");
  return `
  <section class="bp-card wide" aria-labelledby="h-own">
    <h2 id="h-own">Own hosts</h2>
    <p class="tb-soft">Addresses on your own network that the bridge cannot check, for example a machine on your tailnet. Models at these addresses count as local (owner-listed, not verified): the app resolves the name when it connects. Names need https; plain http is allowed only for a private or tailnet IP address. Link-local and cloud metadata addresses never count.</p>${rows ? `\n    <ul class="tb-list">${rows}\n    </ul>` : ""}
    <form class="bp-form" method="post" action="/keys">${hidden({ csrf, action: "host_add" })}<label class="tb-label" for="own-new">Address</label><input class="tb-input" id="own-new" name="origin" maxlength="${URL_MAX}" autocomplete="off" inputmode="url" required placeholder="https://gpu.example:8443"><button class="tb-btn primary" type="submit">${ink("Add")}</button></form>
  </section>`;
}

// ── spec 0.1.92: one key per provider ──

/** the provider of a `provider` form field: a MODEL_PROVIDERS row that needs a key */
const keyedById = (id: string): ModelProvider | undefined => keyedProviders().find((p) => p.id === id);

function checkValue(raw: string): string | ModelsOutcome {
  const value = raw.trim();
  if (!value) return refused("empty_value", "enter a value.");
  if (Buffer.byteLength(value) > VALUE_MAX_BYTES) return refused("too_large", "the value is too large (at most 16 KB).");
  return value;
}

/** item 5a: "Save for all apps" — the provider key plus its mirrors, one revision */
function saveForAll(ctx: BridgeContext, t: Table, providerId: string, raw: string, drop?: string): ModelsOutcome {
  const p = keyedById(providerId);
  if (!p) return refused("provider_invalid", "choose a provider from the list.");
  const value = checkValue(raw);
  if (typeof value !== "string") return value;
  const c = providerKeyChanges(ctx.state, t, p.id, value);
  const overrides = drop ? [...overridesOf(ctx.state, t)].filter((n) => n !== drop) : undefined;
  ctx.state.commitKeys(c.values, { ...(c.bindings ? { bindings: c.bindings } : {}), ...(overrides ? { overrides } : {}) });
  ctx.log.info("bridge.keys.provider_saved", { provider: p.id, names: Object.keys(c.values).length - 1, keysRev: ctx.state.keyStore.keysRev });
  return { kind: "saved", flash: `Saved the ${p.label} key for all apps.` };
}

function deleteProviderSlot(ctx: BridgeContext, t: Table, form: URLSearchParams): ModelsOutcome {
  const p = keyedById(form.get("provider") ?? "");
  if (!p || !Object.hasOwn(ctx.state.keyStore.values, providerSlot(p.id))) return refused("unknown_key", "this key does not exist.");
  if (form.get("confirm") !== "1") {
    const serves = servesText(ctx, t, providerSlot(p.id));
    const names = linkedNames(t, p.id).filter((k) => linkState(ctx.state, t, k) === "follows").map((k) => k.name);
    if (serves || names.length)
      return { kind: "confirm", title: `Delete the ${p.label} key?`, text: `It is used by: ${[serves, names.join(", ")].filter(Boolean).join("; ")}. They get no ${p.label} key until you enter it again.`, fields: { action: "prov_delete", provider: p.id }, button: "Delete the key" };
  }
  const c = providerKeyChanges(ctx.state, t, p.id, null);
  ctx.state.commitKeys(c.values);
  ctx.log.info("bridge.keys.provider_deleted", { provider: p.id, keysRev: ctx.state.keyStore.keysRev });
  return { kind: "saved", flash: `Deleted the ${p.label} key.` };
}

/** item 8: "Use this value for all apps" — adopt a stored value (a linked name or an older named key) as the provider key */
function adopt(ctx: BridgeContext, t: Table, form: URLSearchParams): ModelsOutcome {
  const from = form.get("from") ?? "";
  const providerId = form.get("provider") ?? "";
  const p = keyedById(providerId);
  if (!p) return refused("provider_invalid", "choose a provider from the list.");
  const linked = linkedNames(t, p.id).some((k) => k.name === from);
  if (!(linked || isNamedKey(from)) || !Object.hasOwn(ctx.state.keyStore.values, from)) return refused("unknown_key", "this key does not exist.");
  return saveForAll(ctx, t, p.id, ctx.state.keyStore.values[from] as string, linked ? from : undefined);
}

/** item 7: "Use the <Provider> key" for one linked name — a mirror, no longer an override */
function follow(ctx: BridgeContext, t: Table, name: string): ModelsOutcome {
  const k = linkedNames(t).find((x) => x.name === name);
  if (!k) return refused("unknown_key", "no app links this key to a provider.");
  const p = k.provider as ModelProvider;
  const slot = providerSlot(p.id);
  if (!Object.hasOwn(ctx.state.keyStore.values, slot)) return refused("provider_key_unset", `enter the ${p.label} key first.`);
  ctx.state.commitKeys({ [name]: ctx.state.keyStore.values[slot] as string }, { overrides: [...overridesOf(ctx.state, t)].filter((n) => n !== name) });
  ctx.log.info("bridge.keys.follow", { keyName: name, provider: p.id, keysRev: ctx.state.keyStore.keysRev });
  return { kind: "saved", flash: `${appsNames(ctx, k.products)} use the ${p.label} key for ${name}.` };
}

const appsNames = (ctx: BridgeContext, products: readonly string[]) => [...new Set(products.map((p) => appName(ctx, p)))].sort().join(", ");

/** item 7: "Keep as an override" — the stored value stays and is never mirrored */
function keep(ctx: BridgeContext, t: Table, name: string): ModelsOutcome {
  const k = linkedNames(t).find((x) => x.name === name);
  if (!k || !Object.hasOwn(ctx.state.keyStore.values, name)) return refused("unknown_key", "this key does not exist.");
  ctx.state.commitKeys({}, { overrides: [...overridesOf(ctx.state, t), name] });
  ctx.log.info("bridge.keys.override_kept", { keyName: name, keysRev: ctx.state.keyStore.keysRev });
  return { kind: "saved", flash: `${name} stays an override for ${appsNames(ctx, k.products)}.` };
}

/** item 8: "Switch these models to the <Provider> key" — bindings of that provider that name an older key */
function switchNamed(ctx: BridgeContext, form: URLSearchParams): ModelsOutcome {
  const p = keyedById(form.get("provider") ?? "");
  const name = providerKeyName(form.get("label") ?? "");
  if (!p || !isNamedKey(name)) return refused("unknown_key", "this key does not exist.");
  if (!Object.hasOwn(ctx.state.keyStore.values, providerSlot(p.id))) return refused("provider_key_unset", `enter the ${p.label} key first.`);
  const next = ctx.state.bindings.map((b) => (b.provider === p.id && b.keyName === name ? { ...b, keyName: providerSlot(p.id) } : b));
  if (next.every((b, i) => b === ctx.state.bindings[i])) return refused("binding_unknown", "no model of this provider uses this key.");
  ctx.state.saveBindings(next);
  ctx.log.info("bridge.keys.switched", { provider: p.id, keysRev: ctx.state.keyStore.keysRev });
  return { kind: "saved", flash: `These models use the ${p.label} key now.` };
}

/** the "Other app keys" and override saves of person.ts: the S3 changes for a requirement name (spec 0.1.92 item 7) */
export function appKeyChange(ctx: BridgeContext, t: Table, name: string, value: string | null): void {
  const k = linkedNames(t).find((x) => x.name === name);
  if (!k) return ctx.state.setKey(name, value);
  const ov = [...overridesOf(ctx.state, t)].filter((n) => n !== name);
  const slot = providerSlot((k.provider as ModelProvider).id);
  if (value !== null) return ctx.state.commitKeys({ [name]: value }, { overrides: [...ov, name] });
  // a delete of a linked name means "follow the provider key": a mirror when it is set (a rollback serves it)
  const has = Object.hasOwn(ctx.state.keyStore.values, slot);
  ctx.state.commitKeys({ [name]: has ? (ctx.state.keyStore.values[slot] as string) : null }, { overrides: ov });
}

export type { LinkState };
