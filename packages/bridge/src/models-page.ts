/**
 * The "Keys and models" part of the key page (v0.1.63, BRIDGE §15.2): owner-named provider keys and one model binding per
 * declared role (workspace default + per-app override). person.ts owns the ticket, session, CSRF and CSP (§9.3); this
 * module renders the two sections and applies their form posts. Every dynamic value goes through `esc`; key values are
 * write-only; logs carry role, instance, provider id and policy only (never a base URL, key name or value). The bridge
 * never calls a provider: there is no "test" button (§1.1).
 */
import type { ServerResponse } from "node:http";
import type { ModelRoleRequirementEntry } from "@opt2-tealbrick/spec/bridge";
import type { InstanceId, PersonTicketKeysClaims } from "@opt2-tealbrick/spec/credentials";
import { DATA_POLICY_RANK, type DataPolicy, MODEL_ID_PATTERN, MODEL_PROVIDERS, MODEL_ROLE_HINTS_MAX, MODEL_ROLES, type ModelRole, OWN_HOSTS_MAX, type PolicyBasis } from "@opt2-tealbrick/spec/models";
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
import type { ModelBinding } from "./state.ts";
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

const ROLE_LABEL: Record<ModelRole, string> = {
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

/** "reasoning (Notes, Tasks); embeddings (Notes)": which roles and apps one key serves (bindings that name it) */
export function servesText(ctx: BridgeContext, t: Table, keyName: string): string {
  const reqs = roleRequirements(t);
  const parts: string[] = [];
  for (const b of ctx.state.bindings.filter((x) => x.keyName === keyName)) {
    const products = b.ins
      ? [productOf(t, b.ins)]
      : [...new Set(reqs.filter((e) => e.role === b.role && !ctx.state.bindings.some((o) => o.role === b.role && o.ins === e.ins)).map((e) => e.product))];
    parts.push(`${b.role}${products.length ? ` (${products.map((p) => appName(ctx, p)).sort().join(", ")})` : ""}`);
  }
  return parts.join("; ");
}

// ── render ──

const hidden = (fields: Record<string, string>) =>
  Object.entries(fields)
    .map(([k, v]) => `<input type="hidden" name="${esc(k)}" value="${esc(v)}">`)
    .join("");

/** The provider-keys section (always shown: a key can be named before any app asks for a model). */
export function renderProviderKeys(ctx: BridgeContext, t: Table, csrf: string): string {
  const names = [...(ctx.state.keyStore.providerKeys ?? [])].filter((n) => Object.hasOwn(ctx.state.keyStore.values, n));
  const rows = names
    .map((n, i) => {
      const serves = servesText(ctx, t, n);
      const f = hidden({ csrf, label: n });
      return `
  <section class="bp-key" aria-labelledby="pk-${i}">
    <div class="bp-key-head"><h3 id="pk-${i}">${esc(n)}</h3><span class="tb-tag live">${ink("Set")}</span></div>
    <div class="bp-used"><span>Serves:</span><span>${esc(serves || "no model yet")}</span></div>
    <div class="bp-form"><form class="bp-form-del" method="post" action="/keys">${f}<input type="hidden" name="action" value="pkey"><label class="tb-sr" for="pkv-${i}">${esc(n)}</label><input class="tb-input" id="pkv-${i}" name="value" type="password" autocomplete="off" required placeholder="Replace value"><button class="tb-btn" type="submit">${ink("Replace")}</button></form><form class="bp-form-del" method="post" action="/keys">${f}<input type="hidden" name="action" value="pkey_delete"><button class="tb-btn danger" type="submit">${ink("Delete")}</button></form></div>
  </section>`;
    })
    .join("");
  return `
  <section class="bp-card wide" aria-labelledby="h-pk">
    <h2 id="h-pk">Provider keys</h2>
    <p class="tb-soft">Name a key once (for example "OpenAI main") and choose it for any model below. One key can serve many models and apps.</p>${rows ? `\n    <div class="bp-keys">${rows}\n    </div>` : ""}
    <form class="bp-form" method="post" action="/keys">${hidden({ csrf, action: "pkey" })}<label class="tb-label" for="pk-new-label">Name</label><input class="tb-input" id="pk-new-label" name="label" maxlength="${PROVIDER_KEY_LABEL_MAX}" autocomplete="off" required placeholder="OpenAI main"><label class="tb-label" for="pk-new-value">Value</label><input class="tb-input" id="pk-new-value" name="value" type="password" autocomplete="off" required placeholder="Enter value"><button class="tb-btn primary" type="submit">${ink("Save key")}</button></form>
  </section>`;
}

/** key choices: owner-named provider keys, then app keys that are set */
function keyOptions(ctx: BridgeContext, t: Table, selected: string | undefined): string {
  const values = ctx.state.keyStore.values;
  const named = new Set(ctx.state.keyStore.providerKeys ?? []);
  const appKeys = new Map<string, string>();
  for (const k of t.config.keyRequirements) if (k.source === "account_default" && Object.hasOwn(values, k.name) && !named.has(k.name)) appKeys.set(k.name, k.label);
  const opt = (v: string, label: string) => `<option value="${esc(v)}"${v === selected ? " selected" : ""}>${esc(label)}</option>`;
  return [opt("", "No key"), ...[...named].filter((n) => Object.hasOwn(values, n)).map((n) => opt(n, n)), ...[...appKeys].map(([n, l]) => opt(n, `${l} (app key)`))].join("");
}

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

function bindingForm(ctx: BridgeContext, t: Table, csrf: string, v: RoleView, id: string, init: FormInit, scope: { ins?: InstanceId; pickApp?: boolean }, isSet: boolean): string {
  const opts = providerChoices(v.role)
    .map((p) => `<option value="${esc(p.id)}"${p.id === init.provider ? " selected" : ""}>${esc(p.label)}${p.keyNeeded ? "" : " (no key)"}${p.defaultBaseUrl ? "" : " (needs an address)"}</option>`)
    .join("");
  const pol = (["", "local", "zdr", "standard"] as const)
    .map((p) => `<option value="${p}"${(init.dataPolicy ?? "") === p ? " selected" : ""}>${esc(p ? POLICY_LABEL[p] : "Automatic (local for a private address)")}</option>`)
    .join("");
  const zdrNames = MODEL_PROVIDERS.filter((p) => p.zdrOffered && p.roles.includes(v.role)).map((p) => p.label);
  const apps = scope.pickApp
    ? `<label class="tb-label" for="${id}-ins">App</label><select class="tb-select-native" id="${id}-ins" name="ins" required>${v.entries
        .map((e) => e.ins)
        .filter((ins, i, a) => a.indexOf(ins) === i)
        .map((ins) => `<option value="${esc(ins)}">${esc(appName(ctx, productOf(t, ins)))}</option>`)
        .join("")}</select>`
    : "";
  const field = (name: string, label: string, control: string, hint?: string) => `<div class="tb-field"><label class="tb-label" for="${id}-${name}">${esc(label)}</label>${control}${hint ? `<span class="tb-hint">${esc(hint)}</span>` : ""}</div>`;
  return `<form class="bp-form" method="post" action="/keys">${hidden({ csrf, action: "bind", role: v.role, ...(scope.ins ? { ins: scope.ins } : {}) })}${apps}
      ${field("provider", "Provider", `<select class="tb-select-native" id="${id}-provider" name="provider" required>${opts}</select>`)}
      ${field("model", "Model", `<input class="tb-input" id="${id}-model" name="model" maxlength="${MODEL_MAX}" autocomplete="off" required value="${esc(init.model ?? "")}">`)}
      ${field("baseUrl", "Base URL", `<input class="tb-input" id="${id}-baseUrl" name="baseUrl" maxlength="${URL_MAX}" autocomplete="off" inputmode="url" value="${esc(init.baseUrl ?? "")}">`, "Leave empty to use the provider's own address. Own servers need one.")}
      ${field("keyName", "Key", `<select class="tb-select-native" id="${id}-keyName" name="keyName">${keyOptions(ctx, t, init.keyName)}</select>`, "Own-server providers need no key.")}
      ${field("dataPolicy", "Data policy", `<select class="tb-select-native" id="${id}-dataPolicy" name="dataPolicy">${pol}</select>`, `Local needs an address on your own network. ${POLICY_LABEL.zdr}: ${zdrNames.join(", ") || "no provider for this role"}; the bridge cannot check a contract. For a gateway (OpenRouter, LiteLLM, a custom address) you confirm on the next page, naming its host.`)}
      <label class="tb-check"><input type="checkbox" name="zdr" value="1"> ${esc(ZDR_TICK)}</label>${
        v.role === "embeddings"
          ? `\n      ${field("dims", "Vector size (optional)", `<input class="tb-input" id="${id}-dims" name="dims" inputmode="numeric" pattern="[0-9]*" value="${init.dims ?? ""}">`)}${isSet ? `\n      <p class="tb-notice needs-you">${esc(`${REINDEX_WARNING}.`)}</p><label class="tb-check"><input type="checkbox" name="reindex" value="1"> I understand</label>` : ""}`
          : ""
      }
      <button class="tb-btn primary" type="submit">${ink("Save model")}</button></form>`;
}

function bindingText(ctx: BridgeContext, b: ModelBinding): string {
  const p = providerById(b.provider);
  const key = p && !p.keyNeeded ? "no key" : b.keyName && Object.hasOwn(ctx.state.keyStore.values, b.keyName) ? `key ${b.keyName}` : "key not set";
  return [p?.label ?? b.provider, b.model, baseUrlOf(b) ?? "no address", key, policyText(effectivePolicy(b, ownNet(ctx)))].join(" · ");
}

/** The Models section: one row per declared role (none when the config declares none). */
export function renderModels(ctx: BridgeContext, t: Table, csrf: string, hints: RoleHint[], apps: Map<string, PageApp>): string {
  const views = roleViews(t);
  if (!views.length) return "";
  const { bindings } = ctx.state;
  const rows = views
    .map((v) => {
      const id = `r-${v.role}`;
      const def = bindings.find((b) => b.role === v.role && !b.ins);
      const overrides = bindings.filter((b) => b.role === v.role && b.ins && v.entries.some((e) => e.ins === b.ins));
      // per declared instance: does what it resolves to work and meet its policy?
      const states = v.entries.map((e) => {
        const b = overrides.find((o) => o.ins === e.ins) ?? def;
        if (!b || !servable(b, ownNet(ctx)) || boundKey(b, ctx.state.keyStore.values) === undefined) return "unset";
        return policyMeets(effectivePolicy(b, ownNet(ctx)).policy, e.minPolicy) ? "ok" : "low";
      });
      const tag = states.includes("low")
        ? `<span class="tb-tag needs-you">${ink("Policy too low")}</span>`
        : states.every((s) => s === "ok")
          ? `<span class="tb-tag live">${ink("Set")}</span>`
          : `<span class="tb-tag ${v.required ? "needs-you" : "idle"}">${ink("Not set")}</span>`;
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
      const overrideRows = overrides
        .map((b) => `\n      <li>${esc(appName(ctx, productOf(t, b.ins as InstanceId)))}: ${esc(bindingText(ctx, b))} <form class="bp-form-del" method="post" action="/keys">${hidden({ csrf, action: "unbind", role: v.role, ins: b.ins as string })}<button class="tb-btn" type="submit">${ink("Remove override")}</button></form></li>`)
        .join("");
      return `
  <section class="bp-key" aria-labelledby="${id}">
    <div class="bp-key-head"><h3 id="${id}">${esc(ROLE_LABEL[v.role])}${v.required ? "" : " <small>(optional)</small>"}</h3>${tag}</div>
    <div class="bp-used"><span class="tb-mono">${esc(v.role)}</span><span>used by</span>${chips}<span>at least: ${esc(POLICY_LABEL[v.minPolicy])}</span></div>
    <p class="tb-soft">Workspace default: ${esc(def ? bindingText(ctx, def) : "not set")}</p>${suggested}
    ${bindingForm(ctx, t, csrf, v, `${id}-d`, init, {}, !!def)}${def ? `\n    <form class="bp-form-del" method="post" action="/keys">${hidden({ csrf, action: "unbind", role: v.role })}<button class="tb-btn danger" type="submit">${ink("Remove default")}</button></form>` : ""}${overrideRows ? `\n    <ul class="tb-list">${overrideRows}\n    </ul>` : ""}
    <details><summary>Override for one app</summary>
    ${bindingForm(ctx, t, csrf, v, `${id}-o`, {}, { pickApp: true }, v.role === "embeddings" && overrides.length > 0)}
    </details>
  </section>`;
    })
    .join("");
  return `
  <section class="bp-card wide" aria-labelledby="h-models">
    <h2 id="h-models">Models</h2>
    <p class="tb-soft">Choose which model each kind of work uses. Apps get the model, the address and the key from your workspace; Tealbrick Portal sees only the names of the provider and the model.</p>
    <div class="bp-keys">${rows}
    </div>
  </section>`;
}

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
  return { kind: "confirm", title: `Delete ${display}?`, text: `This key serves: ${serves}. Those models stay without a key until you choose another one.`, fields, button: "Delete the key" };
}

// ── apply a post ──

const refused = (code: string, reason: string): ModelsOutcome => ({ kind: "refused", code, reason });

/** Applies a models post (`action` pkey | pkey_delete | bind | unbind); undefined = not a models action. */
export function applyModelsPost(ctx: BridgeContext, t: Table, form: URLSearchParams): ModelsOutcome | undefined {
  const action = form.get("action");
  if (action === "pkey") return saveProviderKey(ctx, t, form);
  if (action === "pkey_delete") return deleteProviderKey(ctx, t, form);
  if (action === "bind") return bind(ctx, t, form);
  if (action === "unbind") return unbind(ctx, t, form);
  if (action === "host_add") return addOwnHost(ctx, form);
  if (action === "host_remove") return removeOwnHost(ctx, t, form);
  return undefined;
}

function saveProviderKey(ctx: BridgeContext, t: Table, form: URLSearchParams): ModelsOutcome {
  const label = (form.get("label") ?? "").trim();
  const value = (form.get("value") ?? "").trim();
  const store = ctx.state.keyStore;
  const named = store.providerKeys ?? [];
  if (!label || label.length > PROVIDER_KEY_LABEL_MAX || CONTROL.test(label)) return refused("label_invalid", `the name must be 1 to ${PROVIDER_KEY_LABEL_MAX} characters.`);
  if (t.config.keyRequirements.some((k) => k.name === label) || (Object.hasOwn(store.values, label) && !named.includes(label))) return refused("label_taken", "an app key already has this name. Choose another name.");
  if (!named.includes(label) && named.length >= PROVIDER_KEYS_MAX) return refused("too_many_keys", `at most ${PROVIDER_KEYS_MAX} provider keys.`);
  if (!value) return refused("empty_value", "enter a value.");
  if (Buffer.byteLength(value) > VALUE_MAX_BYTES) return refused("too_large", "the value is too large (at most 16 KB).");
  ctx.state.setKey(label, value, true);
  ctx.log.info("bridge.models.key_saved", { keysRev: store.keysRev });
  return { kind: "saved", flash: `Saved ${label}.` };
}

function deleteProviderKey(ctx: BridgeContext, t: Table, form: URLSearchParams): ModelsOutcome {
  const label = form.get("label") ?? "";
  if (!(ctx.state.keyStore.providerKeys ?? []).includes(label)) return refused("unknown_key", "this key does not exist.");
  if (form.get("confirm") !== "1") {
    const q = deleteQuestion(ctx, t, label, label, { action: "pkey_delete", label });
    if (q) return q;
  }
  ctx.state.setKey(label, null);
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
  const keyName = provider.keyNeeded ? (form.get("keyName") ?? "") || undefined : undefined;
  if (keyName && !Object.hasOwn(ctx.state.keyStore.values, keyName)) return refused("key_unknown", "choose a key from the list.");
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
  ctx.state.saveBindings(bindings);
  ctx.log.info("bridge.models.bound", { role, ...(ins ? { ins } : {}), provider: provider.id, dataPolicy, keysRev: ctx.state.keyStore.keysRev });
  if (dataPolicy === "zdr" && !zdrAttestedAt) {
    // an effective gateway without a current attestation: stored, counts as `standard` until the owner confirms for this host
    const fields = Object.fromEntries([...form].filter(([k]) => k !== "csrf" && k !== "confirm"));
    return { kind: "confirm", saved: true, title: "Confirm zero data retention", text: `${gatewayTick(host)}. Until you confirm, this model counts as standard.`, fields: { ...fields, zdr_host: host }, button: "I confirm" };
  }
  return { kind: "saved", flash: `Saved the model for ${ROLE_LABEL[role]}${ins ? ` (${appName(ctx, productOf(t, ins))})` : ""}.` };
}

function unbind(ctx: BridgeContext, t: Table, form: URLSearchParams): ModelsOutcome {
  const role = form.get("role");
  const ins = (form.get("ins") || undefined) as InstanceId | undefined;
  const prev = isModelRole(role) ? ctx.state.bindings.find((b) => b.role === role && b.ins === ins) : undefined;
  if (!prev || !isModelRole(role)) return refused("binding_unknown", "this model setting does not exist.");
  ctx.state.saveBindings(ctx.state.bindings.filter((b) => b !== prev));
  ctx.log.info("bridge.models.unbound", { role, ...(ins ? { ins } : {}), keysRev: ctx.state.keyStore.keysRev });
  return { kind: "saved", flash: `Removed the model for ${ROLE_LABEL[role]}${ins ? ` (${appName(ctx, productOf(t, ins))})` : ""}.` };
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
