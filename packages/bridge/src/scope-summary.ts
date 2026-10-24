/**
 * The app's scope summary (BRIDGE hooks / SDK-API §3.2 bridge op `scope_summary`): one label per agent for the status
 * report, and (spec 0.1.50, C283 A1) `admittedOps`, the STATIC scoped ops an agent's owner-set rows admit above the Portal
 * grant. `admittedOps` is DISPLAY input for tools/list only (tools.ts `visibleOps`); the SDK authorizes every call.
 *
 * When it is asked:
 *  - the app's `scopesRev` changed in a status push, and a pause was lifted (a pause does not change `scopesRev`, and the SDK
 *    gives its marks only to an agent that is not paused): `refreshScopeSummary(…, true)`;
 *  - on demand, bounded by an age (`refreshScopeSummaryIfOlder`): a tools/list whose answer is older than
 *    {@link LIST_MAX_AGE_MS}, and a tools/call of a scoped op that the tool list does not show ({@link MISS_MIN_AGE_MS}).
 *    An owner who widens a row then sees the tool without waiting for the app's next push. One request per app at a time.
 */
import { SCOPE_SOURCE_LABEL_MAX, SCOPE_SOURCES_MAX, type ScopeSourceItem } from "@opt2-tealbrick/spec/bridge";
import type { InstanceId } from "@opt2-tealbrick/spec/credentials";
import type { CallRouter } from "./calls.ts";
import type { BridgeContext } from "./context.ts";

/** at most this many `admittedOps` per agent are read from a scope summary (a manifest has far fewer ops) */
export const MAX_ADMITTED_OPS = 256;
const ADMITTED_OP_RE = /^[a-z][a-z0-9_]{1,47}$/;
/** a tools/list asks again when the last answer of an app is older than this */
export const LIST_MAX_AGE_MS = 30_000;
/** a tools/call of an unlisted scoped op asks again when the last answer is older than this (bounds the load an agent can cause) */
export const MISS_MIN_AGE_MS = 5_000;

const SNAKE_RE = /^[a-z][a-z0-9_]{0,39}$/;
const SOURCE_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;

/**
 * `ScopeSummaryResult.sources` → the items the status report forwards (BRIDGE §5.6): the first SCOPE_SOURCES_MAX, each well
 * formed (snake type and access, app instance id), labels without control or format characters (\p{Cc}, \p{Cf}) and at most
 * SCOPE_SOURCE_LABEL_MAX; a malformed item is dropped, never repaired. Not an array (an SDK before 0.1.65) → undefined.
 */
export function scopeSourceItems(v: unknown): ScopeSourceItem[] | undefined {
  if (!Array.isArray(v)) return undefined;
  const out: ScopeSourceItem[] = [];
  for (const it of v.slice(0, SCOPE_SOURCES_MAX)) {
    if (!it || typeof it !== "object") continue;
    const { type, id, label, access } = it as Record<string, unknown>;
    if (typeof type !== "string" || !SNAKE_RE.test(type) || typeof access !== "string" || !SNAKE_RE.test(access)) continue;
    if (typeof id !== "string" || !SOURCE_ID_RE.test(id) || typeof label !== "string") continue;
    const clean = label.replace(/[\p{Cc}\p{Cf}]/gu, "").trim().slice(0, SCOPE_SOURCE_LABEL_MAX);
    if (clean) out.push({ type: type as ScopeSourceItem["type"], id, label: clean, access: access as ScopeSourceItem["access"] });
  }
  return out;
}

/** `ScopeSummaryResult.admittedOps` → a set of well-formed op ids; anything else is dropped (display only) */
export function admittedOpIds(v: unknown): Set<string> {
  const out = new Set<string>();
  if (!Array.isArray(v)) return out;
  for (const id of v.slice(0, MAX_ADMITTED_OPS)) if (typeof id === "string" && ADMITTED_OP_RE.test(id)) out.add(id);
  return out;
}

/** a comparable form of one instance's labels and sources (all agents), to tell whether a refresh changed what the status report shows */
function labelsKey(ctx: BridgeContext, ins: InstanceId): string {
  return [...ctx.scopeSummaries.entries()]
    .filter(([k]) => k.endsWith(`|${ins}`))
    .map(([k, s]) => `${k}=${s.label}=${JSON.stringify(s.sources ?? null)}`)
    .sort()
    .join(";");
}

/** a comparable form of one instance's admitted ops (all agents), to tell whether a refresh changed them */
function admittedKey(ctx: BridgeContext, ins: InstanceId): string {
  return [...ctx.admittedOps.entries()]
    .filter(([k]) => k.endsWith(`|${ins}`))
    .map(([k, ids]) => `${k}=${[...ids].sort().join(",")}`)
    .sort()
    .join(";");
}

/**
 * Asks the app for its scope summary and keeps the labels (status report) and the admitted ops (tools/list). Never throws.
 * `always`: the app's scopes changed (or a pause lifted), so the tool lists and catalogs are rebuilt even when the admitted
 * ops are equal (the catalog `admitted` marks may differ). Otherwise they are rebuilt only when the admitted ops changed.
 */
export function refreshScopeSummary(ctx: BridgeContext, router: CallRouter, ins: InstanceId, always: boolean): Promise<void> {
  const running = ctx.scopeSummaryRuns.get(ins);
  // a request in flight may have been asked before the change this call is about: when the scopes changed, ask once more after it
  if (running) return always ? running.then(() => refreshScopeSummary(ctx, router, ins, true)) : running;
  const run = doRefresh(ctx, router, ins, always).finally(() => ctx.scopeSummaryRuns.delete(ins));
  ctx.scopeSummaryRuns.set(ins, run);
  return run;
}

/** {@link refreshScopeSummary} unless the app answered less than `maxAgeMs` ago; resolves when an answer in that age exists */
export async function refreshScopeSummaryIfOlder(ctx: BridgeContext, router: CallRouter, ins: InstanceId, maxAgeMs: number): Promise<void> {
  const running = ctx.scopeSummaryRuns.get(ins);
  if (running) return running;
  if (Date.now() - (ctx.scopeSummaryAt.get(ins) ?? 0) < maxAgeMs) return;
  await refreshScopeSummary(ctx, router, ins, false);
}

async function doRefresh(ctx: BridgeContext, router: CallRouter, ins: InstanceId, always: boolean): Promise<void> {
  const t = ctx.table;
  const app = t?.apps.get(ins);
  if (!t || !app || t.pausedWorkspace || t.pausedInstances.has(ins)) return;
  // stamped before the request: a failing or slow app is not asked again at once
  ctx.scopeSummaryAt.set(ins, Date.now());
  try {
    const list = await router.bridgeOp<{ agent: `agt_${string}`; label: string; admittedOps?: unknown; sources?: unknown }[]>(app, "scope_summary", {});
    const labelsBefore = labelsKey(ctx, ins);
    for (const k of [...ctx.scopeSummaries.keys()]) if (k.endsWith(`|${ins}`)) ctx.scopeSummaries.delete(k);
    const before = admittedKey(ctx, ins);
    for (const k of [...ctx.admittedOps.keys()]) if (k.endsWith(`|${ins}`)) ctx.admittedOps.delete(k);
    for (const s of Array.isArray(list) ? list : []) {
      if (typeof s?.agent !== "string" || typeof s.label !== "string") continue;
      const sources = scopeSourceItems(s.sources);
      ctx.scopeSummaries.set(`${s.agent}|${ins}`, { agt: s.agent, ins, label: s.label.slice(0, 80), ...(sources ? { sources } : {}) });
      // C283 A1: display marks only; a missing or malformed member = none
      const admitted = admittedOpIds(s.admittedOps);
      if (admitted.size > 0) ctx.admittedOps.set(`${s.agent}|${ins}`, admitted);
    }
    // S4-1: Portal is poked only when the labels changed (the admitted ops are not in the report)
    if (labelsKey(ctx, ins) !== labelsBefore) ctx.emit("health");
    if (always || admittedKey(ctx, ins) !== before) ctx.emit("scopes", ins);
  } catch {
    ctx.log.warn("bridge.scope_summary.failed", { ins, code: "app_error" });
    // S4-2: fail closed for display: without a fresh answer no op is shown above the grant (the labels stay, they only inform)
    const had = admittedKey(ctx, ins) !== "";
    for (const k of [...ctx.admittedOps.keys()]) if (k.endsWith(`|${ins}`)) ctx.admittedOps.delete(k);
    if (had) ctx.emit("scopes", ins);
  }
}
