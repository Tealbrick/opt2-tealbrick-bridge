/**
 * The bridge's own HTML pages (design: coordination/design/BRIDGE-PAGES.md, mockups bridge-*.html, C185).
 * Every HTML answer goes through {@link htmlPage}: one shell (mark + "Tealbrick" + workspace), one card, one footer.
 *
 * CSS: assets/bridge-pages.css is the generated, cut-down Tealbrick kit (design tools/bridge-css.ts: tokens +
 * components subset + bp-* layout, minified), copied verbatim. It is inlined as the first <style>; its sha256 is
 * computed here from the same bytes and put in the CSP, so the two can never differ. App colours go in one short
 * per-response <style> under a per-response nonce. No 'unsafe-inline', no style="" attributes, no script except the
 * nonce'd auto-submit and the key page's one nonce'd script (spec 0.1.92 item 12). Font, mark and favicon are served by the bridge itself under /_tb/ (exact allowlist).
 * Provenance of assets/: bridge-pages.css + nunito-latin-wght-normal.woff2 + OFL.txt from the design kit
 * (coordination/design/bridge, Nunito from @opt2-tealbrick/ui 0.2.4, OFL 1.1); mark.png = the drawn brand mark
 * (logo-mark@3x.png) and favicon.png = the production favicon (logo-32.png), both from coordination/design/assets/brand.
 */
import { createHash, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import type { ServerResponse } from "node:http";
import type { BridgeContext } from "./context.ts";

const asset = (name: string): Buffer => readFileSync(new URL(`../assets/${name}`, import.meta.url));

/** the one stylesheet every page inlines (exact bytes; the CSP hash is computed from them) */
export const PAGE_CSS: string = asset("bridge-pages.css").toString("utf8");
if (!PAGE_CSS || /<\/style/i.test(PAGE_CSS)) throw new Error("assets/bridge-pages.css is empty or would end its <style> early");
/** CSP source for {@link PAGE_CSS}: `sha256-<base64>` */
export const PAGE_CSS_HASH = `sha256-${createHash("sha256").update(PAGE_CSS, "utf8").digest("base64")}`;

/** GET /_tb/<file>: exactly these files, nothing else (no directory listing, no path from the request reaches the disk) */
const STATIC_FILES: Record<string, { type: string; body: Buffer }> = Object.assign(Object.create(null), {
  "nunito-latin-wght-normal.woff2": { type: "font/woff2", body: asset("nunito-latin-wght-normal.woff2") },
  "mark.png": { type: "image/png", body: asset("mark.png") },
  "favicon.png": { type: "image/png", body: asset("favicon.png") },
});
export const STATIC_PREFIX = "/_tb/";

/** the allowlisted file for a request path, or undefined (→ 404) */
export function staticFile(path: string): { type: string; body: Buffer } | undefined {
  if (!path.startsWith(STATIC_PREFIX)) return undefined;
  const name = path.slice(STATIC_PREFIX.length);
  return Object.hasOwn(STATIC_FILES, name) ? STATIC_FILES[name] : undefined;
}

export function sendStatic(res: ServerResponse, file: { type: string; body: Buffer }): void {
  res.writeHead(200, {
    "content-type": file.type,
    "content-length": String(file.body.length),
    "cache-control": "public, max-age=31536000, immutable",
    "cross-origin-resource-policy": "same-origin",
  });
  res.end(file.body);
}

// ── app colours ──

/** the kit's app colour table (`--tb-app-<id>: #rrggbb` in the generated stylesheet), by product id */
const APP_COLORS: ReadonlyMap<string, string> = (() => {
  const m = new Map<string, string>();
  for (const [, id, hex] of PAGE_CSS.matchAll(/--tb-app-([a-z][a-z0-9-]*):(#[0-9a-fA-F]{6})\b/g)) if (id !== "on" && !m.has(id as string)) m.set(id as string, (hex as string).toLowerCase());
  return m;
})();
/** an app with no colour of its own: a dark warm grey; white text on it is 5.8:1 (the band is white on the colour) */
export const NEUTRAL_APP_COLOR = "#6b655b";

const PRODUCT_ID = /^[a-z][a-z0-9-]{1,31}$/;

function whiteContrast(hex: string): number {
  const ch = [1, 3, 5].map((i) => Number.parseInt(hex.slice(i, i + 2), 16) / 255).map((v) => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4));
  const l = 0.2126 * (ch[0] as number) + 0.7152 * (ch[1] as number) + 0.0722 * (ch[2] as number);
  return 1.05 / (l + 0.05);
}

/**
 * An app's colour: the manifest's `display.color` when it is `#rrggbb` and white text on it reaches AA (4.5:1);
 * otherwise the kit's table by product id; otherwise a neutral. Always a plain `#rrggbb` (safe inside CSS).
 */
export function appColor(product: string, manifest: unknown): string {
  const own = (manifest as { display?: { color?: unknown } } | undefined)?.display?.color;
  if (typeof own === "string" && /^#[0-9a-fA-F]{6}$/.test(own) && whiteContrast(own) >= 4.5) return own.toLowerCase();
  return APP_COLORS.get(product) ?? NEUTRAL_APP_COLOR;
}

/** what a page needs to show one app: chip/band class, production name, colour */
export interface PageApp {
  product: string;
  name: string;
  color: string;
}

/** an app as pages show it: the manifest name (never the product id when a manifest is known) and its colour */
export function pageApp(ctx: Pick<BridgeContext, "table">, product: string): PageApp {
  const manifest = ctx.table?.appsByProduct.get(product)?.manifest;
  return { product, name: manifest?.name || product, color: appColor(product, manifest) };
}

const appClass = (product: string) => (PRODUCT_ID.test(product) ? ` bp-a-${product}` : "");

// ── markup helpers (callers pass trusted markup; every dynamic value goes through esc) ──

export function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] as string);
}

export const ARROW =
  '<svg class="tb-arrow" viewBox="0 0 20 14" aria-hidden="true"><path d="M1 7h16M11 1l6 6-6 6" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg>';

/** a control label in its cap-centring wrapper (C128) */
export const ink = (label: string) => `<span class="tb-ink">${esc(label)}</span>`;

/** an app chip: colour + production name */
export const appChip = (a: PageApp) => `<span class="bp-app${appClass(a.product)}">${esc(a.name)}</span>`;

/** the workspace's Portal (TB_PORTAL_URL, an origin from config; nothing from the request), or "" when standalone */
export function portalButton(ctx: Pick<BridgeContext, "table" | "portalUrl">, label = "Open Portal"): string {
  if (ctx.table?.standalone) return "";
  return `<a class="tb-btn primary" href="${esc(ctx.portalUrl)}">${ink(label)} ${ARROW}</a>`;
}

export const linkButton = (href: string, label: string, primary = false) => `<a class="tb-btn${primary ? " primary" : ""}" href="${esc(href)}">${ink(label)}</a>`;

/** the connect flow's step row (StepFlow, C126): 0 = check the request, 1 = approve in Portal */
export function steps(current: number): string {
  const names = ["Check the request", "Approve in Portal", "Back to your app"];
  return `<ol class="tb-stepflow-steps" aria-label="Steps">${names.map((s, i) => `<li${i < current ? ' class="done"' : ""}${i === current ? ' aria-current="step"' : ""}>${i + 1}-${s}</li>`).join("")}</ol>`;
}

// ── the one page builder ──

export interface PageSpec {
  /** document title (" · Tealbrick" is added) */
  title: string;
  /** the content of <main> (trusted markup) */
  main: string;
  /** workspace name for the header (omitted before the first config) */
  workspace?: string | undefined;
  /** apps whose colour the page uses (chips, band): one rule each in the nonce'd <style> */
  apps?: PageApp[];
  headers?: Record<string, string>;
  /** a trusted inline script (the auto-submit); it runs under the response nonce */
  script?: string;
  /** CSP form-action (default 'self') */
  formAction?: string;
  /** CSP connect-src 'self': the page script may call its own origin (the key page's model lists) */
  connect?: boolean;
  /** trusted page CSS added to the nonce'd <style> (after the app colours) */
  css?: string;
}

/** CSP of an HTML page; exported for the tests */
export function pageCsp(nonce: string, o: { script?: boolean; formAction?: string; connect?: boolean } = {}): string {
  return [
    "default-src 'none'",
    `style-src '${PAGE_CSS_HASH}' 'nonce-${nonce}'`,
    "font-src 'self'",
    "img-src 'self'",
    `script-src ${o.script ? `'nonce-${nonce}'` : "'none'"}`,
    ...(o.connect ? ["connect-src 'self'"] : []),
    `form-action ${o.formAction ?? "'self'"}`,
    "frame-ancestors 'none'",
    "base-uri 'none'",
  ].join("; ");
}

/** Every bridge HTML response. */
export function htmlPage(res: ServerResponse, status: number, p: PageSpec): void {
  const nonce = randomBytes(16).toString("base64url");
  const seen = new Set<string>();
  let appCss = "";
  for (const a of p.apps ?? []) {
    if (seen.has(a.product) || !PRODUCT_ID.test(a.product) || !/^#[0-9a-f]{6}$/.test(a.color)) continue;
    seen.add(a.product);
    appCss += `.bp-a-${a.product}{--app:${a.color}}`;
  }
  res.writeHead(status, {
    "content-type": "text/html; charset=utf-8",
    "cache-control": "no-store",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "content-security-policy": pageCsp(nonce, { script: !!p.script, ...(p.formAction ? { formAction: p.formAction } : {}), ...(p.connect ? { connect: true } : {}) }),
    ...p.headers,
  });
  const ws = p.workspace ? `<span class="bp-ws">${esc(p.workspace)}</span>` : "";
  res.end(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer">
<title>${esc(p.title)} · Tealbrick</title>
<link rel="icon" href="/_tb/favicon.png" type="image/png">
<style>${PAGE_CSS}</style>
<style nonce="${nonce}">${appCss}${p.css ?? ""}</style>
</head>
<body class="tb-root">
<div class="bp-page">
  <header class="bp-head"><span class="bp-brand"><img class="tb-mark" src="/_tb/mark.png" width="36" height="29" alt="">Tealbrick <small>Workspace bridge</small></span>${ws}</header>
  <main class="bp-main">${p.main}</main>
  <footer class="bp-foot">This page is served by your workspace bridge. Keys and codes stay in your workspace.</footer>
</div>${p.script ? `\n<script nonce="${nonce}">${p.script}</script>` : ""}
</body>
</html>
`);
}

/** one-message page (every refusal): sign, title, one sentence, optional hint, at most one action */
export interface Message {
  title: string;
  /** plain text */
  text: string;
  /** dashed = "open it again", solid brick = "you need to act" */
  sign: "open" | "person";
  /** plain text hint */
  detail?: string;
  /** trusted markup: one button or link */
  action?: string;
  /** the app band (launch pages) */
  app?: PageApp;
  headers?: Record<string, string>;
}

export function messagePage(res: ServerResponse, status: number, ctx: Pick<BridgeContext, "table">, m: Message): void {
  const workspace = ctx.table?.config.workspace.name;
  const band = m.app
    ? `<div class="bp-band${appClass(m.app.product)}"><span class="bp-initial" aria-hidden="true">${esc([...m.app.name][0]?.toUpperCase() ?? "")}</span><span><b>${esc(m.app.name)}</b><small>Mini app in ${esc(workspace ?? "your workspace")}</small></span></div>`
    : "";
  htmlPage(res, status, {
    title: m.title,
    workspace,
    ...(m.app ? { apps: [m.app] } : {}),
    ...(m.headers ? { headers: m.headers } : {}),
    main: `
  <section class="bp-card" aria-labelledby="h">
    ${band}<span class="bp-sign${m.sign === "person" ? " is-person" : ""}" aria-hidden="true"></span>
    <h1 id="h">${esc(m.title)}</h1>
    <p class="tb-soft">${esc(m.text)}</p>${m.detail ? `\n    <p class="tb-hint">${esc(m.detail)}</p>` : ""}${m.action ? `\n    <div class="tb-ctas">${m.action}</div>` : ""}
  </section>`,
  });
}
