/**
 * Person-facing surfaces of the bridge (BRIDGE §9): app launch + UI proxy (/a/<product>/…),
 * declared public routes (/p/<product>/…) and the "Keys and models" page (/keys; v0.1.63 adds provider keys and model
 * roles, models-page.ts). Not paused by design
 * (CREDENTIALS §13) and served with a config older than 12 h so the owner can act.
 */

import { randomBytes } from "node:crypto";
import { request as httpRequest, type IncomingMessage, type ServerResponse } from "node:http";
import { request as httpsRequest } from "node:https";
import { connect as netConnect, type Socket } from "node:net";
import { isRefusal } from "@opt2-tealbrick/relay";
import { LIFETIME_S, type PersonTicketLaunchClaims, TYP } from "@opt2-tealbrick/spec/credentials";
import type { BridgeContext } from "./context.ts";
import { applyModelsPost, confirmPage, deleteQuestion, hintsFrom, type RoleHint, renderModels, renderProviderKeys, servesText } from "./models-page.ts";
import { appChip, esc, htmlPage, ink, linkButton, type Message, messagePage, type PageApp, pageApp, portalButton } from "./pages.ts";
import type { PersonTicketKeysClaims0163 } from "./spec-0163.ts";
import type { AppRuntime } from "./table.ts";
import { BridgeError, clientIp, envelope, headerValue, nowS, OpenCounter, RateLimiter, readBody, sendJson } from "./util.ts";

const MAX_UI_BODY = 10 * 1024 * 1024;
const MAX_PUBLIC_BODY = 1024 * 1024;
/** open WebSocket upgrades per client address, and their idle timeout (H-6) */
const MAX_UPGRADES_PER_CLIENT = 20;
const UPGRADE_IDLE_MS = 10 * 60_000;

interface KeySession {
  csrf: string;
  exp: number;
  req: string[];
  /** one-time success notice for the next page view: the saved key's NAME (never a value), server side only */
  saved?: string;
  /** v0.1.63: one-time notice of a provider key or model change (plain text, server side only) */
  flash?: string;
  /** v0.1.63: the ticket's `roles[]` hints (display only) */
  hints: RoleHint[];
}

export class PersonSurfaces {
  private readonly ctx: BridgeContext;
  private readonly keySessions = new Map<string, KeySession>();
  private readonly publicLimit = new RateLimiter(60);
  /** unauthenticated body routes (launch, key page POST), per client address (BSD-01) */
  private readonly launchLimit = new RateLimiter(30);
  private readonly keysPostLimit = new RateLimiter(30);
  private readonly upgrades = new OpenCounter(MAX_UPGRADES_PER_CLIENT);

  constructor(ctx: BridgeContext) {
    this.ctx = ctx;
    setInterval(() => {
      const now = nowS();
      for (const [k, v] of this.keySessions) if (v.exp <= now) this.keySessions.delete(k);
    }, 60_000).unref();
  }

  private issuerRefs(): string[] {
    return this.ctx.table?.standalone ? [this.ctx.bridgeRef] : ["tb:portal"];
  }

  // ── §9.1 launch + app UI proxy ──
  async app(req: IncomingMessage, res: ServerResponse, requestId: string): Promise<void> {
    const url = new URL(req.url ?? "/", "http://x");
    const m = /^\/a\/([a-z][a-z0-9-]{1,31})(\/.*)?$/.exec(url.pathname);
    const app = m ? this.ctx.table?.appsByProduct.get(m[1] as string) : undefined;
    if (!m || !app) return sendJson(res, 404, envelope("not_found", "not found", requestId));
    // C57: a known app that is restarting (manifest not available) is "try again", never "not found"
    if (app.down || !app.manifest) return unavailable(res, requestId);
    const rest = m[2] ?? "/";
    if (!this.allowedUiPath(app, rest)) return sendJson(res, 404, envelope("not_found", "not found", requestId));
    let body: Buffer | undefined;
    if (rest === "/tb/launch") {
      if (req.method !== "POST") return sendJson(res, 405, envelope("method_not_allowed", "POST only", requestId));
      if (!this.launchLimit.take(clientIp(req))) return sendJson(res, 429, envelope("rate_limited", "rate limited", requestId), { "retry-after": "60" });
      body = await readBody(req, 16 * 1024);
      const ticket = new URLSearchParams(body.toString("utf8")).get("ticket") ?? "";
      const v = this.ctx.api.verifyJws<PersonTicketLaunchClaims>(ticket, this.ctx.table?.issuers ?? { keys: [] }, {
        typ: TYP.personTicket,
        aud: `tb:ins:${app.entry.ins}`,
        iss: this.issuerRefs(),
        now: nowS(),
        maxLifetimeS: LIFETIME_S.ticketLaunch,
      });
      if (isRefusal(v) || v.claims.pur !== "launch" || v.claims.ws !== this.ctx.table?.ws) {
        this.ctx.reject({ kind: "ticket", code: "invalid_token" });
        const a = pageApp(this.ctx, app.entry.product);
        return messagePage(res, 401, this.ctx, {
          title: "Link expired",
          text: "This link has expired. Open the app again from Portal.",
          sign: "open",
          app: a,
          action: portalButton(this.ctx, `Open ${a.name} from Portal`),
          detail: `Links that open an app work once and expire after ${LIFETIME_S.ticketLaunch} seconds.`,
        });
      }
      // The SDK redeems the ticket once (jti in the app DB); the bridge only checks and forwards it.
    }
    return this.proxy(req, res, app, url.pathname + url.search, body, MAX_UI_BODY, true, rest === "/tb/launch" ? (loc) => launchRedirect(app.entry.product, loc, (p) => this.ctx.api.isValidLaunchPath(p)) : undefined);
  }

  private allowedUiPath(app: AppRuntime, rest: string): boolean {
    if (rest === "/tb/launch" || rest.startsWith("/tb/v1/")) return true;
    if (rest.includes("..")) return false;
    const ui = app.manifest?.ui;
    if (!ui) return false;
    return [ui.launchPath, ui.configurePath].filter((p): p is string => !!p).some((p) => p === "/" || rest === p || rest.startsWith(p.endsWith("/") ? p : `${p}/`) || rest.startsWith("/assets/"));
  }

  // ── §9.2 declared public routes ──
  async publicRoute(req: IncomingMessage, res: ServerResponse, requestId: string): Promise<void> {
    const url = new URL(req.url ?? "/", "http://x");
    const m = /^\/p\/([a-z][a-z0-9-]{1,31})(\/.*)$/.exec(url.pathname);
    const app = m ? this.ctx.table?.appsByProduct.get(m[1] as string) : undefined;
    const path = m?.[2] ?? "";
    if (app && (app.down || !app.manifest)) return unavailable(res, requestId);
    const route = app?.manifest?.publicRoutes?.find((r) => r.path === path);
    if (!app || !route) return sendJson(res, 404, envelope("not_found", "not found", requestId));
    const method = route.purpose === "oauth_callback" ? "GET" : "POST";
    if (req.method !== method) return sendJson(res, 405, envelope("method_not_allowed", `${method} only`, requestId));
    // per route AND client: one sender cannot use up a webhook/callback route for everyone
    if (!this.publicLimit.take(`${app.entry.product}|${path}|${clientIp(req)}`)) return sendJson(res, 429, envelope("rate_limited", "rate limited", requestId));
    const body = method === "POST" ? await readBody(req, MAX_PUBLIC_BODY) : undefined;
    return this.proxy(req, res, app, `/p/${app.entry.product}${path}${url.search}`, body, MAX_PUBLIC_BODY, false);
  }

  /** Forwards to the app, stripping Authorization and TB-* (except TB-CSRF on the UI path). */
  private proxy(req: IncomingMessage, res: ServerResponse, app: AppRuntime, pathAndQuery: string, body: Buffer | undefined, max: number, keepCsrf: boolean, rewriteLocation?: (loc: string | undefined) => string): Promise<void> {
    return new Promise((resolve) => {
      const target = new URL(pathAndQuery, app.entry.internalUrl);
      const headers: Record<string, string | string[]> = {};
      for (const [k, v] of Object.entries(req.headers)) {
        if (v === undefined) continue;
        const lk = k.toLowerCase();
        if (lk === "authorization" || lk === "host" || lk === "connection" || lk === "content-length" || lk === "transfer-encoding") continue;
        if (lk.startsWith("tb-") && !(keepCsrf && lk === "tb-csrf")) continue;
        if (lk.startsWith("x-forwarded-")) continue;
        headers[lk] = v;
      }
      const pub = new URL(this.ctx.publicUrl);
      headers["x-forwarded-proto"] = pub.protocol.replace(":", "");
      headers["x-forwarded-host"] = pub.host;
      if (body) headers["content-length"] = String(body.length);
      const send = target.protocol === "https:" ? httpsRequest : httpRequest;
      const upstream = send(target, { method: req.method, headers, timeout: 60_000 }, (ur) => {
        const out: Record<string, string | string[]> = {};
        for (const [k, v] of Object.entries(ur.headers)) if (v !== undefined && !["connection", "transfer-encoding"].includes(k)) out[k] = v;
        const status = ur.statusCode ?? 502;
        if (rewriteLocation && status >= 300 && status < 400) out.location = rewriteLocation(typeof ur.headers.location === "string" ? ur.headers.location : undefined);
        res.writeHead(status, out);
        ur.pipe(res);
        ur.on("end", () => resolve());
      });
      upstream.on("timeout", () => upstream.destroy(new Error("timeout")));
      upstream.on("error", () => {
        if (!res.headersSent) sendJson(res, 502, envelope("app_unavailable", "app unavailable", "proxy"));
        else res.end();
        resolve();
      });
      if (body) upstream.end(body);
      else {
        let size = 0;
        req.on("data", (c: Buffer) => {
          size += c.length;
          if (size > max) {
            upstream.destroy();
            if (!res.headersSent) sendJson(res, 413, envelope("payload_too_large", "body too large", "proxy"));
          }
        });
        req.pipe(upstream);
      }
    });
  }

  /**
   * WebSocket upgrade pass-through for the app UI path only (H-6): client X-Forwarded-* are replaced by the
   * bridge's own, an app that is down is refused, open upgrades are capped per client address and idle
   * tunnels are closed.
   */
  upgrade(req: IncomingMessage, socket: Socket, head: Buffer): void {
    const url = new URL(req.url ?? "/", "http://x");
    const m = /^\/a\/([a-z][a-z0-9-]{1,31})(\/.*)?$/.exec(url.pathname);
    const app = m ? this.ctx.table?.appsByProduct.get(m[1] as string) : undefined;
    if (!app || !this.allowedUiPath(app, m?.[2] ?? "/")) {
      socket.end("HTTP/1.1 404 Not Found\r\nconnection: close\r\n\r\n");
      return;
    }
    if (app.down || !app.manifest) {
      socket.end("HTTP/1.1 503 Service Unavailable\r\nretry-after: 5\r\nconnection: close\r\n\r\n");
      return;
    }
    const release = this.upgrades.acquire(clientIp(req));
    if (!release) {
      socket.end("HTTP/1.1 429 Too Many Requests\r\nretry-after: 60\r\nconnection: close\r\n\r\n");
      return;
    }
    socket.once("close", release);
    const target = new URL(app.entry.internalUrl);
    const pub = new URL(this.ctx.publicUrl);
    const up = netConnect(Number(target.port || 80), target.hostname, () => {
      const lines = [`${req.method} ${url.pathname}${url.search} HTTP/1.1`, `host: ${target.host}`];
      for (const [k, v] of Object.entries(req.headers)) {
        const lk = k.toLowerCase();
        if (lk === "host" || lk === "authorization" || lk.startsWith("x-forwarded-") || (lk.startsWith("tb-") && lk !== "tb-csrf")) continue;
        for (const val of Array.isArray(v) ? v : [v]) if (val !== undefined) lines.push(`${k}: ${val}`);
      }
      lines.push(`x-forwarded-proto: ${pub.protocol.replace(":", "")}`, `x-forwarded-host: ${pub.host}`);
      up.write(`${lines.join("\r\n")}\r\n\r\n`);
      if (head.length) up.write(head);
      up.pipe(socket);
      socket.pipe(up);
    });
    const close = () => {
      up.destroy();
      socket.destroy();
    };
    socket.setTimeout(UPGRADE_IDLE_MS, close);
    up.setTimeout(UPGRADE_IDLE_MS, close);
    up.on("error", close);
    // the app closed: flush what is buffered to the client, then end (the idle timeout covers a client that stays)
    up.on("close", () => socket.end());
    socket.on("error", close);
    socket.on("close", () => up.destroy());
  }

  // ── §9.3 key-entry page ──
  async keys(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const t = this.ctx.table;
    if (!t) return messagePage(res, 503, this.ctx, { title: "The bridge is starting", text: "The bridge is starting. Try again in a moment.", sign: "open", action: linkButton("", "Try again") });
    const cookieName = "tb_keys";
    const sid = parseCookies(headerValue(req, "cookie"))[cookieName];
    const session = sid ? this.keySessions.get(sid) : undefined;
    const secure = (this.ctx.keysUrl ?? this.ctx.publicUrl).startsWith("https:");
    if (req.method === "POST") {
      // L3/L18: every refused save is one log line (names and a code only, never the value, L15) and a plain page
      const refuse = (code: KeySaveRefusal, keyName: string | null, status: number, m: Message) => {
        this.ctx.log.warn("bridge.keys.save_refused", { app: keyApps(t, keyName), keyName: safeKeyName(keyName), code });
        messagePage(res, status, this.ctx, m);
      };
      // the one "not saved" page (BRIDGE-PAGES #4): the reason, back to the keys
      const notSaved = (reason: string): Message => ({ title: "The key was not saved", text: `The key was not saved: ${reason}`, sign: "person", action: linkButton("/keys", "Back to the keys", true), detail: "Nothing was stored. Your other keys did not change." });
      if (!this.keysPostLimit.take(clientIp(req)))
        return refuse("rate_limited", null, 429, { title: "Too many requests", text: "The key was not saved. Please wait a minute and try again.", sign: "person", detail: "This protects your workspace from guessing.", headers: { "retry-after": "60" } });
      let raw: Buffer;
      try {
        raw = await readBody(req, 20 * 1024);
      } catch (e) {
        if (e instanceof BridgeError && e.code === "payload_too_large") return refuse("too_large", null, 413, notSaved("the value is too large (at most 16 KB)."));
        return refuse("body_invalid", null, e instanceof BridgeError ? e.status : 400, notSaved("the form did not arrive completely. Try again."));
      }
      const form = new URLSearchParams(raw.toString("utf8"));
      const ticket = form.get("ticket");
      if (ticket) {
        const v = this.ctx.api.verifyJws<PersonTicketKeysClaims0163>(ticket, t.issuers, {
          typ: TYP.personTicket,
          aud: this.ctx.bridgeRef,
          iss: this.issuerRefs(),
          now: nowS(),
          maxLifetimeS: LIFETIME_S.ticketKeys,
        });
        if (isRefusal(v) || v.claims.pur !== "keys" || v.claims.ws !== t.ws || !this.ctx.state.useJti(v.claims.jti, v.claims.exp)) {
          this.ctx.reject({ kind: "ticket", code: "invalid_token" });
          return refuse("ticket_invalid", null, 401, { title: "Link expired", text: "This link has expired or was used. Open it again from Portal.", sign: "open", action: portalButton(this.ctx) });
        }
        const id = randomBytes(32).toString("base64url");
        const fresh: KeySession = { csrf: randomBytes(24).toString("base64url"), exp: nowS() + LIFETIME_S.keyPageSession, req: v.claims.req ?? [], hints: hintsFrom(v.claims) };
        this.keySessions.set(id, fresh);
        // Render the page in THIS response (no redirect): the ticket arrives by a cross-site form POST from the
        // Portal, and a browser does not send a SameSite=Strict cookie on the redirected GET of that navigation.
        // The later form posts on this page are same-site, so Strict works for them.
        return this.renderKeys(res, t, fresh, { "set-cookie": `${cookieName}=${id}; HttpOnly; ${secure ? "Secure; " : ""}SameSite=Strict; Path=/keys; Max-Age=${LIFETIME_S.keyPageSession}` });
      }
      const name = form.get("name") ?? "";
      if (!session || session.exp <= nowS())
        return refuse("page_expired", name, 401, {
          title: "This page expired",
          text: "The key was not saved: this page expired. Open the key page again from Portal.",
          sign: "open",
          action: portalButton(this.ctx),
          detail: `Key pages close after ${LIFETIME_S.keyPageSession / 60} minutes so a key can never be entered on a page left open.`,
        });
      if (form.get("csrf") !== session.csrf) return refuse("csrf_invalid", name, 403, notSaved("the form expired. Go back to the keys and try again."));
      // v0.1.63 (BRIDGE §15.2): provider keys and model bindings
      const outcome = applyModelsPost(this.ctx, t, form);
      if (outcome?.kind === "confirm") return confirmPage(res, this.ctx, session.csrf, outcome);
      if (outcome?.kind === "refused") {
        this.ctx.log.warn("bridge.models.save_refused", { code: outcome.code });
        return messagePage(res, 400, this.ctx, { title: "The change was not saved", text: `The change was not saved: ${outcome.reason}`, sign: "person", action: linkButton("/keys", "Back to the keys", true), detail: "Nothing was stored. Your other keys and models did not change." });
      }
      if (outcome) {
        session.flash = outcome.flash;
        this.ctx.emit("keys");
        res.writeHead(303, { location: "/keys", "cache-control": "no-store" }).end();
        return;
      }
      const allowed = t.config.keyRequirements.some((k) => k.source === "account_default" && k.name === name);
      if (!allowed) return refuse("unknown_key", name, 400, notSaved("no app requests this key."));
      if (form.get("action") === "delete") {
        // BRIDGE §15.2: a key that serves models is deleted only after the owner confirmed it
        const label = t.config.keyRequirements.find((k) => k.name === name)?.label ?? name;
        const q = form.get("confirm") === "1" ? undefined : deleteQuestion(this.ctx, t, name, label, { name, action: "delete" });
        if (q?.kind === "confirm") return confirmPage(res, this.ctx, session.csrf, q);
        this.ctx.state.setKey(name, null);
      } else {
        // a pasted key often carries a trailing newline or spaces: only the surrounding whitespace is removed
        const value = (form.get("value") ?? "").trim();
        if (!value) return refuse("empty_value", name, 400, notSaved("enter a value."));
        if (Buffer.byteLength(value) > 16 * 1024) return refuse("too_large", name, 400, notSaved("the value is too large (at most 16 KB)."));
        this.ctx.state.setKey(name, value);
        session.saved = name; // the success notice on the next view (BRIDGE-PAGES #3a): shown once, nothing in the URL
        this.ctx.log.info("bridge.keys.saved", { app: keyApps(t, name), keyName: name, keysRev: this.ctx.state.keyStore.keysRev });
      }
      this.ctx.log.info("bridge.keys.changed", { name, keysRev: this.ctx.state.keyStore.keysRev });
      this.ctx.emit("keys");
      res.writeHead(303, { location: "/keys", "cache-control": "no-store" }).end();
      return;
    }
    if (!session || session.exp <= nowS())
      return messagePage(res, 401, this.ctx, {
        title: "Open the key page from Portal",
        text: "Open it from Portal: Workspace → Workspace default keys. The link from Portal signs you in to this page once.",
        sign: "open",
        action: portalButton(this.ctx),
      });
    return this.renderKeys(res, t, session);
  }

  private renderKeys(res: ServerResponse, t: NonNullable<BridgeContext["table"]>, session: KeySession, headers: Record<string, string> = {}): void {
    const reqs = t.config.keyRequirements.filter((k) => k.source === "account_default");
    const byName = new Map<string, { label: string; provider?: string; products: Set<string>; required: boolean }>();
    for (const k of reqs) {
      const e = byName.get(k.name) ?? { label: k.label, ...(k.provider ? { provider: k.provider } : {}), products: new Set<string>(), required: false };
      e.products.add(k.product);
      e.required ||= k.required;
      byName.set(k.name, e);
    }
    const names = [...byName.keys()].sort((a, b) => Number(session.req.includes(b)) - Number(session.req.includes(a)) || a.localeCompare(b));
    const apps = new Map<string, PageApp>();
    const hidden = (n: string) => `<input type="hidden" name="csrf" value="${esc(session.csrf)}"><input type="hidden" name="name" value="${esc(n)}">`;
    const rows = names
      .map((n) => {
        const e = byName.get(n) as { label: string; provider?: string; products: Set<string>; required: boolean };
        const set = Object.hasOwn(this.ctx.state.keyStore.values, n);
        const id = esc(n);
        const chips = [...e.products]
          .map((p) => {
            const a = apps.get(p) ?? pageApp(this.ctx, p);
            apps.set(p, a);
            return appChip(a);
          })
          .join("");
        const tag = set ? `<span class="tb-tag live">${ink("Set")}</span>` : e.required ? `<span class="tb-tag needs-you">${ink("Not set")}</span>` : `<span class="tb-tag idle">${ink("Not set")}</span>`;
        const serves = servesText(this.ctx, t, n);
        return `
  <section class="bp-key" aria-labelledby="k-${id}">
    <div class="bp-key-head"><h2 id="k-${id}">${esc(e.label)}${e.required ? "" : " <small>(optional)</small>"}</h2>${tag}</div>
    <div class="bp-used"><span class="tb-mono">${id}</span><span>used by</span>${chips}${session.req.includes(n) ? `<span class="tb-tag busy">${ink("requested now")}</span>` : ""}</div>${serves ? `\n    <div class="bp-used"><span>Serves:</span><span>${esc(serves)}</span></div>` : ""}
    <div class="bp-form"><form class="bp-form-del" method="post" action="/keys">${hidden(n)}<label class="tb-sr" for="v-${id}">${esc(e.label)}</label><input class="tb-input" id="v-${id}" name="value" type="password" autocomplete="off" required placeholder="${set ? "Replace value" : "Enter value"}"><button class="tb-btn${set ? "" : " primary"}" type="submit">${ink(set ? "Replace" : "Save")}</button></form>${set ? `<form class="bp-form-del" method="post" action="/keys">${hidden(n)}<input type="hidden" name="action" value="delete"><button class="tb-btn danger" type="submit">${ink("Delete")}</button></form>` : ""}</div>
  </section>`;
      })
      .join("");
    // the one-time success notice: the key's label from the table (the name the form sent was checked against it)
    const savedLabel = session.saved ? byName.get(session.saved)?.label : undefined;
    const notice = savedLabel ? `Saved ${savedLabel}.` : session.flash;
    delete session.saved;
    delete session.flash;
    const flash = notice ? `\n    <div class="tb-notice live" role="status"><span><strong>${esc(notice)}</strong> Apps that use it pick it up within a minute.</span></div>` : "";
    const models = renderModels(this.ctx, t, session.csrf, session.hints, apps);
    htmlPage(res, 200, {
      title: "Keys and models",
      workspace: t.config.workspace.name,
      apps: [...apps.values()],
      headers,
      main: `
  <section class="bp-card wide" aria-labelledby="h">
    <h1 id="h">Keys and models</h1>
    <p class="tb-soft">Keys are stored in your workspace only. Tealbrick Portal never sees them, and values are never shown again.</p>${flash}
    <h2>App keys</h2>
    ${rows ? `<div class="bp-keys">${rows}\n    </div>` : '<p class="tb-soft">No app needs a key.</p>'}
    <p class="tb-hint">This page closes its session after ${LIFETIME_S.keyPageSession / 60} minutes. Open it again from Portal when it expires.</p>
  </section>${renderProviderKeys(this.ctx, t, session.csrf)}${models}`,
    });
  }
}

/** why a key page save was refused (`bridge.keys.save_refused` code) */
type KeySaveRefusal = "rate_limited" | "too_large" | "body_invalid" | "ticket_invalid" | "page_expired" | "csrf_invalid" | "unknown_key" | "empty_value";

/** the apps (product ids) that request this key; null when no app does */
function keyApps(t: NonNullable<BridgeContext["table"]>, keyName: string | null): string | null {
  if (!keyName) return null;
  const apps = [...new Set(t.config.keyRequirements.filter((k) => k.source === "account_default" && k.name === keyName).map((k) => k.product))].sort();
  return apps.length ? apps.join(",") : null;
}

/** a key name as the form sent it, for the log: only a plain name shape, never a long or odd string (could be a value) */
function safeKeyName(keyName: string | null): string | null {
  if (!keyName) return null;
  return /^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(keyName) ? keyName : "(invalid)";
}

function unavailable(res: ServerResponse, requestId: string): void {
  sendJson(res, 503, envelope("app_unavailable", "the app is starting; try again in a few seconds", requestId), { "retry-after": "5" });
}

function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of (header ?? "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

export { BridgeError };

/**
 * C86 (BRIDGE §3 launch path): after the ticket POST the app SDK redirects to the ticket's `path`. The bridge keeps
 * that redirect only when it stays under the ticket's own `/a/<product>/` and the app-relative rest passes the
 * shared launch path rule (manifest isValidLaunchPath, L1); on any doubt → `/a/<product>/`.
 */
export function launchRedirect(product: string, location: string | undefined, isValidLaunchPath: (path: string) => boolean): string {
  const home = `/a/${product}/`;
  if (!location) return home;
  const prefix = `/a/${product}`;
  if (location !== prefix && !location.startsWith(home)) return home;
  const rest = location.slice(prefix.length) || "/";
  const path = rest.split(/[?#]/)[0] ?? "";
  return isValidLaunchPath(path) && isValidLaunchPath(rest) ? `${prefix}${rest}` : home;
}
