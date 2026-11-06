/**
 * Bridge 0.1.29 (C185, design/BRIDGE-PAGES.md): the bridge pages in the Tealbrick kit.
 *  - CSP: the generated kit subset is inlined and hashed (style-src 'sha256-…'), app colours in one nonce'd <style>,
 *    font-src/img-src 'self', no 'unsafe-inline'; the nonce is new per response; no style="" and no script without it.
 *  - /_tb/: exactly the font, the mark and the favicon, on both origins, immutable; anything else 404 (traversal too).
 *  - key page: a one-time "Saved <label>." notice after a good save (server side, nothing in the URL, no value).
 *  - appColor: manifest display.color (#rrggbb, white AA) → the kit table by product id → a neutral.
 *  - "Open Portal" goes to TB_PORTAL_URL only.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { request } from "node:http";
import { after, before, describe, test } from "node:test";
import { KEYS_CSS } from "../src/models-page.ts";
import { appColor, NEUTRAL_APP_COLOR, PAGE_CSS, PAGE_CSS_HASH } from "../src/pages.ts";
import { BRG, makeWorld, type World, WS } from "./support/world.ts";

const now = () => Math.floor(Date.now() / 1000);
const FORM = { "content-type": "application/x-www-form-urlencoded" };
const asset = (name: string) => readFileSync(new URL(`../assets/${name}`, import.meta.url));

/** the CSP directives of a page, by name */
const directives = (csp: string | null) => new Map((csp ?? "").split(";").map((d) => d.trim().split(/\s+/)).map(([k, ...v]) => [k as string, v.join(" ")]));
const nonceOf = (csp: string | null) => /'nonce-([A-Za-z0-9_-]+)'/.exec(csp ?? "")?.[1];

/** checks every rule a bridge HTML page must keep; returns the nonce */
function checkPage(r: Response, html: string, o: { script?: boolean } = {}): string {
  assert.match(r.headers.get("content-type") ?? "", /^text\/html; charset=utf-8$/);
  const csp = r.headers.get("content-security-policy");
  assert.ok(csp && !csp.includes("unsafe-inline"), `no 'unsafe-inline': ${csp}`);
  const nonce = nonceOf(csp) as string;
  assert.ok(nonce && nonce.length >= 22, "a nonce of 16 random bytes");
  const d = directives(csp);
  assert.deepEqual([...d.keys()], ["default-src", "style-src", "font-src", "img-src", "script-src", "form-action", "frame-ancestors", "base-uri"]);
  assert.equal(d.get("default-src"), "'none'");
  assert.equal(d.get("style-src"), `'${PAGE_CSS_HASH}' 'nonce-${nonce}'`);
  assert.equal(d.get("font-src"), "'self'");
  assert.equal(d.get("img-src"), "'self'");
  assert.equal(d.get("script-src"), o.script ? `'nonce-${nonce}'` : "'none'");
  assert.equal(d.get("frame-ancestors"), "'none'");
  assert.equal(d.get("base-uri"), "'none'");
  // the first <style> is the hashed stylesheet, byte for byte; the second carries the nonce
  const styles = [...html.matchAll(/<style([^>]*)>([\s\S]*?)<\/style>/g)];
  assert.equal(styles.length, 2, "exactly two <style> elements");
  assert.equal(styles[0]?.[1], "");
  assert.equal(`sha256-${createHash("sha256").update(styles[0]?.[2] ?? "", "utf8").digest("base64")}`, PAGE_CSS_HASH, "the CSP hash matches the inlined CSS");
  assert.equal(styles[0]?.[2], PAGE_CSS);
  assert.equal(styles[1]?.[1], ` nonce="${nonce}"`);
  assert.doesNotMatch(html, /\sstyle\s*=/i, "no style attribute anywhere");
  for (const s of html.matchAll(/<script\b([^>]*)>/gi)) assert.equal(s[1], ` nonce="${nonce}"`, "every <script> carries the response nonce");
  assert.equal(/<script\b/i.test(html), !!o.script);
  assert.match(html, /<img class="tb-mark" src="\/_tb\/mark\.png"/);
  assert.match(html, /<link rel="icon" href="\/_tb\/favicon\.png"/);
  assert.match(html, /Tealbrick/);
  assert.doesNotMatch(html, /Teal Brick/, "the brand is one word");
  return nonce;
}

/** a GET with the path exactly as written (fetch would resolve "..") */
function rawGet(base: string, path: string, method = "GET"): Promise<{ status: number; type: string | undefined; body: string }> {
  const u = new URL(base);
  return new Promise((resolve, reject) => {
    const req = request({ host: "127.0.0.1", port: u.port, path, method, headers: { host: u.host } }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, type: res.headers["content-type"], body: Buffer.concat(chunks).toString("utf8") }));
    });
    req.on("error", reject);
    req.end();
  });
}

describe("bridge pages: CSP, assets, notices (C185)", () => {
  let w: World;
  let portalUrl = "";
  let cookie = "";
  let csrf = "";
  before(async () => {
    w = await makeWorld({ real: true });
    portalUrl = String(w.bridgeEnv().TB_PORTAL_URL);
    const ticket = await w.signPortal("tb-ticket+jwt", { iss: "tb:portal", sub: "tb:per:per_01HPPPPPPPPPPPPPPPPPPPPPPP", aud: `tb:brg:${BRG}`, iat: now(), exp: now() + 120, jti: w.api.ulid(), ws: WS, pur: "keys" });
    const open = await fetch(`${w.keysUrl}/keys`, { method: "POST", headers: FORM, body: new URLSearchParams({ ticket }), redirect: "manual" });
    assert.equal(open.status, 200);
    cookie = String(open.headers.get("set-cookie")).split(";")[0] as string;
    const html = await open.text();
    checkPage(open, html, { script: true }); // spec 0.1.92 item 12: the key page's one nonce'd script
    csrf = /name="csrf" value="([^"]+)"/.exec(html)?.[1] as string;
    assert.ok(csrf);
  });
  after(async () => {
    await w.close();
  });

  const keysGet = () => fetch(`${w.keysUrl}/keys`, { headers: { cookie } });
  const save = (fields: Record<string, string>) => fetch(`${w.keysUrl}/keys`, { method: "POST", headers: { ...FORM, cookie }, body: new URLSearchParams(fields), redirect: "manual" });

  test("CSP: exact directives, hash = the inlined CSS, a new nonce per response, no 'unsafe-inline'", async () => {
    const a = await keysGet();
    const b = await keysGet();
    const na = checkPage(a, await a.text(), { script: true });
    const nb = checkPage(b, await b.text(), { script: true });
    assert.notEqual(na, nb, "the nonce changes per response");
    assert.equal(directives(a.headers.get("content-security-policy")).get("form-action"), "'self'");
    // the hash is computed from the shipped asset, never a hand-copied string
    assert.equal(PAGE_CSS, asset("bridge-pages.css").toString("utf8"));
    assert.equal(PAGE_CSS_HASH, `sha256-${createHash("sha256").update(asset("bridge-pages.css")).digest("base64")}`);
  });

  test("the auto-submit to Portal: the one script runs under the response nonce, form-action = the Portal origin", async () => {
    const hw = await makeWorld({ real: true, env: { TB_PUBLIC_URL: "https://127.0.0.1" } });
    try {
      const reg = await (await fetch(`${hw.publicUrl}/oauth/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ redirect_uris: ["http://127.0.0.1:1/cb"], client_name: "x" }) })).json();
      const q = new URLSearchParams({ response_type: "code", client_id: reg.client_id, redirect_uri: "http://127.0.0.1:1/cb", code_challenge: "a".repeat(43), code_challenge_method: "S256", state: "s" });
      const page = await fetch(`${hw.publicUrl}/oauth/authorize?${q}`);
      const html = await page.text();
      checkPage(page, html);
      const rid = /name="rid" value="([^"]+)"/.exec(html)?.[1] as string;
      const r = await fetch(`${hw.publicUrl}/oauth/authorize`, { method: "POST", headers: FORM, body: new URLSearchParams({ rid, action: "portal" }) });
      assert.equal(r.status, 200);
      const body = await r.text();
      const nonce = checkPage(r, body, { script: true });
      const portal = String(hw.bridgeEnv().TB_PORTAL_URL);
      assert.equal(directives(r.headers.get("content-security-policy")).get("form-action"), new URL(portal).origin);
      assert.ok(body.includes(`<script nonce="${nonce}">document.getElementById("f").submit()</script>`));
      assert.match(body, new RegExp(`<form class="tb-ctas" id="f" method="post" action="${portal.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}/pair"><input type="hidden" name="state" value="[^"]+">`));
      assert.match(body, /<noscript><button class="tb-btn primary" type="submit">/);
    } finally {
      await hw.close();
    }
  });

  test("no page has a style attribute or a script without the nonce (every page the bridge serves)", async () => {
    const reg = await (await fetch(`${w.publicUrl}/oauth/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ redirect_uris: ["http://127.0.0.1:1/cb"], client_name: "x" }) })).json();
    const q = new URLSearchParams({ response_type: "code", client_id: reg.client_id, redirect_uri: "http://127.0.0.1:1/cb", code_challenge: "a".repeat(43), code_challenge_method: "S256", state: "s" });
    const connect = await fetch(`${w.publicUrl}/oauth/authorize?${q}`);
    const connectHtml = await connect.text();
    checkPage(connect, connectHtml);
    const rid = /name="rid" value="([^"]+)"/.exec(connectHtml)?.[1] as string;
    const post = (fields: Record<string, string>, path = "/oauth/authorize") => fetch(`${w.publicUrl}${path}`, { method: "POST", headers: FORM, body: new URLSearchParams(fields), redirect: "manual" });
    const pages: [string, Promise<Response>, number][] = [
      ["unknown client", fetch(`${w.publicUrl}/oauth/authorize?client_id=x&redirect_uri=https%3A%2F%2Fx.example%2Fcb`), 400],
      ["request not valid", fetch(`${w.publicUrl}/oauth/authorize?${new URLSearchParams({ ...Object.fromEntries(q), response_type: "token" })}`), 400],
      ["request expired", post({ rid: "nope", action: "paste", code: "x" }), 400],
      ["bad action", post({ rid, action: "other" }), 400],
      ["config error (http public URL)", post({ rid, action: "portal" }), 400],
      ["pasted code refused", post({ rid, action: "paste", code: "tb_pair_not-a-code" }), 400],
      ["callback code refused", post({ code: "x.y.z" }, "/oauth/pair/callback"), 400],
      ["launch link expired", post({ ticket: "x.y.z" }, "/a/notes/tb/launch"), 401],
      ["key page on the main origin", fetch(`${w.publicUrl}/keys`), 404],
      ["keys: open from Portal", fetch(`${w.keysUrl}/keys`), 401],
      ["keys: link expired", fetch(`${w.keysUrl}/keys`, { method: "POST", headers: FORM, body: new URLSearchParams({ ticket: "x.y.z" }) }), 401],
      ["keys: page expired", fetch(`${w.keysUrl}/keys`, { method: "POST", headers: FORM, body: new URLSearchParams({ csrf, name: "NOTES_API_KEY", value: "v" }) }), 401],
      ["keys: not saved", save({ csrf, name: "NOTES_API_KEY", value: " " }), 400],
      ["keys: unknown key", save({ csrf, name: "OTHER_KEY", value: "v" }), 400],
      ["keys: form expired", save({ csrf: "wrong", name: "NOTES_API_KEY", value: "v" }), 403],
    ];
    for (const [what, p, status] of pages) {
      const r = await p;
      assert.equal(r.status, status, what);
      if (status === 404) {
        assert.match(r.headers.get("content-type") ?? "", /json/, `${what}: JSON, not a page`);
        continue;
      }
      checkPage(r, await r.text());
    }
  });

  test("a refused pasted code: the connect page again, pairing form open, the refusal shown, the code never echoed", async () => {
    const reg = await (await fetch(`${w.publicUrl}/oauth/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ redirect_uris: ["http://127.0.0.1:1/cb"], client_name: "x" }) })).json();
    const q = new URLSearchParams({ response_type: "code", client_id: reg.client_id, redirect_uri: "http://127.0.0.1:1/cb", code_challenge: "a".repeat(43), code_challenge_method: "S256", state: "s" });
    const html = await (await fetch(`${w.publicUrl}/oauth/authorize?${q}`)).text();
    assert.match(html, /<details class="bp-pair"><summary>/, "closed by default");
    const rid = /name="rid" value="([^"]+)"/.exec(html)?.[1] as string;
    const code = "tb_pair_REFUSED-code-never-echoed";
    const r = await fetch(`${w.publicUrl}/oauth/authorize`, { method: "POST", headers: FORM, body: new URLSearchParams({ rid, action: "paste", code }), redirect: "manual" });
    assert.equal(r.status, 400);
    const body = await r.text();
    assert.match(body, /<details class="bp-pair" open>/);
    assert.match(body, /aria-invalid="true"/);
    assert.match(body, /<span class="tb-error" id="code-error">This pairing code is not valid for this workspace/);
    assert.ok(!body.includes(code), "the refused code is not put back into the page");
    assert.ok(body.includes(`name="rid" value="${rid}"`), "the same request can be retried");
  });

  test("/_tb/: the three files on both origins, immutable, exact types; anything else (traversal too) → 404", async () => {
    const files: [string, string, string][] = [
      ["nunito-latin-wght-normal.woff2", "font/woff2", "nunito-latin-wght-normal.woff2"],
      ["mark.png", "image/png", "mark.png"],
      ["favicon.png", "image/png", "favicon.png"],
    ];
    for (const base of [w.publicUrl, w.keysUrl])
      for (const [name, type, file] of files) {
        const r = await fetch(`${base}/_tb/${name}`);
        assert.equal(r.status, 200, `${base} ${name}`);
        assert.equal(r.headers.get("content-type"), type);
        assert.equal(r.headers.get("cache-control"), "public, max-age=31536000, immutable");
        assert.equal(r.headers.get("x-content-type-options"), "nosniff");
        assert.ok(Buffer.from(await r.arrayBuffer()).equals(asset(file)), "the shipped bytes");
      }
    const head = await fetch(`${w.publicUrl}/_tb/mark.png`, { method: "HEAD" });
    assert.equal(head.status, 200);
    const postIt = await fetch(`${w.publicUrl}/_tb/mark.png`, { method: "POST" });
    assert.equal(postIt.status, 405);
    for (const base of [w.publicUrl, w.keysUrl])
      for (const path of ["/_tb/", "/_tb", "/_tb/unknown.png", "/_tb/MARK.PNG", "/_tb/mark.png/", "/_tb/mark.png%00", "/_tb//mark.png", "/_tb/fonts/", "/_tb/bridge-pages.css", "/_tb/OFL.txt", "/_tb/../package.json", "/_tb/../../package.json", "/_tb/%2e%2e/package.json", "/_tb/..%2fpackage.json", "/_tb/..%2f..%2fpackage.json", "/_tb/%2e%2e%2fassets%2fmark.png", "/_tb/__proto__", "/_tb/constructor", "/_tb/toString"]) {
        const r = await rawGet(base, path);
        assert.equal(r.status, 404, `${base} ${path} → ${r.status}`);
        assert.match(r.type ?? "", /json/, `${path}: a JSON 404, no file`);
        assert.ok(!r.body.includes('"version"') && !r.body.includes("PNG"), `${path}: no file content`);
      }
  });

  test("key saved: a one-time notice with the key's label, no value and nothing in the URL; delete and refusals show none", async () => {
    const value = "sk-flash-value-NEVER-shown";
    const r = await save({ csrf, name: "NOTES_API_KEY", value });
    assert.equal(r.status, 303);
    assert.equal(r.headers.get("location"), "/keys", "no marker in the URL");
    const first = await keysGet();
    const html = await first.text();
    checkPage(first, html, { script: true });
    assert.match(html, /<div class="tb-notice live" role="status"><span><strong>Saved Notes key for Notes\.<\/strong> Apps that use it pick it up within a minute\.<\/span><\/div>/);
    assert.ok(!html.includes(value), "the value is never shown");
    assert.match(html, /<span class="tb-tag live"><span class="tb-ink">Set<\/span><\/span>/);
    const second = await (await keysGet()).text();
    assert.ok(!second.includes("tb-notice live"), "shown once");
    // a refused save after it shows no notice either
    assert.equal((await save({ csrf, name: "NOTES_API_KEY", value: " " })).status, 400);
    assert.ok(!(await (await keysGet()).text()).includes("tb-notice live"));
    // delete: no "Saved" notice
    assert.equal((await save({ csrf, name: "NOTES_API_KEY", action: "delete" })).status, 303);
    const afterDelete = await (await keysGet()).text();
    assert.ok(!afterDelete.includes("tb-notice live"));
    assert.match(afterDelete, /<span class="tb-tag needs-you"><span class="tb-ink">Not set<\/span><\/span>/);
  });

  test("the key page shows apps by name with their colour in the nonce'd block; Open Portal = TB_PORTAL_URL only", async () => {
    const r = await keysGet();
    const html = await r.text();
    const nonce = checkPage(r, html, { script: true });
    assert.match(html, /<span class="bp-app bp-a-notes">Notes<\/span>/, "the production name, not the product id");
    assert.ok(html.includes(`<style nonce="${nonce}">.bp-a-notes{--app:${NEUTRAL_APP_COLOR}}${KEYS_CSS}</style>`), "an app without a kit colour gets the neutral");
    // launch link expired: the app band + "Open <app> from Portal" to the configured Portal, whatever the request says
    const l = await fetch(`${w.publicUrl}/a/notes/tb/launch?next=https://evil.example`, { method: "POST", headers: { ...FORM, referer: "https://evil.example/" }, body: new URLSearchParams({ ticket: "x.y.z" }) });
    assert.equal(l.status, 401);
    const lh = await l.text();
    checkPage(l, lh);
    assert.match(lh, /<div class="bp-band bp-a-notes"><span class="bp-initial" aria-hidden="true">N<\/span><span><b>Notes<\/b><small>Mini app in Test workspace<\/small><\/span><\/div>/);
    const hrefs = [...lh.matchAll(/href="([^"]*)"/g)].map((m) => m[1]).filter((h) => h !== "/_tb/favicon.png");
    assert.deepEqual(hrefs, [portalUrl]);
    assert.ok(lh.includes("Open Notes from Portal"));
    assert.ok(!lh.includes("evil.example"));
    const k = await (await fetch(`${w.keysUrl}/keys`)).text();
    assert.deepEqual([...k.matchAll(/href="([^"]*)"/g)].map((m) => m[1]).filter((h) => h !== "/_tb/favicon.png"), [portalUrl]);
  });
});

describe("appColor (C185): manifest display.color → kit table → neutral", () => {
  const table = (id: string) => new RegExp(`--tb-app-${id}:(#[0-9a-f]{6})`).exec(PAGE_CSS)?.[1];
  test("the kit table by product id, and a neutral for an unknown app", () => {
    const kanban = table("kanban");
    assert.ok(kanban);
    assert.equal(appColor("kanban", undefined), kanban);
    assert.equal(appColor("kanban", { name: "Task Board" }), kanban);
    assert.equal(appColor("no-such-app", undefined), NEUTRAL_APP_COLOR);
    assert.equal(appColor("on", undefined), NEUTRAL_APP_COLOR, "--tb-app-on is the text colour, not an app");
  });
  test("display.color wins when it is #rrggbb with white text at AA; anything else is ignored", () => {
    assert.equal(appColor("no-such-app", { display: { color: "#1F4E79" } }), "#1f4e79");
    assert.equal(appColor("kanban", { display: { color: "#1f4e79" } }), "#1f4e79");
    for (const bad of ["#ffffff", "#e7e2d8", "red", "#123", "#1f4e79;}body{display:none", "#1f4e79 ", 0x1f4e79, null, ["#1f4e79"]])
      assert.equal(appColor("no-such-app", { display: { color: bad } }), NEUTRAL_APP_COLOR, String(bad));
    assert.equal(appColor("kanban", { display: { color: "#ffffff" } }), table("kanban"), "too light for white text → the table");
  });
  test("the neutral carries white text at AA (the band is white on the colour)", () => {
    const lum = (h: string) => {
      const c = [1, 3, 5].map((i) => Number.parseInt(h.slice(i, i + 2), 16) / 255).map((v) => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4));
      return 0.2126 * (c[0] as number) + 0.7152 * (c[1] as number) + 0.0722 * (c[2] as number);
    };
    assert.ok(1.05 / (lum(NEUTRAL_APP_COLOR) + 0.05) >= 4.5);
  });
});
