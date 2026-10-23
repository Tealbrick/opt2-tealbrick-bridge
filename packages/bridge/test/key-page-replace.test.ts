/**
 * The key page (BRIDGE §9.3) lets the owner REPLACE a key that is already set, not only fill an empty one (Martin, 2026-10-23: a key the
 * provider rejected must be changeable). Real bridge, the page over HTTP: a set key shows "Set" and a Replace form, a post with a new
 * value overwrites it (the apps' next key fetch and the status `keysRev` follow), the old value is never shown, delete still works.
 */
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import { BRG, makeWorld, type World, WS } from "./support/world.ts";

const now = () => Math.floor(Date.now() / 1000);
const NAME = "NOTES_API_KEY";

describe("key page: replace a key that is already set", () => {
  let w: World;
  before(async () => {
    w = await makeWorld({ real: true });
  });
  after(async () => {
    await w.close();
  });

  /** opens the page with a fresh one-time keys ticket; the form arrives in the POST response */
  async function open(): Promise<{ page: string; csrf: string; cookie: string }> {
    const ticket = await w.signPortal("tb-ticket+jwt", { iss: "tb:portal", sub: "tb:per:per_01HPPPPPPPPPPPPPPPPPPPPPPP", aud: `tb:brg:${BRG}`, iat: now(), exp: now() + 120, jti: w.api.ulid(), ws: WS, pur: "keys" });
    const r = await fetch(`${w.keysUrl}/keys`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ ticket }), redirect: "manual" });
    assert.equal(r.status, 200);
    const page = await r.text();
    return { page, csrf: /name="csrf" value="([^"]+)"/.exec(page)?.[1] as string, cookie: String(r.headers.get("set-cookie")).split(";")[0] as string };
  }
  const post = (s: { csrf: string; cookie: string }, fields: Record<string, string>) =>
    fetch(`${w.keysUrl}/keys`, { method: "POST", headers: { cookie: s.cookie, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ csrf: s.csrf, name: NAME, ...fields }), redirect: "manual" });
  const store = () => w.bridge.ctx.state.keyStore;

  test("empty key: the form says 'Enter value' / Save, tag Not set", async () => {
    const s = await open();
    assert.match(s.page, /placeholder="Enter value"/);
    assert.match(s.page, />\s*Save\s*</);
    assert.ok(!Object.hasOwn(store().values, NAME));
  });

  test("set key: tag Set, 'Replace value' / Replace, and a Delete form; a post with a NEW value overwrites the old one", async () => {
    const first = await open();
    assert.equal((await post(first, { value: "sk-old-111" })).status, 303);
    assert.equal(store().values[NAME], "sk-old-111");
    const rev1 = store().keysRev;

    const second = await open(); // a later visit (a new ticket), the key is already set
    assert.match(second.page, /placeholder="Replace value"/);
    assert.match(second.page, />\s*Replace\s*</);
    assert.match(second.page, /value="delete"/, "Delete stays available");
    assert.match(second.page, /tb-tag live[\s\S]{0,80}Set/);
    assert.ok(!second.page.includes("sk-old-111"), "the stored value is never rendered");

    const replaced = await post(second, { value: "  sk-new-222\n" }); // surrounding whitespace is trimmed
    assert.equal(replaced.status, 303);
    assert.equal(store().values[NAME], "sk-new-222", "the old value is gone");
    assert.ok(store().keysRev > rev1, "keysRev moved: apps long-polling for keys are woken");
    const again = await post({ csrf: second.csrf, cookie: second.cookie }, { value: "sk-newer-333" }); // same session, a second replace
    assert.equal(again.status, 303);
    assert.equal(store().values[NAME], "sk-newer-333");
  });

  test("replacing with an empty value is refused and keeps the old key; the new value is not in the status report", async () => {
    const s = await open();
    const rev = store().keysRev;
    const empty = await post(s, { value: "   " });
    assert.equal(empty.status, 400);
    assert.equal(store().values[NAME], "sk-newer-333");
    assert.equal(store().keysRev, rev);
    assert.ok(!JSON.stringify(w.acks).includes("sk-newer-333"));
  });

  test("delete removes it; a key no app declares cannot be replaced", async () => {
    const s = await open();
    assert.equal((await post(s, { action: "delete" })).status, 303);
    assert.ok(!Object.hasOwn(store().values, NAME));
    const bad = await post(s, { name: "UNDECLARED_KEY", value: "x" });
    assert.equal(bad.status, 400);
  });
});
