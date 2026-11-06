/**
 * One key per provider (spec 0.1.92, BRIDGE "v0.1.92 — one key per provider", rows PK-1..PK-6; Martin 2026-11-06: "input a
 * key once … and it will disperse it for all the apps that need it"). Real bridge, the page over HTTP, apps over the
 * internal listener. Every value here is a fake test value.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { after, before, describe, test } from "node:test";
import type { ModelRoleRequirementEntry } from "@opt2-tealbrick/spec/bridge";
import type { Ed25519KeyPair } from "@opt2-tealbrick/spec/sdk";
import { buildStatusReport } from "../src/portal.ts";
import { bindingKeyName, keyNames, keyProviderOf, resolveAppKey } from "../src/provider-keys.ts";
import type { ModelBinding } from "../src/state.ts";
import { BRG, HOOKINS, INS, makeWorld, type World, WS, waitFor } from "./support/world.ts";

const now = () => Math.floor(Date.now() / 1000);
const FORM = { "content-type": "application/x-www-form-urlencoded" };
const req = (name: string, ins: string, product: string, provider?: string, source = "account_default") => ({ name, label: `${name} label`, ...(provider ? { provider } : {}), ins, product, required: false, source, usedBy: ["app"] }) as never;
const ROLES = [
  { role: "reasoning", ins: INS, product: "notes", required: true, minPolicy: "standard", usedBy: ["app"] },
  { role: "dreaming", ins: INS, product: "notes", required: false, minPolicy: "standard", usedBy: ["app"] },
  { role: "reasoning", ins: HOOKINS, product: "guard", required: true, minPolicy: "standard", usedBy: ["app"] },
] as ModelRoleRequirementEntry[];

/** the rules of bridge 0.2.15 (state as it reads it): key fetch = the value under the name; a binding = its keyName (pk: only) */
const old015 = {
  key: (values: Record<string, string>, name: string) => values[name],
  bound: (values: Record<string, string>, b: ModelBinding) => (b.keyName?.startsWith("pk:") ? values[b.keyName] : undefined),
};

describe("PK-1 link rule (unit)", () => {
  const t = (reqs: unknown[]) => ({ config: { keyRequirements: reqs } }) as never;
  test("a name links when every account_default entry names the same keyNeeded provider (id or label)", () => {
    assert.equal(keyProviderOf("OpenAI")?.id, "openai");
    assert.equal(keyProviderOf("Composio"), undefined);
    assert.equal(keyProviderOf("ollama"), undefined, "a provider without keys never links");
    const both = keyNames(t([req("OPENAI_API_KEY", INS, "notes", "OpenAI"), req("OPENAI_API_KEY", HOOKINS, "guard", "openai")]));
    assert.equal(both[0]?.provider?.id, "openai");
    assert.deepEqual(both[0]?.products, ["guard", "notes"]);
    const mixed = keyNames(t([req("OPENAI_API_KEY", INS, "notes", "OpenAI"), req("OPENAI_API_KEY", HOOKINS, "guard")]));
    assert.equal(mixed[0]?.provider, undefined, "one app plain → plain for all");
    const two = keyNames(t([req("X_KEY", INS, "notes", "OpenAI"), req("X_KEY", HOOKINS, "guard", "Anthropic")]));
    assert.equal(two[0]?.provider, undefined, "two providers → plain");
    const own = keyNames(t([req("OPENAI_API_KEY", INS, "notes", "OpenAI"), req("OPENAI_API_KEY", HOOKINS, "guard", "OpenAI", "app_own")]));
    assert.equal(own[0]?.provider, undefined, "an app_own entry → never linked");
    const st = { keyStore: { keysRev: 1, values: { "pk:@openai": "sk-test-keys-lead-unit", "pk:OPENAI_API_KEY": "sk-test-keys-lead-label" } } } as never;
    assert.equal(resolveAppKey(st, t([req("OPENAI_API_KEY", INS, "notes", "OpenAI")]), "OPENAI_API_KEY"), "sk-test-keys-lead-unit");
    assert.equal(resolveAppKey(st, t([req("OPENAI_API_KEY", INS, "notes")]), "OPENAI_API_KEY"), undefined, "a plain name never falls back; a look-alike label never links");
  });
  test("PK-4 (unit): a binding key name is its provider's key, an older named key, or nothing", () => {
    assert.equal(bindingKeyName({ provider: "openai" }), "pk:@openai");
    assert.equal(bindingKeyName({ provider: "openai", keyName: "pk:@openai" }), "pk:@openai");
    assert.equal(bindingKeyName({ provider: "openai", keyName: "pk:@anthropic" }), undefined, "never another provider's key");
    assert.equal(bindingKeyName({ provider: "openai", keyName: "pk:OpenAI main" }), "pk:OpenAI main");
    assert.equal(bindingKeyName({ provider: "openai", keyName: "OPENAI_API_KEY" }), undefined, "a requirement key never satisfies a binding");
    assert.equal(bindingKeyName({ provider: "ollama" }), undefined);
  });
});

describe("one key per provider: page, resolve, mirrors, conflicts (PK-1..PK-6)", () => {
  let w: World;
  let notesKey: Ed25519KeyPair;
  let guardKey: Ed25519KeyPair;
  let cookie = "";
  let csrf = "";
  const st = () => w.bridge.ctx.state;
  const values = () => st().keyStore.values;
  const open = async () => {
    const ticket = await w.signPortal("tb-ticket+jwt", { iss: "tb:portal", sub: "tb:per:per_01HPPPPPPPPPPPPPPPPPPPPPPP", aud: `tb:brg:${BRG}`, iat: now(), exp: now() + 120, jti: w.api.ulid(), ws: WS, pur: "keys" });
    const r = await fetch(`${w.keysUrl}/keys`, { method: "POST", headers: FORM, body: new URLSearchParams({ ticket }), redirect: "manual" });
    assert.equal(r.status, 200);
    cookie = String(r.headers.get("set-cookie")).split(";")[0] as string;
    const html = await r.text();
    csrf = /name="csrf" value="([^"]+)"/.exec(html)?.[1] as string;
    return html;
  };
  const page = async () => (await fetch(`${w.keysUrl}/keys`, { headers: { cookie } })).text();
  const post = (fields: Record<string, string>) => fetch(`${w.keysUrl}/keys`, { method: "POST", headers: { ...FORM, cookie }, body: new URLSearchParams({ csrf, ...fields }), redirect: "manual" });
  const fetchAs = async (key: Ed25519KeyPair, ins: string, path: string) => {
    const assertion = await w.api.signAssertion("tb-instance-assert+jwt", { iss: `tb:ins:${ins}`, sub: `tb:ins:${ins}`, aud: `tb:brg:${BRG}`, iat: now(), exp: now() + 60, jti: w.api.ulid() }, key, { method: "GET", pathAndQuery: path });
    const r = await fetch(`${w.internalUrl}${path}`, { headers: { "TB-Assert": assertion } });
    return { status: r.status, json: JSON.parse((await r.text()) || "null") };
  };
  const appKey = async (key: Ed25519KeyPair, ins: string, name: string) => (await fetchAs(key, ins, `/tb/v1/keys/${name}`)).json?.value as string | undefined;
  const statusSet = (name: string, ins = INS) => buildStatusReport(w.bridge.ctx).keys.find((k) => k.name === name && k.ins === ins)?.set;
  /** PK-3: no stored value, its last 4 characters, its sha256 (hex or base64) or its base64 on the page */
  const noLeak = (html: string) => {
    for (const v of Object.values(values())) {
      for (const probe of [v, v.slice(-4), createHash("sha256").update(v).digest("hex"), createHash("sha256").update(v).digest("base64"), Buffer.from(v).toString("base64")]) assert.ok(!html.includes(probe), `the page leaks ${probe.slice(0, 6)}…`);
    }
  };

  before(async () => {
    w = await makeWorld({ real: true, withHook: true });
    notesKey = await w.api.generateKeyPair();
    guardKey = await w.api.generateKeyPair();
    await w.amend((c) => {
      c.instanceKeys.push({ ins: INS, jwk: notesKey.publicJwk } as never, { ins: HOOKINS, jwk: guardKey.publicJwk } as never);
      c.modelRoleRequirements = ROLES;
      c.keyRequirements.push(req("OPENAI_API_KEY", INS, "notes", "OpenAI"), req("OPENAI_API_KEY", HOOKINS, "guard", "openai"), req("ANTHROPIC_API_KEY", INS, "notes", "Anthropic"), req("COMPOSIO_API_KEY", HOOKINS, "guard", "Composio"));
    });
    await waitFor(() => w.bridge.ctx.table?.rev === w.rev(), 15000);
  });
  after(async () => {
    await w.close();
  });

  test("the page: sections in order, every save names its scope, one nonce'd script, forms work without it", async () => {
    const html = await open();
    const order = ["1 · Provider keys", "2 · Models: workspace defaults", "3 · Overrides for one app", "4 · Other app keys"].map((h) => html.indexOf(h));
    assert.ok(order.every((i, n) => i > 0 && (n === 0 || i > (order[n - 1] as number))), `sections in order: ${order}`);
    assert.match(html, /<h3 id="pv-openai">OpenAI<\/h3>/, "a provider a requirement links to has a row");
    assert.match(html, /<h3 id="pv-anthropic">Anthropic<\/h3>/);
    assert.match(html, /Save for all apps/);
    assert.match(html, /Save for Notes · Dreaming only/);
    assert.match(html, /Save for Guard · Reasoning \(chat\) only/);
    assert.match(html, /Replace for Guard|Save for Guard/, "Composio is an other app key, scoped to Guard");
    assert.doesNotMatch(html, /id="k-OPENAI_API_KEY"/, "a linked name is not an 'other app key'");
    assert.match(html, /OPENAI_API_KEY<\/strong> <span class="tb-tag live"><span class="tb-ink">Follows the OpenAI key/);
    assert.equal((html.match(/<script\b/g) ?? []).length, 1);
    assert.match(html, /<form class="bp-form" method="post" action="\/keys" data-binding>/, "binding forms are plain POST forms");
    assert.doesNotMatch(html, /\son[a-z]+=/i, "no event-handler attributes");
  });

  test("PK-2 / PK-1 / PK-6: Save for all apps reaches both apps, mirrors under the name, one keysRev; status follows", async () => {
    assert.equal(statusSet("OPENAI_API_KEY"), false);
    const rev = st().keyStore.keysRev;
    assert.equal((await post({ action: "prov_save", provider: "openai", value: " sk-test-keys-lead-AAAA\n" })).status, 303);
    assert.equal(st().keyStore.keysRev, rev + 1, "one revision");
    assert.equal(values()["pk:@openai"], "sk-test-keys-lead-AAAA");
    assert.equal(await appKey(notesKey, INS, "OPENAI_API_KEY"), "sk-test-keys-lead-AAAA", "Notes gets it");
    assert.equal(await appKey(guardKey, HOOKINS, "OPENAI_API_KEY"), "sk-test-keys-lead-AAAA", "Guard gets it");
    assert.equal(values().OPENAI_API_KEY, "sk-test-keys-lead-AAAA", "mirrored under its own name (rollback)");
    assert.equal(statusSet("OPENAI_API_KEY"), true);
    assert.equal(statusSet("OPENAI_API_KEY", HOOKINS), true);
    assert.equal((await fetchAs(guardKey, HOOKINS, "/tb/v1/keys/COMPOSIO_API_KEY")).status, 404, "a plain name never falls back");
    const html = await page();
    assert.match(html, /Saved the OpenAI key for all apps\./);
    assert.match(html, /Used by:<\/span><span>[^<]*Guard, Notes · OPENAI_API_KEY/);
    noLeak(html);
    // replace: the mirror follows
    assert.equal((await post({ action: "prov_save", provider: "openai", value: "sk-test-keys-lead-BBBB" })).status, 303);
    assert.equal(values().OPENAI_API_KEY, "sk-test-keys-lead-BBBB");
    assert.equal(await appKey(notesKey, INS, "OPENAI_API_KEY"), "sk-test-keys-lead-BBBB");
  });

  test("PK-4: a default binding saved on the page names the provider key; both apps resolve it; an override for one app and role", async () => {
    assert.equal((await post({ action: "bind", role: "reasoning", provider: "openai", model: "gpt-test-default" })).status, 303);
    const def = st().bindings.find((b) => b.role === "reasoning" && !b.ins);
    assert.equal(def?.keyName, "pk:@openai", "stored explicitly (rollback)");
    for (const [key, ins] of [[notesKey, INS], [guardKey, HOOKINS]] as const) {
      const r = (await fetchAs(key, ins, "/tb/v1/model-roles/reasoning")).json;
      assert.equal(r.key, "sk-test-keys-lead-BBBB");
      assert.equal(r.model, "gpt-test-default");
    }
    // Notes · reasoning only: Anthropic (its key not set yet → role_not_set for Notes, Guard unchanged)
    assert.equal((await post({ action: "bind", role: "reasoning", ins: INS, provider: "anthropic", model: "claude-test-override" })).status, 303);
    assert.equal((await fetchAs(notesKey, INS, "/tb/v1/model-roles/reasoning")).json.error.code, "role_not_set");
    assert.equal((await fetchAs(guardKey, HOOKINS, "/tb/v1/model-roles/reasoning")).json.model, "gpt-test-default", "Guard keeps the default");
    assert.equal((await post({ action: "prov_save", provider: "anthropic", value: "sk-test-keys-lead-ANT1" })).status, 303);
    const notes = (await fetchAs(notesKey, INS, "/tb/v1/model-roles/reasoning")).json;
    assert.deepEqual([notes.provider, notes.model, notes.key], ["anthropic", "claude-test-override", "sk-test-keys-lead-ANT1"]);
    assert.equal(values().ANTHROPIC_API_KEY, "sk-test-keys-lead-ANT1", "the linked Anthropic name is mirrored too");
    const html = await page();
    assert.match(html, /<strong>Reasoning \(chat\)<\/strong> <span class="tb-tag busy"><span class="tb-ink">Override/);
    assert.match(html, /Saved the Anthropic key for all apps\./);
    // a key of another provider never resolves; the page refuses it
    assert.equal((await post({ action: "bind", role: "dreaming", provider: "openai", model: "m", keyName: "pk:@anthropic" })).status, 400);
    assert.equal((await post({ action: "unbind", role: "reasoning", ins: INS })).status, 303);
    assert.equal((await fetchAs(notesKey, INS, "/tb/v1/model-roles/reasoning")).json.model, "gpt-test-default", "back to the default");
  });

  test("PK-4: a key for one setting only; deleting it moves the binding to the provider key", async () => {
    assert.equal((await post({ action: "bind", role: "dreaming", ins: INS, provider: "openai", model: "gpt-dream", newKey: "sk-test-keys-lead-ONE1" })).status, 303);
    const b = st().bindings.find((x) => x.role === "dreaming" && x.ins === INS);
    assert.equal(b?.keyName, "pk:OpenAI · Notes · Dreaming");
    assert.equal((await fetchAs(notesKey, INS, "/tb/v1/model-roles/dreaming")).json.key, "sk-test-keys-lead-ONE1");
    assert.equal((await post({ action: "pkey_delete", label: "OpenAI · Notes · Dreaming", confirm: "1" })).status, 303);
    assert.equal(st().bindings.find((x) => x.role === "dreaming" && x.ins === INS)?.keyName, "pk:@openai");
    assert.equal((await fetchAs(notesKey, INS, "/tb/v1/model-roles/dreaming")).json.key, "sk-test-keys-lead-BBBB");
    assert.equal((await post({ action: "pkey", label: "@openai", value: "sk-test-keys-lead-AT" })).status, 400, "an @ label is the provider namespace");
  });

  test("PK-3 / item 7: a differing app value is a conflict; differs, no value bytes; keep → override; follow → mirror", async () => {
    // an owner value for the linked name (the 0.2.15 way: written directly under the name, not an override)
    st().keyStore.values.OPENAI_API_KEY = "sk-test-keys-lead-DIFF";
    st().saveKeyStore();
    let html = await page();
    assert.match(html, /These OpenAI keys differ\./);
    assert.match(html, /<strong>Value 2<\/strong> <span class="tb-tag needs-you">differs<\/span>: OPENAI_API_KEY \(Guard, Notes\)/);
    noLeak(html);
    // a new provider value skips the differing name (never resolved silently)
    assert.equal((await post({ action: "prov_save", provider: "openai", value: "sk-test-keys-lead-CCCC" })).status, 303);
    assert.equal(values().OPENAI_API_KEY, "sk-test-keys-lead-DIFF");
    assert.equal(await appKey(notesKey, INS, "OPENAI_API_KEY"), "sk-test-keys-lead-DIFF", "its own value wins");
    // keep as an override: no conflict any more, and a later provider save still skips it
    assert.equal((await post({ action: "akey_keep", name: "OPENAI_API_KEY" })).status, 303);
    assert.deepEqual(st().keyStore.overrides, ["OPENAI_API_KEY"]);
    html = await page();
    assert.doesNotMatch(html, /These OpenAI keys differ/);
    assert.match(html, /OPENAI_API_KEY<\/strong> <span class="tb-tag busy"><span class="tb-ink">Override/);
    assert.equal((await post({ action: "prov_save", provider: "openai", value: "sk-test-keys-lead-DDDD" })).status, 303);
    assert.equal(values().OPENAI_API_KEY, "sk-test-keys-lead-DIFF", "an override is never mirrored");
    // follow: the provider value under the name (a mirror), the override is gone
    assert.equal((await post({ action: "akey_follow", name: "OPENAI_API_KEY" })).status, 303);
    assert.equal(values().OPENAI_API_KEY, "sk-test-keys-lead-DDDD");
    assert.equal(st().keyStore.overrides, undefined);
    // an override entered on the page ("Save for Guard, Notes only")
    assert.equal((await post({ name: "OPENAI_API_KEY", value: "sk-test-keys-lead-OVR1" })).status, 303);
    assert.deepEqual(st().keyStore.overrides, ["OPENAI_API_KEY"]);
    assert.match(await page(), /Saved OPENAI_API_KEY label for Guard, Notes only\./);
    assert.equal((await post({ name: "OPENAI_API_KEY", action: "delete" })).status, 303, "delete of a linked name = follow");
    assert.equal(values().OPENAI_API_KEY, "sk-test-keys-lead-DDDD");
  });

  test("PK-3: before a provider key exists, one found value is offered once; two differing values ask; adopt writes only what it names", async () => {
    assert.equal((await post({ action: "prov_delete", provider: "openai" })).status, 200, "asks first: it serves");
    assert.equal((await post({ action: "prov_delete", provider: "openai", confirm: "1" })).status, 303);
    assert.ok(!Object.hasOwn(values(), "pk:@openai"));
    assert.ok(!Object.hasOwn(values(), "OPENAI_API_KEY"), "its mirror went with it");
    // the state of an older bridge: an app key and an older named key with different values
    st().commitKeys({ OPENAI_API_KEY: "sk-test-keys-lead-APP0", "pk:OpenAI main": "sk-test-keys-lead-NAMD" }, { bindings: st().bindings.map((b) => (b.role === "reasoning" && !b.ins ? { ...b, keyName: "pk:OpenAI main" } : b)) });
    let html = await page();
    assert.match(html, /These OpenAI keys differ\./);
    assert.match(html, /<strong>Value 1<\/strong> <span class="tb-tag needs-you">differs<\/span>: OPENAI_API_KEY/);
    assert.match(html, /<strong>Value 2<\/strong> <span class="tb-tag needs-you">differs<\/span>: older key &quot;OpenAI main&quot;/);
    noLeak(html);
    const rev = st().keyStore.keysRev;
    assert.equal(rev, st().keyStore.keysRev, "a view writes nothing");
    assert.equal((await post({ action: "prov_adopt", provider: "openai", from: "OPENAI_API_KEY" })).status, 303);
    assert.equal(values()["pk:@openai"], "sk-test-keys-lead-APP0");
    assert.equal(values()["pk:OpenAI main"], "sk-test-keys-lead-NAMD", "the other value is kept");
    assert.equal(st().bindings.find((b) => b.role === "reasoning" && !b.ins)?.keyName, "pk:OpenAI main", "its models are not switched silently");
    html = await page();
    assert.match(html, /Switch these models to the OpenAI key/);
    assert.equal((await post({ action: "pkey_switch", provider: "openai", label: "OpenAI main" })).status, 303);
    assert.equal(st().bindings.find((b) => b.role === "reasoning" && !b.ins)?.keyName, "pk:@openai");
  });

  test("PK-2 item 5b: a config that adds a linked name fills it without a keysRev bump", async () => {
    const rev = st().keyStore.keysRev;
    await w.amend((c) => {
      c.keyRequirements.push(req("OPENAI_KEY_TWO", HOOKINS, "guard", "OpenAI"));
    });
    await waitFor(() => w.bridge.ctx.table?.rev === w.rev(), 15000);
    assert.equal(values().OPENAI_KEY_TWO, values()["pk:@openai"], "mirrored for a rollback");
    assert.equal(st().keyStore.keysRev, rev, "the served value did not change");
  });

  test("PK-5: every value 0.2.16 serves, the 0.2.15 rules serve too; overrides[] survives a rewrite that does not know it", async () => {
    const t = w.bridge.ctx.table;
    for (const k of keyNames(t)) {
      const now16 = resolveAppKey(st(), t, k.name);
      if (now16 !== undefined) assert.equal(old015.key(values(), k.name), now16, k.name);
    }
    for (const b of st().bindings) {
      const name = bindingKeyName(b);
      if (name && Object.hasOwn(values(), name)) assert.equal(old015.bound(values(), b), values()[name], `${b.role} ${b.ins ?? "default"}`);
    }
    // a 0.2.15 key write: values mutated, the whole keyStore object written back
    st().commitKeys({}, { overrides: ["OPENAI_API_KEY"] });
    st().keyStore.values.OTHER_FROM_015 = "sk-test-keys-lead-015W";
    st().saveKeyStore();
    const reread = (st() as unknown as { readRecord: (n: string) => { overrides?: string[] } }).readRecord("keys");
    assert.deepEqual(reread.overrides, ["OPENAI_API_KEY"]);
  });
});
