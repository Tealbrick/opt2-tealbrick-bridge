/**
 * QA review of bridge#22 (coordination qa/VERDICTS.md QA-BRIDGE22-1..3):
 *  - S2 -1: owner-named provider keys live in their own S3 namespace. A provider key labelled like an app requirement
 *    (OPENAI_API_KEY) never answers `GET /tb/v1/keys/OPENAI_API_KEY`, and the page shows that app key "Not set". A store
 *    saved by the earlier 0.2.8 shape (label bare in `values`) is migrated on load and still serves its role binding.
 *  - S3 -2: a malformed percent escape in the role or key path is 400, not 500.
 *  - S3 -3: a provider change clears the zdr attestation (R18).
 */
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import type { ModelRoleRequirementEntry } from "@opt2-tealbrick/spec/bridge";
import type { Ed25519KeyPair } from "@opt2-tealbrick/spec/sdk";
import { buildStatusReport } from "../src/portal.ts";
import { BRG, INS, makeWorld, type World, WS, waitFor } from "./support/world.ts";

const now = () => Math.floor(Date.now() / 1000);
const FORM = { "content-type": "application/x-www-form-urlencoded" };
const ROLE = { role: "reasoning", ins: INS, product: "notes", required: true, minPolicy: "standard", usedBy: ["app"] } as ModelRoleRequirementEntry;
const ROLE_ZDR = { role: "summarize", ins: INS, product: "notes", required: false, minPolicy: "standard", usedBy: ["app"] } as ModelRoleRequirementEntry;
const appKeyReq = (name: string) => ({ name, label: `App ${name}`, ins: INS, product: "notes", required: true, source: "account_default", usedBy: ["app"] }) as never;

describe("QA-BRIDGE22: provider keys in their own namespace, percent errors, zdr attestation", () => {
  let w: World;
  let appKey: Ed25519KeyPair;
  let cookie = "";
  let csrf = "";
  const store = () => w.bridge.ctx.state.keyStore;
  const open = async () => {
    const ticket = await w.signPortal("tb-ticket+jwt", { iss: "tb:portal", sub: "tb:per:per_01HPPPPPPPPPPPPPPPPPPPPPPP", aud: `tb:brg:${BRG}`, iat: now(), exp: now() + 120, jti: w.api.ulid(), ws: WS, pur: "keys" });
    const r = await fetch(`${w.keysUrl}/keys`, { method: "POST", headers: FORM, body: new URLSearchParams({ ticket }), redirect: "manual" });
    assert.equal(r.status, 200);
    cookie = String(r.headers.get("set-cookie")).split(";")[0] as string;
    const html = await r.text();
    csrf = /name="csrf" value="([^"]+)"/.exec(html)?.[1] as string;
    return html;
  };
  const post = (fields: Record<string, string>) => fetch(`${w.keysUrl}/keys`, { method: "POST", headers: { ...FORM, cookie }, body: new URLSearchParams({ csrf, ...fields }), redirect: "manual" });
  const internal = async (path: string) => {
    const assertion = await w.api.signAssertion("tb-instance-assert+jwt", { iss: `tb:ins:${INS}`, sub: `tb:ins:${INS}`, aud: `tb:brg:${BRG}`, iat: now(), exp: now() + 60, jti: w.api.ulid() }, appKey, { method: "GET", pathAndQuery: path });
    const r = await fetch(`${w.internalUrl}${path}`, { headers: { "TB-Assert": assertion } });
    return { status: r.status, json: JSON.parse((await r.text()) || "null") };
  };
  /** the app key's section of the page: its tag */
  const appKeyTag = (html: string, name: string) => new RegExp(`<h2 id="k-${name}">[\\s\\S]*?</h2><span class="tb-tag [a-z-]+"><span class="tb-ink">([^<]+)</span>`).exec(html)?.[1];

  before(async () => {
    w = await makeWorld({ real: true });
    appKey = await w.api.generateKeyPair();
    await w.amend((c) => {
      c.instanceKeys.push({ ins: INS, jwk: appKey.publicJwk } as never);
      c.modelRoleRequirements = [ROLE, ROLE_ZDR];
    });
    await waitFor(() => w.bridge.ctx.table?.rev === w.rev(), 15000);
  });
  after(async () => {
    await w.close();
  });

  test("S2 -1: a provider key labelled OPENAI_API_KEY never answers a later app requirement OPENAI_API_KEY", async () => {
    await open();
    assert.equal((await post({ action: "pkey", label: "OPENAI_API_KEY", value: "sk-provider-qa22" })).status, 303);
    assert.equal(store().values["pk:OPENAI_API_KEY"], "sk-provider-qa22");
    assert.ok(!Object.hasOwn(store().values, "OPENAI_API_KEY"));
    assert.equal((await post({ action: "bind", role: "reasoning", provider: "openai", model: "gpt-qa", keyName: "pk:OPENAI_API_KEY" })).status, 303);
    // a later config: an app now declares the same name as an account_default key
    await w.amend((c) => {
      c.keyRequirements.push(appKeyReq("OPENAI_API_KEY"));
    });
    await waitFor(() => w.bridge.ctx.table?.rev === w.rev(), 15000);
    const k = await internal("/tb/v1/keys/OPENAI_API_KEY");
    assert.equal(k.status, 404);
    assert.equal(k.json.error.code, "key_not_set");
    const html = await open();
    assert.equal(appKeyTag(html, "OPENAI_API_KEY"), "Not set", "the app key is not set");
    assert.equal(buildStatusReport(w.bridge.ctx).keys.find((k) => k.name === "OPENAI_API_KEY")?.set, false, "StatusReport.keys[] says not set (RM-25)");
    assert.match(html, /<h3 id="pk-0">OPENAI_API_KEY<\/h3>/, "the provider key shows in its own section");
    // the role still gets the provider key it is bound to
    assert.equal((await internal("/tb/v1/model-roles/reasoning")).json.key, "sk-provider-qa22");
    // an app key entered under that name is a different key; each answers only its own path
    assert.equal((await post({ name: "OPENAI_API_KEY", value: "sk-app-qa22" })).status, 303);
    assert.equal((await internal("/tb/v1/keys/OPENAI_API_KEY")).json.value, "sk-app-qa22");
    assert.equal((await internal("/tb/v1/model-roles/reasoning")).json.key, "sk-provider-qa22");
    const missing = await internal(`/tb/v1/keys/${encodeURIComponent("pk:OPENAI_API_KEY")}`);
    assert.equal(missing.status, 403, "a provider key name is never a requirement");
    assert.equal(missing.json.error.code, "key_not_declared");
  });

  test("S2 -1: a store of the earlier 0.2.8 shape migrates on load; the binding still resolves, the app key is not set", async () => {
    const st = w.bridge.ctx.state;
    // what an earlier 0.2.8 bridge wrote: the provider label bare in `values`, listed in `providerKeys`, named by the binding
    st.keyStore = { keysRev: st.keyStore.keysRev, values: { ...st.keyStore.values, MISTRAL_API_KEY: "sk-legacy-qa22" }, providerKeys: ["MISTRAL_API_KEY"] };
    st.saveBindings([...st.bindings.filter((b) => b.role !== "reasoning"), { role: "reasoning", provider: "mistral", model: "mistral-qa", keyName: "MISTRAL_API_KEY", dataPolicy: "standard" }]);
    assert.deepEqual(st.keyStore.providerKeys, ["MISTRAL_API_KEY"], "written in the old shape");
    await w.amend((c) => {
      c.keyRequirements.push(appKeyReq("MISTRAL_API_KEY"));
    });
    await w.restart();
    await waitFor(() => w.bridge.ctx.table?.rev === w.rev(), 15000);
    const migrated = w.bridge.ctx.state;
    assert.equal(migrated.keyStore.providerKeys, undefined, "the old list is gone");
    assert.equal(migrated.keyStore.values["pk:MISTRAL_API_KEY"], "sk-legacy-qa22");
    assert.ok(!Object.hasOwn(migrated.keyStore.values, "MISTRAL_API_KEY"));
    assert.equal(migrated.bindings.find((b) => b.role === "reasoning")?.keyName, "pk:MISTRAL_API_KEY");
    assert.equal(migrated.keyStore.values["pk:OPENAI_API_KEY"], "sk-provider-qa22", "keys already in the new shape are untouched");
    const r = await internal("/tb/v1/model-roles/reasoning");
    assert.equal(r.status, 200);
    assert.equal(r.json.key, "sk-legacy-qa22", "the migrated key still serves its role binding");
    const k = await internal("/tb/v1/keys/MISTRAL_API_KEY");
    assert.equal(k.status, 404);
    assert.equal(k.json.error.code, "key_not_set");
    assert.equal(appKeyTag(await open(), "MISTRAL_API_KEY"), "Not set");
  });

  test("S3 -2 / RM-25: authenticated first (401), then a malformed percent escape in the role or key path is 400 bad_request, never 500", async () => {
    for (const path of ["/tb/v1/model-roles/%", "/tb/v1/model-roles/%FF", "/tb/v1/model-roles/%E0%A4%A", "/tb/v1/keys/%", "/tb/v1/keys/%FF", "/tb/v1/keys/%E0%A4%A"]) {
      const r = await internal(path);
      assert.equal(r.status, 400, path);
      assert.equal(r.json.error.code, "bad_request", path);
    }
    // order (specs#55): authentication first — a bad or missing TB-Assert with a bad percent is 401, not 400
    for (const path of ["/tb/v1/model-roles/%E0%A4%A", "/tb/v1/keys/%FF"]) {
      assert.equal((await fetch(`${w.internalUrl}${path}`)).status, 401, `${path} without TB-Assert`);
      assert.equal((await fetch(`${w.internalUrl}${path}`, { headers: { "TB-Assert": "x.y.z" } })).status, 401, `${path} with a bad TB-Assert`);
    }
    assert.equal((await internal("/tb/v1/model-roles/reasoning")).status, 200, "the bridge is fine afterwards");
  });

  test("S3 -3 (R18): a provider change clears the zdr attestation; without a new tick the save is refused", async () => {
    await open();
    assert.equal((await post({ action: "bind", role: "summarize", provider: "openai", model: "gpt-zdr", keyName: "pk:OPENAI_API_KEY", dataPolicy: "zdr", zdr: "1" })).status, 303);
    const before = w.bridge.ctx.state.bindings.find((b) => b.role === "summarize");
    assert.ok(before?.zdrAttestedAt);
    // same provider and URL: the attestation is kept without a new tick
    assert.equal((await post({ action: "bind", role: "summarize", provider: "openai", model: "gpt-zdr", keyName: "pk:OPENAI_API_KEY", dataPolicy: "zdr" })).status, 303);
    assert.equal(w.bridge.ctx.state.bindings.find((b) => b.role === "summarize")?.zdrAttestedAt, before.zdrAttestedAt);
    // another provider (both on their default URL, neither a gateway): the old attestation does not carry over
    const other = await post({ action: "bind", role: "summarize", provider: "anthropic", model: "claude-zdr", keyName: "pk:OPENAI_API_KEY", dataPolicy: "zdr" });
    assert.equal(other.status, 400);
    assert.match(await other.text(), /I confirm a zero-data-retention contract with this provider/);
    assert.equal(w.bridge.ctx.state.bindings.find((b) => b.role === "summarize")?.provider, "openai", "nothing stored");
    assert.equal((await post({ action: "bind", role: "summarize", provider: "anthropic", model: "claude-zdr", keyName: "pk:OPENAI_API_KEY", dataPolicy: "zdr", zdr: "1" })).status, 303);
    const after = w.bridge.ctx.state.bindings.find((b) => b.role === "summarize");
    assert.equal(after?.provider, "anthropic");
    assert.ok(after?.zdrAttestedAt && after.zdrAttestedAt >= before.zdrAttestedAt);
  });
});
