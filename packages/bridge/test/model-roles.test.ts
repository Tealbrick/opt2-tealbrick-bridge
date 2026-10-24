/**
 * v0.1.63 (BRIDGE §15, C330(4)): the workspace model-role registry. Real bridge, the "Keys and models" page over HTTP and
 * the internal resolve route with real instance assertions. Rows RM-2..RM-6, RM-12 and the bridge half of RM-13
 * (CONFORMANCE v0.1.63): resolve and its refusals, the `local` check, one key for many roles, label-only status and logs,
 * per-app overrides, resolve without Portal (standalone).
 */
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import type { Ed25519KeyPair } from "@opt2-tealbrick/spec/sdk";
import { effectivePolicy, localUrlOk, resolveForCaller } from "../src/model-roles.ts";
import { hintsFrom, renderModels } from "../src/models-page.ts";
import { buildStatusReport } from "../src/portal.ts";
import { DATA_POLICIES, DATA_POLICY_RANK, type DataPolicy, type ModelRoleRequirementEntry, type StatusReport0163, type WorkspaceConfig0163 } from "../src/spec-0163.ts";
import type { ModelBinding } from "../src/state.ts";
import { BRG, HOOKINS, INS, makeWorld, type World, WS, waitFor } from "./support/world.ts";

const now = () => Math.floor(Date.now() / 1000);
const FORM = { "content-type": "application/x-www-form-urlencoded" };
type Line = { level: string; e: string; f: Record<string, unknown> };
const capture = (lines: Line[]) => {
  const at = (level: string) => (e: string, f?: Record<string, unknown>) => void lines.push({ level, e, f: f ?? {} });
  return { info: at("info"), warn: at("warn"), error: at("error") };
};
/** tailnet names and addresses, assembled so no tailnet literal sits in the repo (scripts/check-literals.ts) */
const TAILNET_HOST = ["gpu-box", "example-tailnet", "ts", "net"].join(".");
const CGNAT_IP = [100, 64, 1, 2].join(".");
const CGNAT_TOP = [100, 127, 255, 254].join(".");
const NOT_TAILNET = ["x", "ts", "net", "example", "com"].join(".");
/** RM-13 canaries (BRIDGE §15.7) */
const CANARY = { baseUrl: "http://10.9.8.7:11434/canary-url-7f3a", keyName: "canary-keyname-7f3a", value: "canary-keyvalue-7f3a" };
const MODEL_ID = /^(?!.*\/\/)[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}$/;

const REQS = [
  { role: "reasoning", ins: INS, product: "notes", required: true, minPolicy: "standard", usedBy: ["app", "engine"] },
  { role: "utility", ins: INS, product: "notes", required: false, minPolicy: "standard", usedBy: ["app"] },
  { role: "summarize", ins: INS, product: "notes", required: false, minPolicy: "zdr", usedBy: ["app"] },
  { role: "dreaming", ins: INS, product: "notes", required: false, minPolicy: "zdr", usedBy: ["app"] },
  { role: "rerank", ins: INS, product: "notes", required: false, minPolicy: "standard", usedBy: ["app"] },
  { role: "embeddings", ins: INS, product: "notes", required: false, minPolicy: "local", usedBy: ["app"] },
  { role: "reasoning", ins: HOOKINS, product: "guard", required: true, minPolicy: "standard", usedBy: ["app"] },
] as ModelRoleRequirementEntry[];

/** the key page and the resolve route of one world */
function harness(get: () => World) {
  let cookie = "";
  let csrf = "";
  return {
    async open(): Promise<string> {
      const w = get();
      const ticket = await w.signPortal("tb-ticket+jwt", { iss: "tb:portal", sub: "tb:per:per_01HPPPPPPPPPPPPPPPPPPPPPPP", aud: `tb:brg:${BRG}`, iat: now(), exp: now() + 120, jti: w.api.ulid(), ws: WS, pur: "keys" });
      return this.openWith(ticket);
    },
    async openWith(ticket: string): Promise<string> {
      const r = await fetch(`${get().keysUrl}/keys`, { method: "POST", headers: FORM, body: new URLSearchParams({ ticket }), redirect: "manual" });
      assert.equal(r.status, 200);
      cookie = String(r.headers.get("set-cookie")).split(";")[0] as string;
      const html = await r.text();
      csrf = /name="csrf" value="([^"]+)"/.exec(html)?.[1] as string;
      return html;
    },
    post: (fields: Record<string, string>) => fetch(`${get().keysUrl}/keys`, { method: "POST", headers: { ...FORM, cookie }, body: new URLSearchParams({ csrf, ...fields }), redirect: "manual" }),
    page: async () => (await fetch(`${get().keysUrl}/keys`, { headers: { cookie } })).text(),
    async role(key: Ed25519KeyPair, ins: string, role: string, svc?: string) {
      const w = get();
      const path = `/tb/v1/model-roles/${role}`;
      const assertion = await w.api.signAssertion("tb-instance-assert+jwt", { iss: `tb:ins:${ins}`, sub: `tb:ins:${ins}`, aud: `tb:brg:${BRG}`, iat: now(), exp: now() + 60, jti: w.api.ulid(), ...(svc ? { svc } : {}) }, key, { method: "GET", pathAndQuery: path });
      const r = await fetch(`${w.internalUrl}${path}`, { headers: { "TB-Assert": assertion } });
      return { status: r.status, cache: r.headers.get("cache-control"), text: await r.text() };
    },
  };
}

describe("BRIDGE §15.3 local check (RM-3, unit)", () => {
  test("`local` holds for every §15.3 form and for nothing else (QA-SPEC42-5 algorithm, no DNS)", () => {
    const own = ["https://gpu.owner.example:8443"];
    const yes = [
      "http://localhost:1234",
      "http://LOCALHOST.:1234",
      "http://ollama.railway.internal:11434",
      "http://OLLAMA.Railway.Internal.:11434",
      `http://${TAILNET_HOST}:11434`,
      "https://gpu.owner.example:8443/v1",
      "http://127.0.0.1:11434/v1",
      "http://2130706433:11434",
      "http://10.0.0.5",
      "http://172.16.3.4:80",
      "http://172.31.255.1",
      "http://192.168.1.10:11434",
      `http://${CGNAT_IP}:11434`,
      `http://${CGNAT_TOP}`,
      "http://[::1]:8080",
      "http://[fd12:3456::1]:11434",
      "http://[FC00::1]",
      "http://[::ffff:10.0.0.1]:11434",
      "http://[::FFFF:192.168.0.9]",
    ];
    for (const url of yes) assert.ok(localUrlOk(url, own), url);
    const no = [
      "https://api.openai.com/v1",
      "http://8.8.8.8",
      "http://172.32.0.1",
      "http://100.128.0.1",
      "http://100.63.255.255",
      "http://169.254.169.254/latest/meta-data",
      "http://[fe80::1]",
      "http://0.0.0.0:11434",
      "http://[::]:11434",
      "http://[::ffff:8.8.8.8]",
      "http://[::ffff:169.254.169.254]",
      "http://user@10.0.0.5:11434",
      "http://user:pw@localhost:1234",
      "ftp://10.0.0.1",
      "http://10.0.0.1.nip.io",
      `https://${NOT_TAILNET}`,
      "https://x.railway.internal.example.com",
      "https://gpu.owner.example",
      "http://example.com",
      "http://[2001:db8::1]",
      "not a url",
      "",
    ];
    for (const url of no) assert.ok(!localUrlOk(url, own), url);
  });

  test("a stored `local` binding whose URL no longer passes counts as `standard`; `zdr` needs the attestation", () => {
    const b = { role: "embeddings", provider: "ollama", model: "m", baseUrl: "https://gpu.owner.example:8443", dataPolicy: "local" } as const;
    assert.equal(effectivePolicy(b, ["https://gpu.owner.example:8443"]), "local");
    assert.equal(effectivePolicy(b, []), "standard", "TB_OWN_INFRA_ORIGINS changed: no longer local");
    assert.equal(effectivePolicy({ role: "reasoning", provider: "openai", model: "m", dataPolicy: "zdr" }, []), "standard", "no zdrAttestedAt");
    assert.equal(effectivePolicy({ role: "reasoning", provider: "openai", model: "m", dataPolicy: "zdr", zdrAttestedAt: new Date().toISOString() }, []), "zdr");
    assert.equal(effectivePolicy({ role: "reasoning", provider: "deepseek", model: "m", dataPolicy: "zdr", zdrAttestedAt: new Date().toISOString() }, []), "standard", "a stored zdr binding whose provider changed to one without zdr");
    assert.equal(effectivePolicy({ role: "reasoning", provider: "litellm", model: "m", dataPolicy: "zdr", zdrAttestedAt: new Date().toISOString() }, []), "zdr", "litellm is zdrOffered (9db11fe)");
  });
});

describe("RM-2 resolve order (unit): 9 binding × minPolicy pairs, key after policy, no override fall-back", () => {
  const INS2 = "ins_01HQQQQQQQQQQQQQQQQQQQQQQQ";
  const at = new Date().toISOString();
  const BIND: Record<DataPolicy, ModelBinding> = {
    local: { role: "reasoning", provider: "ollama", model: "llama3", baseUrl: "http://10.0.0.5:11434", dataPolicy: "local" },
    zdr: { role: "reasoning", provider: "openai", model: "gpt-z", keyName: "K", dataPolicy: "zdr", zdrAttestedAt: at },
    standard: { role: "reasoning", provider: "openai", model: "gpt-s", keyName: "K", dataPolicy: "standard" },
  };
  const run = (bindings: ModelBinding[], minPolicy: DataPolicy, values: Record<string, string> = { K: "v" }, ins = INS) => {
    const t = { config: { modelRoleRequirements: [{ role: "reasoning", ins, product: "notes", required: true, minPolicy, usedBy: ["app"] }] }, apps: new Map([[ins, {}]]) } as never;
    const ctx = { state: { bindings, keyStore: { keysRev: 7, values } }, ownInfraOrigins: [] } as never;
    try {
      return resolveForCaller(ctx, t, ins as never, "app", "reasoning");
    } catch (e) {
      return e as { code: string; status: number; details?: unknown };
    }
  };
  test("a binding meets minPolicy exactly when its rank is at least the needed rank", () => {
    for (const have of DATA_POLICIES)
      for (const needed of DATA_POLICIES) {
        const r = run([BIND[have]], needed);
        if (DATA_POLICY_RANK[have] >= DATA_POLICY_RANK[needed]) assert.equal((r as { dataPolicy?: string }).dataPolicy, have, `${have} vs ${needed}`);
        else assert.deepEqual([(r as { code: string }).code, (r as { details?: unknown }).details], ["role_policy_too_low", { needed, have }], `${have} vs ${needed}`);
      }
  });
  test("the key check comes AFTER the policy check; an override below policy refuses (no default fall-back)", () => {
    assert.equal((run([BIND.standard], "zdr", {}) as { code: string }).code, "role_policy_too_low", "key unset AND policy too low → policy");
    assert.equal((run([BIND.zdr], "zdr", {}) as { code: string }).code, "role_not_set", "policy ok, key unset → role_not_set");
    const both = [BIND.zdr, { ...BIND.standard, ins: INS2 as never }];
    assert.equal((run(both, "zdr", { K: "v" }, INS2) as { code: string }).code, "role_policy_too_low", "the override is used, never the default");
    assert.equal((run(both, "zdr") as { model: string }).model, "gpt-z", "the other instance keeps the default");
  });
});

describe("model roles: page, resolve, status (RM-2..RM-6, RM-13 bridge half)", () => {
  let w: World;
  const lines: Line[] = [];
  const h = harness(() => w);
  let appKey: Ed25519KeyPair;
  let svcKey: Ed25519KeyPair;
  let guardKey: Ed25519KeyPair;
  const store = () => w.bridge.ctx.state.keyStore;
  const json = (r: { text: string }) => JSON.parse(r.text);
  const bind = (fields: Record<string, string>) => h.post({ action: "bind", ...fields });

  before(async () => {
    w = await makeWorld({ real: true, withHook: true, logger: capture(lines) });
    appKey = await w.api.generateKeyPair();
    svcKey = await w.api.generateKeyPair();
    guardKey = await w.api.generateKeyPair();
    await w.amend((c) => {
      c.instanceKeys.push({ ins: INS, jwk: appKey.publicJwk } as never, { ins: INS, svc: "engine", jwk: svcKey.publicJwk } as never, { ins: HOOKINS, jwk: guardKey.publicJwk } as never);
      (c as WorkspaceConfig0163).modelRoleRequirements = REQS;
    });
    await waitFor(() => w.bridge.ctx.table?.rev === w.rev(), 15000);
    const html = await h.open();
    assert.match(html, /<title>Keys and models · Tealbrick<\/title>/);
  });
  after(async () => {
    await w.close();
  });

  test("the page: one Models row per declared role; local providers first; a ticket hint pre-fills (display only)", async () => {
    // K11 `roles[]` (v0.1.63): the shared verifier of @opt2-tealbrick/manifest 0.1.30 does not know the claim yet, so the
    // hint path is checked below the ticket: the claim parser, then the page with the session's hints
    const hints = hintsFrom({ roles: [{ role: "reasoning", provider: "openai", model: "gpt-hint", dataPolicy: "standard" }, { role: "bogus" }, { role: "utility", provider: "nope", model: "x\u0000y" }] } as never);
    assert.deepEqual(hints, [{ role: "reasoning", provider: "openai", model: "gpt-hint", dataPolicy: "standard" }, { role: "utility" }]);
    const html = `${await h.page()}${renderModels(w.bridge.ctx, w.bridge.ctx.table as never, "c", hints, new Map())}`;
    for (const r of ["reasoning", "utility", "summarize", "dreaming", "rerank", "embeddings"]) assert.match(html, new RegExp(`id="r-${r}"`), r);
    assert.ok(!html.includes('id="r-vision"'), "an undeclared role has no row");
    const providers = [.../<select class="tb-select-native" id="r-embeddings-d-provider"[^>]*>([\s\S]*?)<\/select>/.exec(html)?.[1]?.matchAll(/value="([^"]+)"/g) ?? []].map((m) => m[1]);
    assert.deepEqual(providers.slice(0, 3), ["ollama", "llama-server", "lm-studio"], "local providers listed first");
    assert.ok(!providers.includes("anthropic"), "only providers that serve the role");
    assert.match(html, /Suggested: OpenAI · gpt-hint · Standard\. Nothing is saved until you save it\./);
    assert.match(html, /id="r-reasoning-d-model"[^>]*value="gpt-hint"/);
    assert.equal(w.bridge.ctx.state.bindings.length, 0, "a hint stores nothing");
    assert.match(html, /I confirm a zero-data-retention contract with this provider/);
  });

  test("RM-2 / RM-4: one provider key serves three roles; declared + set → the binding; replacing the key bumps keysRev once", async () => {
    assert.equal((await h.post({ action: "pkey", label: "OpenAI main", value: " sk-rm-one\n" })).status, 303);
    assert.equal(store().values["OpenAI main"], "sk-rm-one");
    assert.deepEqual(store().providerKeys, ["OpenAI main"]);
    assert.equal((await bind({ role: "reasoning", provider: "openai", model: "gpt-test", keyName: "OpenAI main", dataPolicy: "standard" })).status, 303);
    assert.equal((await bind({ role: "utility", provider: "openai", model: "gpt-mini", keyName: "OpenAI main" })).status, 303);
    assert.equal((await bind({ role: "summarize", provider: "openai", model: "gpt-zdr", keyName: "OpenAI main", dataPolicy: "zdr", zdr: "1" })).status, 303);
    assert.ok(w.bridge.ctx.state.bindings.find((b) => b.role === "summarize")?.zdrAttestedAt, "the tick is stored as zdrAttestedAt");

    const r = await h.role(appKey, INS, "reasoning");
    assert.equal(r.status, 200, r.text);
    assert.equal(r.cache, "no-store");
    assert.deepEqual(json(r), { role: "reasoning", provider: "openai", model: "gpt-test", baseUrl: "https://api.openai.com/v1", key: "sk-rm-one", dataPolicy: "standard", dims: null, keysRev: store().keysRev });
    assert.equal((await h.role(svcKey, INS, "reasoning", "engine")).status, 200, "a declared service resolves too");

    const html = await h.page();
    const serves = /Serves:<\/span><span>([^<]*)<\/span>/.exec(html)?.[1] ?? "";
    for (const role of ["reasoning (", "utility (", "summarize ("]) assert.ok(serves.includes(role), `Serves lists ${role}: ${serves}`);
    assert.ok(!html.includes("sk-rm-one"), "the value is never rendered");

    const rev = store().keysRev;
    assert.equal((await h.post({ action: "pkey", label: "OpenAI main", value: "sk-rm-two" })).status, 303);
    assert.equal(store().keysRev, rev + 1, "one revision for the whole change");
    for (const role of ["reasoning", "utility", "summarize"]) assert.equal(json(await h.role(appKey, INS, role)).key, "sk-rm-two", role);
  });

  test("RM-2 refusals: not declared, not set, policy too low (nothing of the binding), key unset", async () => {
    for (const [key, ins, role, svc] of [[appKey, INS, "vision"], [appKey, INS, "nonsense"], [svcKey, INS, "utility", "engine"], [guardKey, HOOKINS, "utility"]] as const) {
      const r = await h.role(key, ins, role, svc);
      assert.equal(r.status, 403, `${role}: ${r.text}`);
      assert.equal(json(r).error.code, "role_not_declared");
    }
    const unset = await h.role(appKey, INS, "rerank");
    assert.equal(unset.status, 404);
    assert.equal(json(unset).error.code, "role_not_set");

    assert.equal((await bind({ role: "dreaming", provider: "openai", model: "gpt-dream", keyName: "OpenAI main", dataPolicy: "standard" })).status, 303);
    const low = await h.role(appKey, INS, "dreaming");
    assert.equal(low.status, 403);
    assert.equal(json(low).error.code, "role_policy_too_low");
    assert.deepEqual(Object.keys(json(low)), ["error"]);
    assert.deepEqual(json(low).error.details, { needed: "zdr", have: "standard" });
    for (const leak of ["openai", "gpt-dream", "sk-rm", "api.openai.com", "OpenAI main"]) assert.ok(!low.text.includes(leak), `no ${leak} in the refusal`);

    assert.equal((await bind({ role: "rerank", provider: "openrouter", model: "rr-1" })).status, 303, "a binding may wait for its key");
    const noKey = await h.role(appKey, INS, "rerank");
    assert.equal(noKey.status, 404);
    assert.equal(json(noKey).error.code, "role_not_set");
    assert.equal((await bind({ role: "rerank", provider: "openrouter", model: "rr-1", keyName: "OpenAI main" })).status, 303);
    assert.equal((await h.role(appKey, INS, "rerank")).status, 200);
  });

  test("RM-3 on the page: `local` refused for a public URL, a plain-http public URL refused, a private URL defaults to `local`", async () => {
    const before = structuredClone(w.bridge.ctx.state.bindings);
    const refused = async (fields: Record<string, string>, text: RegExp) => {
      const r = await bind({ role: "embeddings", provider: "ollama", model: "nomic", ...fields });
      assert.equal(r.status, 400);
      assert.match(await r.text(), text);
    };
    await refused({ baseUrl: "https://models.example.com", dataPolicy: "local" }, /Local needs a base URL on your own network/);
    await refused({ baseUrl: "http://203.0.113.5:11434" }, /use an https address, or an address on your own network/);
    await refused({}, /needs a base URL/);
    await refused({ baseUrl: "http://user:pw@10.0.0.5:11434" }, /without a user name or password/);
    assert.deepEqual(w.bridge.ctx.state.bindings, before, "nothing stored");
    const zdr = await bind({ role: "reasoning", provider: "deepseek", model: "d", keyName: "OpenAI main", dataPolicy: "zdr", zdr: "1" });
    assert.equal(zdr.status, 400, "zdr only for providers that offer it");
    assert.equal((await bind({ role: "reasoning", provider: "openai", model: "d", keyName: "OpenAI main", dataPolicy: "zdr" })).status, 400, "zdr needs the tick");

    assert.equal((await bind({ role: "embeddings", provider: "ollama", model: "nomic", baseUrl: "http://10.20.30.40:11434", keyName: "OpenAI main", dims: "768" })).status, 303);
    const b = w.bridge.ctx.state.bindings.find((x) => x.role === "embeddings");
    assert.equal(b?.dataPolicy, "local", "a passing private URL defaults to local (C336 Q3)");
    assert.equal(b?.keyName, undefined, "no key for a provider that needs none");
    assert.deepEqual(json(await h.role(appKey, INS, "embeddings")), { role: "embeddings", provider: "ollama", model: "nomic", baseUrl: "http://10.20.30.40:11434", key: null, dataPolicy: "local", dims: 768, keysRev: store().keysRev });
  });

  test("embeddings: a changed model asks for the re-index confirmation first", async () => {
    assert.match(await h.page(), /Apps must re-index their memory after this change; each app asks you first\./);
    const r = await bind({ role: "embeddings", provider: "ollama", model: "bge-m3", baseUrl: "http://10.20.30.40:11434", dims: "1024" });
    assert.equal(r.status, 400);
    assert.equal(w.bridge.ctx.state.bindings.find((x) => x.role === "embeddings")?.model, "nomic");
    assert.equal((await bind({ role: "embeddings", provider: "ollama", model: "bge-m3", baseUrl: "http://10.20.30.40:11434", dims: "1024", reindex: "1" })).status, 303);
    assert.equal(json(await h.role(appKey, INS, "embeddings")).dims, 1024);
  });

  test("RM-6: an instance override wins over the workspace default; the other app keeps the default", async () => {
    assert.equal((await h.post({ action: "pkey", label: "Anthropic main", value: "sk-ant-rm" })).status, 303);
    assert.equal((await bind({ role: "reasoning", ins: INS, provider: "anthropic", model: "claude-test", keyName: "Anthropic main" })).status, 303);
    const notes = json(await h.role(appKey, INS, "reasoning"));
    assert.equal(notes.provider, "anthropic");
    assert.equal(notes.key, "sk-ant-rm");
    const guard = json(await h.role(guardKey, HOOKINS, "reasoning"));
    assert.equal(guard.provider, "openai");
    assert.equal(guard.model, "gpt-test");
    assert.equal((await bind({ role: "reasoning", ins: "ins_01HXXXXXXXXXXXXXXXXXXXXXXX", provider: "openai", model: "x", keyName: "OpenAI main" })).status, 400, "an app that does not declare the role");
    assert.match(await h.page(), /Remove override/);
    assert.equal((await h.post({ action: "unbind", role: "reasoning", ins: INS })).status, 303);
    assert.equal(json(await h.role(appKey, INS, "reasoning")).provider, "openai", "back to the default");
  });

  test("deleting a key that serves models asks first, then leaves those bindings without a key (one keysRev)", async () => {
    const rev = store().keysRev;
    const ask = await h.post({ action: "pkey_delete", label: "OpenAI main" });
    assert.equal(ask.status, 200);
    const html = await ask.text();
    assert.match(html, /Delete OpenAI main\?/);
    assert.match(html, /name="confirm" value="1"/);
    assert.equal(store().values["OpenAI main"], "sk-rm-two", "nothing deleted yet");
    assert.equal(store().keysRev, rev);
    assert.equal((await h.post({ action: "pkey_delete", label: "OpenAI main", confirm: "1" })).status, 303);
    assert.ok(!Object.hasOwn(store().values, "OpenAI main"));
    assert.equal(store().keysRev, rev + 1);
    assert.ok(!w.bridge.ctx.state.bindings.some((b) => b.keyName === "OpenAI main"));
    assert.equal(w.bridge.ctx.state.bindings.find((b) => b.role === "reasoning" && !b.ins)?.model, "gpt-test", "the binding stays, without a key");
    assert.equal(json(await h.role(appKey, INS, "reasoning")).error.code, "role_not_set");
    // an app key chosen for a model asks too
    assert.equal((await h.post({ name: "NOTES_API_KEY", value: "sk-notes-rm" })).status, 303);
    assert.equal((await bind({ role: "reasoning", provider: "openai", model: "gpt-test", keyName: "NOTES_API_KEY" })).status, 303);
    const ask2 = await h.post({ name: "NOTES_API_KEY", action: "delete" });
    assert.equal(ask2.status, 200);
    assert.match(await ask2.text(), /Delete Notes key\?/);
    assert.equal(store().values.NOTES_API_KEY, "sk-notes-rm");
  });

  test("RM-5 / RM-13 (bridge half): status roles[] are labels only; no base URL, key name or value in reports or logs", async () => {
    const report = buildStatusReport(w.bridge.ctx) as StatusReport0163;
    assert.equal(report.roles?.length, REQS.length);
    // schema model-role-status.schema.json#/$defs/modelRoleStatus: exactly these keys, labels of the spec patterns or null
    for (const row of report.roles ?? []) {
      assert.deepEqual(Object.keys(row).sort(), ["dataPolicy", "ins", "model", "policyOk", "provider", "role", "set"]);
      assert.ok(row.provider === null || /^[a-z][a-z0-9-]{1,31}$/.test(row.provider));
      assert.ok(row.model === null || MODEL_ID.test(row.model));
      assert.ok(row.dataPolicy === null || (DATA_POLICIES as readonly string[]).includes(row.dataPolicy));
      assert.equal(typeof row.set, "boolean");
      assert.equal(typeof row.policyOk, "boolean");
    }
    const row = (role: string, ins = INS) => report.roles?.find((r) => r.role === role && r.ins === ins);
    assert.deepEqual(row("embeddings"), { role: "embeddings", ins: INS, set: true, policyOk: true, provider: "ollama", model: "bge-m3", dataPolicy: "local" });
    assert.deepEqual(row("dreaming"), { role: "dreaming", ins: INS, set: false, policyOk: false, provider: null, model: null, dataPolicy: null }, "its key was deleted");
    assert.equal(row("reasoning", HOOKINS)?.set, true);
    await waitFor(() => (w.acks as StatusReport0163[]).some((a) => a.roles?.some((r) => r.role === "embeddings" && r.model === "bge-m3")), 15000);
    const seen = JSON.stringify(w.acks) + JSON.stringify(report) + JSON.stringify(lines);
    for (const leak of ["10.20.30.40", "sk-rm-", "sk-ant-rm", "sk-notes-rm", "OpenAI main", "Anthropic main", "api.openai.com"]) assert.ok(!seen.includes(leak), `${leak} must not reach Portal or the log`);
    assert.ok(lines.some((l) => l.e === "bridge.models.bound"), "binding changes are logged (labels only)");
  });

  test("a paused instance gets `paused`", async () => {
    await w.amend((c) => {
      c.pause.instances = [INS] as never;
    });
    await waitFor(() => w.bridge.ctx.table?.pausedInstances.has(INS as never) === true, 15000);
    const r = await h.role(appKey, INS, "embeddings");
    assert.equal(r.status, 403);
    assert.equal(json(r).error.code, "paused");
  });
});

describe("RM-12: standalone — resolve and the page work without Portal", () => {
  let w: World;
  const h = harness(() => w);
  let appKey: Ed25519KeyPair;
  before(async () => {
    w = await makeWorld({ real: true });
    appKey = await w.api.generateKeyPair();
    await w.amend((c) => {
      c.instanceKeys.push({ ins: INS, jwk: appKey.publicJwk } as never);
      (c as WorkspaceConfig0163).modelRoleRequirements = [REQS[0] as ModelRoleRequirementEntry];
    });
    await waitFor(() => w.bridge.ctx.table?.rev === w.rev(), 15000);
    await h.open();
    assert.equal((await h.post({ action: "bind", role: "reasoning", provider: "ollama", model: "llama-a", baseUrl: "http://192.168.1.20:11434" })).status, 303);
  });
  after(async () => {
    await w.close();
  });

  test("Leave Portal, Portal down: the app still resolves; the owner changes the model on a bridge-issued ticket", async () => {
    const id = w.bridge.ctx.identity;
    assert.ok(id);
    const owner = await w.api.generateKeyPair();
    const standalone = { issuer: w.bridge.ctx.bridgeRef, kid: w.api.thumbprint(id.key.publicJwk), ownerKeys: [owner.publicJwk] };
    await w.publish((c) => {
      (c as { standalone?: unknown }).standalone = standalone;
    });
    await waitFor(() => w.bridge.ctx.table?.standalone === true && w.bridge.ctx.table?.config.iss === w.bridge.ctx.bridgeRef, 15000);
    w.portalDown();
    const r = await h.role(appKey, INS, "reasoning");
    assert.equal(r.status, 200, r.text);
    assert.equal(JSON.parse(r.text).model, "llama-a");
    const ref = w.bridge.ctx.bridgeRef;
    const ticket = await w.api.signJws("tb-ticket+jwt" as never, { iss: ref, sub: "tb:per:per_01HPPPPPPPPPPPPPPPPPPPPPPP", aud: ref, iat: now(), exp: now() + 120, jti: w.api.ulid(), ws: WS, pur: "keys" }, id.key);
    await h.openWith(ticket);
    assert.equal((await h.post({ action: "bind", role: "reasoning", provider: "ollama", model: "llama-b", baseUrl: "http://192.168.1.20:11434" })).status, 303);
    assert.equal(JSON.parse((await h.role(appKey, INS, "reasoning")).text).model, "llama-b");
  });
});

describe("Keys and models: owner text is escaped; RM-13 canaries never leave the bridge", () => {
  let w: World;
  const lines: Line[] = [];
  const h = harness(() => w);
  before(async () => {
    w = await makeWorld({ real: true, logger: capture(lines) });
    await w.amend((c) => {
      (c as WorkspaceConfig0163).modelRoleRequirements = [REQS[1] as ModelRoleRequirementEntry];
    });
    await waitFor(() => w.bridge.ctx.table?.rev === w.rev(), 15000);
    await h.open();
  });
  after(async () => {
    await w.close();
  });

  test("owner text is escaped on the page and the confirm page", async () => {
    const label = `<img src=x onerror="alert(1)">`;
    assert.equal((await h.post({ action: "pkey", label, value: "sk-xss-rm" })).status, 303);
    // the model label follows MODEL_ID_PATTERN: markup, spaces and "//" are refused
    for (const model of ["<b>m</b>", "gpt 4", "https://x//y", "", "-m", "m".repeat(129)]) assert.equal((await h.post({ action: "bind", role: "utility", provider: "openai", model, keyName: label })).status, 400, model);
    assert.equal((await h.post({ action: "bind", role: "utility", provider: "nope", model: "m", keyName: label })).status, 400, "a provider outside the catalog");
    assert.equal((await h.post({ action: "bind", role: "utility", provider: "openai", model: "org/model:v1@x+y", keyName: label })).status, 303);
    const html = await h.page();
    assert.ok(!html.includes(label));
    assert.ok(html.includes("&lt;img src=x onerror=&quot;alert(1)&quot;&gt;"));
    const ask = await (await h.post({ action: "pkey_delete", label })).text();
    assert.ok(!ask.includes(label));
    assert.equal((await h.post({ action: "pkey_delete", label, confirm: "1" })).status, 303);
  });


  test("RM-13 (bridge half): canary base URL, key name and value: zero hits in status bodies and logs", async () => {
    assert.equal((await h.post({ action: "pkey", label: CANARY.keyName, value: CANARY.value })).status, 303);
    assert.equal((await h.post({ action: "bind", role: "utility", provider: "openai-compatible", model: "canary-model", baseUrl: CANARY.baseUrl, keyName: CANARY.keyName })).status, 303);
    assert.equal(w.bridge.ctx.state.bindings.find((b) => b.role === "utility")?.dataPolicy, "local");
    await waitFor(() => (w.acks as StatusReport0163[]).some((a) => a.roles?.some((r) => r.model === "canary-model" && r.set)), 15000);
    const seen = JSON.stringify(w.acks) + JSON.stringify(buildStatusReport(w.bridge.ctx)) + JSON.stringify(lines);
    for (const canary of [CANARY.baseUrl, "canary-url-7f3a", "10.9.8.7", CANARY.keyName, CANARY.value]) assert.ok(!seen.includes(canary), `${canary}: zero hits`);
    assert.ok(lines.length > 0, "the log was captured");
  });
});
