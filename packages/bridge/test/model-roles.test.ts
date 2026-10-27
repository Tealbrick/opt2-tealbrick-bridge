/**
 * v0.1.63 (BRIDGE §15, C330(4)): the workspace model-role registry. Real bridge, the "Keys and models" page over HTTP and
 * the internal resolve route with real instance assertions. Rows RM-2..RM-6, RM-12 and the bridge half of RM-13
 * (CONFORMANCE v0.1.63): resolve and its refusals, the `local` check, one key for many roles, label-only status and logs,
 * per-app overrides, resolve without Portal (standalone).
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { after, before, describe, test } from "node:test";
import type { ModelRoleRequirementEntry, StatusReport } from "@opt2-tealbrick/spec/bridge";
import { DATA_POLICIES, DATA_POLICY_RANK, type DataPolicy, MODEL_PROVIDERS, NEVER_LOCAL, NEVER_LOCAL_HOSTNAMES } from "@opt2-tealbrick/spec/models";
import type { Ed25519KeyPair } from "@opt2-tealbrick/spec/sdk";
import { classifyBase, classifyOwnHost, effectiveGateway, effectivePolicy, resolveForCaller } from "../src/model-roles.ts";
import { hintsFrom, renderModels } from "../src/models-page.ts";
import { buildStatusReport } from "../src/portal.ts";
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
const METADATA_CGNAT = [100, 100, 100, 200].join(".");
const OTHER_TAILNET = ["other", "ts", "net"].join(".");
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

/** the spec fixture (BRIDGE §15.3), with the check-literals placeholders restored (see its `source`) */
interface LocalCase {
  kind: "base" | "own_host";
  input: string;
  expect: string;
  canonical?: string;
  ownHosts?: string[];
  ownInfra?: string[];
}
const restore = (v: string) => v.replaceAll("{tsnet}", ["ts", "net"].join(".")).replaceAll("{TSNET}", ["TS", "NET"].join(".")).replaceAll("{cgnat}", String(100));
const LOCAL_CASES: LocalCase[] = (JSON.parse(readFileSync(new URL("./fixtures/local-check.cases.json", import.meta.url), "utf8")).cases as LocalCase[]).map((c) => ({
  ...c,
  input: restore(c.input),
  ...(c.canonical ? { canonical: restore(c.canonical) } : {}),
  ...(c.ownHosts ? { ownHosts: c.ownHosts.map(restore) } : {}),
  ...(c.ownInfra ? { ownInfra: c.ownInfra.map(restore) } : {}),
}));

describe("BRIDGE §15.3 local check (RM-3, unit; spec follow-up #49)", () => {
  test("every row of the spec fixture local-check.cases.json gives its expected class and canonical form", () => {
    assert.equal(LOCAL_CASES.length, 137, "all rows of specs#53 9f9f916");
    assert.ok(LOCAL_CASES.some((c) => c.input === "http://10.0.0.1\\evil/v1" && c.expect === "refused"), "the backslash-only row (QA-BRIDGE22-3)");
    for (const c of LOCAL_CASES) {
      const label = `${c.kind} ${JSON.stringify(c.input)}`;
      if (c.kind === "own_host") {
        const r = classifyOwnHost(c.input);
        assert.equal("refused" in r ? "refused" : r.warnPublic ? "accepted_warn_public" : "accepted", c.expect, label);
        continue;
      }
      const r = classifyBase(c.input, { infra: c.ownInfra ?? [], hosts: c.ownHosts ?? [] });
      assert.equal("refused" in r ? "refused" : r.cls, c.expect, label);
      if (c.canonical && "href" in r) assert.equal(r.href, c.canonical, `${label}: canonical`);
    }
    assert.ok(LOCAL_CASES.some((c) => c.input === "http://10.0.0.1\\@evil.example/v1" && c.expect === "refused"), "the parser-differential row is in the copy");
  });

  test("TB_OWN_INFRA_ORIGINS is verified local; the Own hosts list is owner-listed; NEVER_LOCAL wins over both", () => {
    const own = { infra: ["https://gpu.owner.example:8443"], hosts: [`https://${TAILNET_HOST}`, `https://${METADATA_CGNAT}`] };
    assert.deepEqual(classifyBase("https://gpu.owner.example:8443/v1", own), { cls: "verified", href: "https://gpu.owner.example:8443/v1" });
    assert.deepEqual(classifyBase(`https://${TAILNET_HOST}/v1`, own), { cls: "owner_listed", href: `https://${TAILNET_HOST}/v1` });
    assert.equal((classifyBase(`https://${METADATA_CGNAT}/`, own) as { cls: string }).cls, "not_local", "listed, but never local");
    assert.equal((classifyBase(`https://${OTHER_TAILNET}/v1`, own) as { cls: string }).cls, "not_local", "an unlisted tailnet name");
    // Node prints an IPv4-mapped address in hex with brackets; the bridge converts the last 32 bits back
    assert.equal(new URL("http://[::ffff:169.254.169.254]").hostname, "[::ffff:a9fe:a9fe]");
    assert.equal((classifyBase("https://[::ffff:a9fe:a9fe]/", own) as { cls: string }).cls, "not_local");
    assert.equal((classifyBase("http://[::ffff:a00:1]/v1", own) as { cls: string }).cls, "verified");
    assert.ok("refused" in classifyOwnHost("http://metadata.goog"));
    assert.ok("refused" in classifyOwnHost(`https://${CGNAT_TOP}/v1`), "no path");
  });

  test("NEVER_LOCAL, NEVER_LOCAL_HOSTNAMES and the gateway rows are the spec 0.1.68 values", () => {
    assert.deepEqual([...NEVER_LOCAL], ["169.254.0.0/16", "fe80::/10", "fd00:ec2::254/128", `${METADATA_CGNAT}/32`, "192.0.0.192/32", "168.63.129.16/32", "0.0.0.0/8", "::/128"]);
    assert.deepEqual([...NEVER_LOCAL_HOSTNAMES], ["metadata.google.internal", "metadata.goog", "metadata"]);
    assert.deepEqual(MODEL_PROVIDERS.filter((p) => p.gateway).map((p) => p.id), ["openrouter", "litellm", "openai-compatible"]);
  });

  test("a stored binding is re-classified at every resolve: local while verified or listed, zdr while attested; policyBasis", () => {
    const own = { infra: ["https://gpu.owner.example:8443"], hosts: [`http://${CGNAT_IP}:11434/`] };
    const none = { infra: [], hosts: [] };
    const at = new Date().toISOString();
    const b = { role: "embeddings", provider: "ollama", model: "m", baseUrl: "https://gpu.owner.example:8443/", dataPolicy: "local" } as const;
    assert.deepEqual(effectivePolicy(b, own), { policy: "local", basis: "verified" });
    assert.deepEqual(effectivePolicy(b, none), { policy: "standard", basis: "verified" }, "TB_OWN_INFRA_ORIGINS changed: no longer local");
    const listed = { ...b, baseUrl: `http://${CGNAT_IP}:11434/v1` };
    assert.deepEqual(effectivePolicy(listed, own), { policy: "local", basis: "owner_attested" });
    assert.deepEqual(effectivePolicy(listed, none), { policy: "standard", basis: "verified" }, "removed from Own hosts");
    assert.equal(effectivePolicy({ role: "reasoning", provider: "openai", model: "m", dataPolicy: "zdr" }, none).policy, "standard", "no zdrAttestedAt");
    assert.deepEqual(effectivePolicy({ role: "reasoning", provider: "openai", model: "m", dataPolicy: "zdr", zdrAttestedAt: at }, none), { policy: "zdr", basis: "owner_attested" });
    assert.equal(effectivePolicy({ role: "reasoning", provider: "deepseek", model: "m", dataPolicy: "zdr", zdrAttestedAt: at }, none).policy, "standard", "a stored zdr binding whose provider changed to one without zdr");
  });

  test("effective gateway: gateway flag, no default address, or a base URL other than the default", () => {
    const p = (id: string) => MODEL_PROVIDERS.find((x) => x.id === id) as (typeof MODEL_PROVIDERS)[number];
    assert.equal(effectiveGateway(p("openrouter"), undefined), true);
    assert.equal(effectiveGateway(p("azure-openai"), "https://x.openai.azure.com/"), true, "no defaultBaseUrl");
    assert.equal(effectiveGateway(p("openai"), undefined), false);
    assert.equal(effectiveGateway(p("openai"), "https://api.openai.com/v1"), false);
    assert.equal(effectiveGateway(p("openai"), "https://proxy.example/v1"), true, "openai behind a proxy");
  });
});

describe("RM-2 resolve order (unit): 9 binding × minPolicy pairs, key after policy, no override fall-back", () => {
  const INS2 = "ins_01HQQQQQQQQQQQQQQQQQQQQQQQ";
  const at = new Date().toISOString();
  const BIND: Record<DataPolicy, ModelBinding> = {
    local: { role: "reasoning", provider: "ollama", model: "llama3", baseUrl: "http://10.0.0.5:11434", dataPolicy: "local" },
    zdr: { role: "reasoning", provider: "openai", model: "gpt-z", keyName: "pk:K", dataPolicy: "zdr", zdrAttestedAt: at },
    standard: { role: "reasoning", provider: "openai", model: "gpt-s", keyName: "pk:K", dataPolicy: "standard" },
  };
  const run = (bindings: ModelBinding[], minPolicy: DataPolicy, values: Record<string, string> = { "pk:K": "v" }, ins = INS, ownHosts: string[] = []) => {
    const t = { config: { modelRoleRequirements: [{ role: "reasoning", ins, product: "notes", required: true, minPolicy, usedBy: ["app"] }] }, apps: new Map([[ins, {}]]) } as never;
    const ctx = { state: { bindings, ownHosts, keyStore: { keysRev: 7, values } }, ownInfraOrigins: [] } as never;
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
    assert.equal((run(both, "zdr", { "pk:K": "v" }, INS2) as { code: string }).code, "role_policy_too_low", "the override is used, never the default");
    assert.equal((run(both, "zdr") as { model: string }).model, "gpt-z", "the other instance keeps the default");
  });
  test("an http binding whose host stopped being local is not served (role_not_set), whatever the policy", () => {
    const listed = `http://${CGNAT_IP}:11434/`;
    const b: ModelBinding = { role: "reasoning", provider: "ollama", model: "llama3", baseUrl: `${listed}v1`, dataPolicy: "local" };
    assert.equal((run([b], "standard", {}, INS, [listed]) as { baseUrl: string }).baseUrl, `${listed}v1`, "listed: served");
    for (const needed of DATA_POLICIES) assert.equal((run([b], needed, {}, INS, []) as { code: string }).code, "role_not_set", `removed from Own hosts, minPolicy ${needed}`);
    const https = { ...b, baseUrl: `https://${CGNAT_IP}/v1` };
    assert.equal((run([https], "standard", {}, INS, []) as { dataPolicy: string }).dataPolicy, "standard", "https: still served, as standard");
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
      c.modelRoleRequirements = REQS;
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
    assert.match(html, /Suggested: OpenAI · gpt-hint · standard\. Nothing is saved until you save it\./);
    assert.match(html, /id="r-reasoning-d-model"[^>]*value="gpt-hint"/);
    assert.equal(w.bridge.ctx.state.bindings.length, 0, "a hint stores nothing");
    assert.match(html, /I confirm a zero-data-retention contract with this provider/);
  });

  test("RM-2 / RM-4: one provider key serves three roles; declared + set → the binding; replacing the key bumps keysRev once", async () => {
    assert.equal((await h.post({ action: "pkey", label: "OpenAI main", value: " sk-rm-one\n" })).status, 303);
    assert.equal(store().values["pk:OpenAI main"], "sk-rm-one");
    assert.ok(!Object.hasOwn(store().values, "OpenAI main"), "a provider key lives in its own namespace (QA-BRIDGE22-1)");
    assert.equal((await bind({ role: "reasoning", provider: "openai", model: "gpt-test", keyName: "pk:OpenAI main", dataPolicy: "standard" })).status, 303);
    assert.equal((await bind({ role: "utility", provider: "openai", model: "gpt-mini", keyName: "pk:OpenAI main" })).status, 303);
    assert.equal((await bind({ role: "summarize", provider: "openai", model: "gpt-zdr", keyName: "pk:OpenAI main", dataPolicy: "zdr", zdr: "1" })).status, 303);
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

    assert.equal((await bind({ role: "dreaming", provider: "openai", model: "gpt-dream", keyName: "pk:OpenAI main", dataPolicy: "standard" })).status, 303);
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
    assert.equal((await bind({ role: "rerank", provider: "openrouter", model: "rr-1", keyName: "pk:OpenAI main" })).status, 303);
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
    await refused({ baseUrl: "http://203.0.113.5:11434" }, /use an https address; plain http is allowed only on your own network/);
    await refused({}, /needs a base URL/);
    // input hygiene (every case is in the fixture test; one here proves the page uses it)
    await refused({ baseUrl: "http://10.0.0.1\\@evil.example/v1" }, /without a user name, password, spaces, query or fragment/);
    assert.deepEqual(w.bridge.ctx.state.bindings, before, "nothing stored");
    const zdr = await bind({ role: "reasoning", provider: "deepseek", model: "d", keyName: "pk:OpenAI main", dataPolicy: "zdr", zdr: "1" });
    assert.equal(zdr.status, 400, "zdr only for providers that offer it");
    assert.equal((await bind({ role: "reasoning", provider: "openai", model: "d", keyName: "pk:OpenAI main", dataPolicy: "zdr" })).status, 400, "zdr needs the tick");

    assert.equal((await bind({ role: "embeddings", provider: "ollama", model: "nomic", baseUrl: "http://10.20.30.40:11434", keyName: "pk:OpenAI main", dims: "768" })).status, 303);
    const b = w.bridge.ctx.state.bindings.find((x) => x.role === "embeddings");
    assert.equal(b?.dataPolicy, "local", "a passing private URL defaults to local (C336 Q3)");
    assert.equal(b?.keyName, undefined, "no key for a provider that needs none");
    assert.deepEqual(json(await h.role(appKey, INS, "embeddings")), { role: "embeddings", provider: "ollama", model: "nomic", baseUrl: "http://10.20.30.40:11434/", key: null, dataPolicy: "local", dims: 768, keysRev: store().keysRev });
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
    assert.equal((await bind({ role: "reasoning", ins: INS, provider: "anthropic", model: "claude-test", keyName: "pk:Anthropic main" })).status, 303);
    const notes = json(await h.role(appKey, INS, "reasoning"));
    assert.equal(notes.provider, "anthropic");
    assert.equal(notes.key, "sk-ant-rm");
    const guard = json(await h.role(guardKey, HOOKINS, "reasoning"));
    assert.equal(guard.provider, "openai");
    assert.equal(guard.model, "gpt-test");
    assert.equal((await bind({ role: "reasoning", ins: "ins_01HXXXXXXXXXXXXXXXXXXXXXXX", provider: "openai", model: "x", keyName: "pk:OpenAI main" })).status, 400, "an app that does not declare the role");
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
    assert.equal(store().values["pk:OpenAI main"], "sk-rm-two", "nothing deleted yet");
    assert.equal(store().keysRev, rev);
    assert.equal((await h.post({ action: "pkey_delete", label: "OpenAI main", confirm: "1" })).status, 303);
    assert.ok(!Object.hasOwn(store().values, "pk:OpenAI main"));
    assert.equal(store().keysRev, rev + 1);
    assert.ok(!w.bridge.ctx.state.bindings.some((b) => b.keyName === "pk:OpenAI main"));
    assert.equal(w.bridge.ctx.state.bindings.find((b) => b.role === "reasoning" && !b.ins)?.model, "gpt-test", "the binding stays, without a key");
    assert.equal(json(await h.role(appKey, INS, "reasoning")).error.code, "role_not_set");
    // RM-25 (spec 0.1.69): a requirement (app) key never satisfies a binding; the form offers provider keys only
    assert.equal((await h.post({ name: "NOTES_API_KEY", value: "sk-notes-rm" })).status, 303);
    assert.doesNotMatch(await h.page(), /\(app key\)/);
    const appKeyBind = await bind({ role: "reasoning", provider: "openai", model: "gpt-test", keyName: "NOTES_API_KEY" });
    assert.equal(appKeyBind.status, 400);
    assert.match(await appKeyBind.text(), /choose a provider key from the list/);
    // a stored binding that names an app key (written directly): not served, status set:false, page "key missing"
    const st = w.bridge.ctx.state;
    st.saveBindings(st.bindings.map((b) => (b.role === "reasoning" && !b.ins ? { ...b, keyName: "NOTES_API_KEY" } : b)));
    assert.equal(json(await h.role(appKey, INS, "reasoning")).error.code, "role_not_set");
    assert.equal(buildStatusReport(w.bridge.ctx).roles?.find((r) => r.role === "reasoning" && r.ins === INS)?.set, false);
    assert.match(await h.page(), /Workspace default: OpenAI · gpt-test · https:\/\/api\.openai\.com\/v1 · key missing · standard/);
    // the owner picks a provider key: served again
    assert.equal((await bind({ role: "reasoning", provider: "openai", model: "gpt-test", keyName: "pk:Anthropic main" })).status, 303);
    assert.equal(json(await h.role(appKey, INS, "reasoning")).key, "sk-ant-rm");
  });

  test("RM-5 / RM-13 (bridge half): status roles[] are labels only; no base URL, key name or value in reports or logs", async () => {
    const report = buildStatusReport(w.bridge.ctx) as StatusReport;
    assert.equal(report.roles?.length, REQS.length);
    // schema model-role-status.schema.json#/$defs/modelRoleStatus: exactly these keys, labels of the spec patterns or null
    for (const row of report.roles ?? []) {
      // `policyBasis` (spec follow-up #49) only when set
      assert.deepEqual(Object.keys(row).sort(), ["dataPolicy", "ins", "model", ...(row.set ? ["policyBasis"] : []), "policyOk", "provider", "role", "set"]);
      assert.ok(row.policyBasis === undefined || ["verified", "owner_attested"].includes(row.policyBasis));
      assert.ok(row.provider === null || /^[a-z][a-z0-9-]{1,31}$/.test(row.provider));
      assert.ok(row.model === null || MODEL_ID.test(row.model));
      assert.ok(row.dataPolicy === null || (DATA_POLICIES as readonly string[]).includes(row.dataPolicy));
      assert.equal(typeof row.set, "boolean");
      assert.equal(typeof row.policyOk, "boolean");
    }
    const row = (role: string, ins = INS) => report.roles?.find((r) => r.role === role && r.ins === ins);
    assert.deepEqual(row("embeddings"), { role: "embeddings", ins: INS, set: true, policyOk: true, provider: "ollama", model: "bge-m3", dataPolicy: "local", policyBasis: "verified" });
    assert.deepEqual(row("dreaming"), { role: "dreaming", ins: INS, set: false, policyOk: false, provider: null, model: null, dataPolicy: null }, "its key was deleted");
    assert.equal(row("reasoning", HOOKINS)?.set, true);
    await waitFor(() => (w.acks as StatusReport[]).some((a) => a.roles?.some((r) => r.role === "embeddings" && r.model === "bge-m3")), 15000);
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
      c.modelRoleRequirements = [REQS[0] as ModelRoleRequirementEntry];
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
      c.modelRoleRequirements = [REQS[1] as ModelRoleRequirementEntry];
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
    for (const model of ["<b>m</b>", "gpt 4", "https://x//y", "", "-m", "m".repeat(129)]) assert.equal((await h.post({ action: "bind", role: "utility", provider: "openai", model, keyName: `pk:${label}` })).status, 400, model);
    assert.equal((await h.post({ action: "bind", role: "utility", provider: "nope", model: "m", keyName: `pk:${label}` })).status, 400, "a provider outside the catalog");
    assert.equal((await h.post({ action: "bind", role: "utility", provider: "openai", model: "org/model:v1@x+y", keyName: `pk:${label}` })).status, 303);
    const html = await h.page();
    assert.ok(!html.includes(label));
    assert.ok(html.includes("&lt;img src=x onerror=&quot;alert(1)&quot;&gt;"));
    const ask = await (await h.post({ action: "pkey_delete", label })).text();
    assert.ok(!ask.includes(label));
    assert.equal((await h.post({ action: "pkey_delete", label, confirm: "1" })).status, 303);
  });


  test("RM-13 (bridge half): canary base URL, key name and value: zero hits in status bodies and logs", async () => {
    assert.equal((await h.post({ action: "pkey", label: CANARY.keyName, value: CANARY.value })).status, 303);
    assert.equal((await h.post({ action: "bind", role: "utility", provider: "openai-compatible", model: "canary-model", baseUrl: CANARY.baseUrl, keyName: `pk:${CANARY.keyName}` })).status, 303);
    assert.equal(w.bridge.ctx.state.bindings.find((b) => b.role === "utility")?.dataPolicy, "local");
    await waitFor(() => (w.acks as StatusReport[]).some((a) => a.roles?.some((r) => r.model === "canary-model" && r.set)), 15000);
    const seen = JSON.stringify(w.acks) + JSON.stringify(buildStatusReport(w.bridge.ctx)) + JSON.stringify(lines);
    for (const canary of [CANARY.baseUrl, "canary-url-7f3a", "10.9.8.7", CANARY.keyName, CANARY.value]) assert.ok(!seen.includes(canary), `${canary}: zero hits`);
    assert.ok(lines.length > 0, "the log was captured");
  });
});

describe("spec follow-up #49 on the page: Own hosts, gateway attestation, owner-attested labels (RM-3, RM-18)", () => {
  let w: World;
  const h = harness(() => w);
  const report = () => buildStatusReport(w.bridge.ctx) as StatusReport;
  const row = () => report().roles?.find((r) => r.role === "utility");
  const policy = () => row()?.dataPolicy;
  const stored = () => w.bridge.ctx.state.bindings.find((b) => b.role === "utility");
  before(async () => {
    w = await makeWorld({ real: true });
    await w.amend((c) => {
      c.modelRoleRequirements = [{ ...(REQS[1] as ModelRoleRequirementEntry), minPolicy: "local" }];
    });
    await waitFor(() => w.bridge.ctx.table?.rev === w.rev(), 15000);
    await h.open();
    assert.equal((await h.post({ action: "pkey", label: "gw", value: "sk-gw-49" })).status, 303);
  });
  after(async () => {
    await w.close();
  });

  test("a tailnet address is local only while listed in Own hosts; removing it makes the binding standard; NEVER_LOCAL is refused", async () => {
    const url = `http://${CGNAT_IP}:11434`;
    const refusedLocal = await h.post({ action: "bind", role: "utility", provider: "ollama", model: "llama3", baseUrl: url, dataPolicy: "local" });
    assert.equal(refusedLocal.status, 400, "unlisted: not local (and plain http to it is refused)");
    for (const origin of [`http://${METADATA_CGNAT}`, "http://169.254.169.254", `${url}/v1`, `http://${TAILNET_HOST}`]) assert.equal((await h.post({ action: "host_add", origin })).status, 400, origin);
    const warn = await h.post({ action: "host_add", origin: "https://8.8.8.8" });
    assert.equal(warn.status, 303, "a public IP literal is accepted with a warning");
    assert.match(await h.page(), /This is a public address: traffic to it crosses the internet\./);
    const rev = w.bridge.ctx.state.keyStore.keysRev;
    assert.equal((await h.post({ action: "host_add", origin: `${url}/` })).status, 303);
    assert.deepEqual(w.bridge.ctx.state.ownHosts, ["https://8.8.8.8/", `${url}/`], "stored canonical (href)");
    assert.equal(w.bridge.ctx.state.keyStore.keysRev, rev + 1, "an Own hosts change bumps keysRev once");
    const page = await h.page();
    assert.match(page, new RegExp(`<h2 id="h-own">Own hosts</h2>[\\s\\S]*${url.replace(/\./g, "\\.")}`));
    assert.equal((await h.post({ action: "bind", role: "utility", provider: "ollama", model: "llama3", baseUrl: `${url}/v1` })).status, 303);
    assert.equal(stored()?.dataPolicy, "local", "listed: Automatic gives local");
    assert.equal(stored()?.baseUrl, `${url}/v1`);
    assert.deepEqual([row()?.dataPolicy, row()?.policyBasis, row()?.policyOk], ["local", "owner_attested", true]);
    assert.match(await h.page(), /local \(owner-listed, not verified\)/);
    const ask = await h.post({ action: "host_remove", origin: `${url}/` });
    assert.equal(ask.status, 200, "a removal asks first");
    assert.match(await ask.text(), /These models fall below their app&#39;s data policy: utility \(/);
    assert.deepEqual(w.bridge.ctx.state.ownHosts.length, 2, "nothing removed yet");
    const rev2 = w.bridge.ctx.state.keyStore.keysRev;
    assert.equal((await h.post({ action: "host_remove", origin: `${url}/`, confirm: "1" })).status, 303);
    assert.equal(w.bridge.ctx.state.keyStore.keysRev, rev2 + 1);
    assert.equal(stored()?.dataPolicy, "local", "the stored binding is unchanged …");
    // §15.3 (3129040): its URL is plain http to a host that is no longer listed: not served at all
    assert.deepEqual([row()?.set, row()?.dataPolicy, row()?.policyOk], [false, null, false], "… and is no longer served (http to a host that stopped being local)");
    // a verified private address, canonical form stored
    assert.equal((await h.post({ action: "bind", role: "utility", provider: "ollama", model: "llama3", baseUrl: "http://LOCALHOST.:11434/v1" })).status, 303);
    assert.equal(stored()?.baseUrl, "http://localhost.:11434/v1");
    assert.deepEqual([row()?.dataPolicy, row()?.policyBasis], ["local", "verified"]);
  });

  test("gateway zdr: the confirmation names the host; until then and after a MODEL change it counts as standard", async () => {
    const bind = (model: string, extra: Record<string, string> = {}) => h.post({ action: "bind", role: "utility", provider: "openrouter", model, keyName: "pk:gw", dataPolicy: "zdr", zdr: "1", ...extra });
    const ask = await bind("vendor/model-a");
    assert.equal(ask.status, 200, "the generic tick is not enough for a gateway");
    const html = await ask.text();
    assert.match(html, /I confirm that my contract with openrouter\.ai keeps no data for every model it routes this role to/);
    assert.match(html, /name="zdr_host" value="openrouter\.ai"/);
    assert.equal(stored()?.model, "vendor/model-a");
    assert.equal(stored()?.zdrAttestedAt, undefined);
    assert.equal(policy(), "standard", "stored, not attested: standard");
    assert.equal((await bind("vendor/model-a", { zdr_host: "openrouter.ai" })).status, 303);
    assert.ok(stored()?.zdrAttestedAt);
    assert.equal(policy(), "zdr");
    assert.equal((await bind("vendor/model-a")).status, 303, "same provider, URL and model: the attestation is kept");
    assert.equal(policy(), "zdr");
    assert.equal((await bind("vendor/model-b")).status, 200, "a model change on a gateway asks again");
    assert.equal(stored()?.zdrAttestedAt, undefined, "the model change cleared the attestation");
    assert.equal(policy(), "standard");
    assert.equal((await bind("vendor/model-b", { zdr_host: "evil.example" })).status, 200, "a confirmation for another host does not count");
    assert.equal(policy(), "standard");
    assert.equal((await bind("vendor/model-b", { zdr_host: "openrouter.ai" })).status, 303);
    assert.deepEqual([policy(), row()?.policyBasis], ["zdr", "owner_attested"]);
    // openai behind a proxy is an effective gateway: the confirmation names the proxy host
    const proxy = await h.post({ action: "bind", role: "utility", provider: "openai", model: "gpt-x", baseUrl: "https://proxy.example/v1", keyName: "pk:gw", dataPolicy: "zdr", zdr: "1" });
    assert.equal(proxy.status, 200);
    assert.match(await proxy.text(), /my contract with proxy\.example keeps no data/);
  });

  test("RM-18: every zdr label reads 'zero data retention (owner-attested)'", async () => {
    const html = await h.page();
    assert.ok(html.includes("zero data retention (owner-attested)"));
    assert.ok(!/Zero data retention(?! \(owner-attested\))/i.test(html.replaceAll("zero data retention (owner-attested)", "")), "no other zdr wording");
  });
});
