// The model list of the key page (Martin 2026-11-11): request shape per provider, role filter, refusals. No network.
import assert from "node:assert/strict";
import { test } from "node:test";
import { MODEL_PROVIDERS, type ModelProvider } from "@opt2-tealbrick/spec/models";
import { fitsRole, LIST_MAX_BYTES, listModels, listRequest, parseList } from "../src/model-list.ts";

const P = (id: string) => MODEL_PROVIDERS.find((p) => p.id === id) as ModelProvider;
const valid = (n: string) => /^(?!.*\/\/)[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}$/.test(n);
const answer = (body: unknown, status = 200) => async () => new Response(typeof body === "string" ? body : JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

test("requests: OpenAI-shaped /models with Bearer; Anthropic and Gemini their own address and header; Azure and Voyage none", () => {
  assert.deepEqual(listRequest(P("openai"), "https://api.openai.com/v1", "sk-a"), { url: "https://api.openai.com/v1/models", headers: { authorization: "Bearer sk-a" } });
  assert.deepEqual(listRequest(P("anthropic"), "https://api.anthropic.com/", "sk-b"), { url: "https://api.anthropic.com/v1/models?limit=1000", headers: { "x-api-key": "sk-b", "anthropic-version": "2023-06-01" } });
  assert.deepEqual(listRequest(P("google"), "https://generativelanguage.googleapis.com", "g-c"), { url: "https://generativelanguage.googleapis.com/v1beta/models?pageSize=1000", headers: { "x-goog-api-key": "g-c" } });
  assert.deepEqual(listRequest(P("ollama"), "http://192.168.1.20:11434/v1", undefined), { url: "http://192.168.1.20:11434/v1/models", headers: {} });
  assert.equal(listRequest(P("azure-openai"), "https://x.openai.azure.com", "k"), undefined);
  assert.equal(listRequest(P("voyage"), "https://api.voyageai.com/v1", "k"), undefined);
});

test("parse and filter: Gemini by its generation methods, Together by its type, the rest by name", () => {
  const gem = parseList(P("google"), { models: [{ name: "models/gemini-embedding-001", supportedGenerationMethods: ["embedContent"] }, { name: "models/gemini-2.5-pro", supportedGenerationMethods: ["generateContent"] }] });
  assert.deepEqual(gem, [{ id: "gemini-embedding-001", kind: "embeddings" }, { id: "gemini-2.5-pro", kind: "chat" }]);
  const tog = parseList(P("together"), [{ id: "BAAI/bge-large-en-v1.5", type: "embedding" }, { id: "meta-llama/Llama-3.3-70B", type: "chat" }, { id: "Salesforce/rerank-x", type: "rerank" }]);
  assert.deepEqual(tog?.filter((m) => fitsRole(m, "embeddings")).map((m) => m.id), ["BAAI/bge-large-en-v1.5"]);
  assert.deepEqual(tog?.filter((m) => fitsRole(m, "rerank")).map((m) => m.id), ["Salesforce/rerank-x"]);
  const oa = ["text-embedding-3-large", "gpt-5", "whisper-1", "dall-e-3", "tts-1", "omni-moderation-latest"].map((id) => ({ id }));
  assert.deepEqual(oa.filter((m) => fitsRole(m, "embeddings")).map((m) => m.id), ["text-embedding-3-large"]);
  assert.deepEqual(oa.filter((m) => fitsRole(m, "reasoning")).map((m) => m.id), ["gpt-5"]);
  assert.deepEqual(oa.filter((m) => fitsRole(m, "transcribe")).map((m) => m.id), ["whisper-1"]);
  assert.equal(parseList(P("openai"), { nope: 1 }), undefined);
});

test("listModels: sorted names for the role; names the binding refuses left out; no fit → every name", async () => {
  const r = await listModels(answer({ data: [{ id: "text-embedding-3-small" }, { id: "text-embedding-3-large" }, { id: "gpt-5" }, { id: "bad name" }] }), P("openai"), "embeddings", "https://api.openai.com/v1", "sk", valid);
  assert.deepEqual(r, { models: ["text-embedding-3-large", "text-embedding-3-small"] });
  const own = await listModels(answer({ data: [{ id: "my-model-a" }, { id: "my-model-b" }] }), P("llama-server"), "embeddings", "http://10.0.0.2:8080/v1", undefined, valid);
  assert.deepEqual(own, { models: ["my-model-a", "my-model-b"] }, "a custom server's own names are all shown");
});

test("listModels refusals: no key, refused key, provider error, bad body, too large, unreachable; never the provider's text", async () => {
  let called = false;
  const spy: typeof fetch = async () => {
    called = true;
    return new Response("{}");
  };
  assert.equal(((await listModels(spy, P("openai"), "embeddings", "https://api.openai.com/v1", undefined, valid)) as { refused: string }).refused, "key_missing");
  assert.equal(called, false);
  assert.equal(((await listModels(answer({ error: { message: "Incorrect API key sk-secret" } }, 401), P("openai"), "embeddings", "https://api.openai.com/v1", "sk", valid)) as { refused: string }).refused, "key_refused");
  const down = await listModels(answer("upstream exploded sk-secret", 502), P("openai"), "embeddings", "https://api.openai.com/v1", "sk", valid);
  assert.deepEqual(down, { refused: "provider_failed", reason: "OpenAI answered 502. Try again later." });
  assert.equal(((await listModels(answer("not json"), P("openai"), "embeddings", "https://api.openai.com/v1", "sk", valid)) as { refused: string }).refused, "answer_invalid");
  const huge = await listModels(answer(`{"data":[${'{"id":"x"},'.repeat(LIST_MAX_BYTES / 10)}{"id":"y"}]}`), P("openai"), "embeddings", "https://api.openai.com/v1", "sk", valid);
  assert.equal((huge as { refused: string }).refused, "answer_invalid");
  const gone = await listModels(
    async () => {
      throw new TypeError("fetch failed");
    },
    P("openai"),
    "embeddings",
    "https://api.openai.com/v1",
    "sk",
    valid,
  );
  assert.equal((gone as { refused: string }).refused, "provider_failed");
  assert.equal(((await listModels(spy, P("azure-openai"), "embeddings", "https://x.openai.azure.com", "sk", valid)) as { refused: string }).refused, "list_unsupported");
});

test("listModels sends no redirect and a timeout; the key goes only in its header", async () => {
  let seen: RequestInit | undefined;
  let url = "";
  await listModels(
    async (u, init) => {
      url = String(u);
      seen = init;
      return new Response(JSON.stringify({ data: [] }));
    },
    P("openai"),
    "embeddings",
    "https://api.openai.com/v1",
    "sk-only-header",
    valid,
  );
  assert.equal(seen?.redirect, "error");
  assert.ok(seen?.signal);
  assert.ok(!url.includes("sk-only-header"));
  assert.equal((seen?.headers as Record<string, string> | undefined)?.authorization, "Bearer sk-only-header");
});
