/**
 * The model list of the key page (Martin 2026-11-11, hotfix): the owner picks a model from what the provider offers instead of
 * typing a name. The ONE provider call the bridge makes (BRIDGE §1.1 exception): only when the owner opens a model form on the
 * key page, only the provider's list-models address, with the key that setting would use. Nothing is stored; the answer is
 * model names only (each checked against the `model` pattern), never the key and never the provider's own error text.
 * A provider with no list address (Azure deployments, Voyage AI) keeps the typed model field.
 */
import type { ModelProvider, ModelRole } from "@opt2-tealbrick/spec/models";

export const LIST_TIMEOUT_MS = 10_000;
/** the provider answer is read up to this size; a longer answer is refused (a list of a few thousand names fits) */
export const LIST_MAX_BYTES = 4 * 1024 * 1024;
/** at most this many names go to the page */
export const LIST_MAX_MODELS = 1000;

export type ListRefusal = "list_unsupported" | "key_missing" | "key_refused" | "provider_failed" | "answer_invalid";
export type ModelListResult = { models: string[] } | { refused: ListRefusal; reason: string };

interface Raw {
  id: string;
  /** the provider's own kind of the model, when it says one (Together: `type`; Gemini: generation methods) */
  kind?: "embeddings" | "rerank" | "chat" | "audio" | "image" | "other";
}

const EMBED = /embed|bge-|\be5-|gte-|nomic|arctic-embed|mxbai/i;
const RERANK = /rerank/i;
const AUDIO = /whisper|transcri/i;
const NOT_CHAT = /embed|rerank|whisper|tts|speech|dall-e|gpt-image|image-|moderation|davinci|babbage|sora|realtime|transcri|search-|computer-use|bge-|gte-/i;

/** Which names fit the role. A role the names do not tell apart (vision, the chat roles) keeps every chat-like name. */
export function fitsRole(m: Raw, role: ModelRole): boolean {
  if (m.kind && m.kind !== "other") {
    if (role === "embeddings") return m.kind === "embeddings";
    if (role === "rerank") return m.kind === "rerank";
    if (role === "transcribe") return m.kind === "audio";
    return m.kind === "chat";
  }
  if (role === "embeddings") return EMBED.test(m.id);
  if (role === "rerank") return RERANK.test(m.id);
  if (role === "transcribe") return AUDIO.test(m.id);
  return !NOT_CHAT.test(m.id);
}

function togetherKind(t: unknown): Raw["kind"] {
  if (t === "embedding") return "embeddings";
  if (t === "rerank") return "rerank";
  if (t === "chat" || t === "language" || t === "code") return "chat";
  if (t === "audio" || t === "transcribe") return "audio";
  if (t === "image") return "image";
  return undefined;
}

/** The request for one provider, or undefined when the provider has no list address the bridge knows. */
export function listRequest(p: ModelProvider, base: string, key: string | undefined): { url: string; headers: Record<string, string> } | undefined {
  const root = base.replace(/\/+$/u, "");
  if (p.id === "anthropic") return { url: `${root}/v1/models?limit=1000`, headers: { ...(key ? { "x-api-key": key } : {}), "anthropic-version": "2023-06-01" } };
  if (p.id === "google") return { url: `${root}/v1beta/models?pageSize=1000`, headers: key ? { "x-goog-api-key": key } : {} };
  if (p.id === "azure-openai" || p.id === "voyage") return undefined;
  if (p.openaiCompatible) return { url: `${root}/models`, headers: key ? { authorization: `Bearer ${key}` } : {} };
  return undefined;
}

/** The names in one provider answer (OpenAI shape `data[].id`, Gemini `models[].name`, Ollama-style `models[].model`). */
export function parseList(p: ModelProvider, body: unknown): Raw[] | undefined {
  if (!body || typeof body !== "object") return undefined;
  const b = body as { data?: unknown; models?: unknown };
  if (p.id === "google" && Array.isArray(b.models)) {
    return b.models.flatMap((m) => {
      const r = m as { name?: unknown; supportedGenerationMethods?: unknown };
      if (typeof r.name !== "string") return [];
      const methods = Array.isArray(r.supportedGenerationMethods) ? r.supportedGenerationMethods : [];
      const kind: Raw["kind"] = methods.includes("embedContent") ? "embeddings" : methods.includes("generateContent") ? "chat" : "other";
      return [{ id: r.name.replace(/^models\//u, ""), kind }];
    });
  }
  const list = Array.isArray(b.data) ? b.data : Array.isArray(body) ? (body as unknown[]) : Array.isArray(b.models) ? b.models : undefined;
  if (!list) return undefined;
  return list.flatMap((m) => {
    const r = m as { id?: unknown; model?: unknown; name?: unknown; type?: unknown };
    const id = typeof r.id === "string" ? r.id : typeof r.model === "string" ? r.model : typeof r.name === "string" ? r.name : undefined;
    if (!id) return [];
    const kind = togetherKind(r.type);
    return [kind ? { id, kind } : { id }];
  });
}

async function readCapped(res: Response): Promise<string | undefined> {
  if (!res.body) return "";
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > LIST_MAX_BYTES) {
      await reader.cancel().catch(() => {});
      return undefined;
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}

/**
 * The model names `p` offers for `role` at `base` (canonical, already checked by §15.3), sorted. `valid` is the binding's
 * model pattern: a name that fails it could not be saved, so it is left out.
 */
export async function listModels(
  fetchFn: typeof fetch,
  p: ModelProvider,
  role: ModelRole,
  base: string,
  key: string | undefined,
  valid: (name: string) => boolean,
): Promise<ModelListResult> {
  const req = listRequest(p, base, key);
  if (!req) return { refused: "list_unsupported", reason: `${p.label} has no model list the bridge can read.` };
  if (p.keyNeeded && !key) return { refused: "key_missing", reason: `Enter the ${p.label} key under Provider keys first.` };
  let res: Response;
  try {
    res = await fetchFn(req.url, { headers: { accept: "application/json", ...req.headers }, redirect: "error", signal: AbortSignal.timeout(LIST_TIMEOUT_MS) });
  } catch {
    return { refused: "provider_failed", reason: `${p.label} did not give its model list. Try again later.` };
  }
  if (res.status === 401 || res.status === 403) {
    await res.body?.cancel().catch(() => {});
    return { refused: "key_refused", reason: `${p.label} refused the key. Check the key under Provider keys.` };
  }
  if (!res.ok) {
    await res.body?.cancel().catch(() => {});
    return { refused: "provider_failed", reason: `${p.label} did not give its model list. Try again later.` };
  }
  let body: unknown;
  try {
    const text = await readCapped(res);
    if (text === undefined) return { refused: "answer_invalid", reason: `The ${p.label} model list is too large.` };
    body = JSON.parse(text);
  } catch {
    return { refused: "answer_invalid", reason: `${p.label} sent a model list the bridge cannot read.` };
  }
  const raw = parseList(p, body);
  if (!raw) return { refused: "answer_invalid", reason: `${p.label} sent a model list the bridge cannot read.` };
  const names = (list: Raw[]) => [...new Set(list.map((m) => m.id).filter(valid))].sort((a, b) => a.localeCompare(b));
  const fitting = names(raw.filter((m) => fitsRole(m, role)));
  // a provider whose names say nothing about the role (a custom server with its own names) shows every name
  const models = fitting.length ? fitting : names(raw);
  return { models: models.slice(0, LIST_MAX_MODELS) };
}
