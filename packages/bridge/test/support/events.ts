/**
 * Bridge 0.2.7 (BRIDGE §14) test support: manifests that declare events, synthetic tables for the EventStore unit tests, and
 * the app / agent side of the end-to-end tests (signed `POST /tb/v1/events`, MCP sessions, the SSE stream of `GET /mcp`).
 */
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type ManifestApi, manifestApi } from "@opt2-tealbrick/relay";
import type { AppEntry } from "@opt2-tealbrick/spec/bridge";
import type { GrantClaims } from "@opt2-tealbrick/spec/credentials";
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import type { Ed25519KeyPair } from "@opt2-tealbrick/spec/sdk";
import { eventHookMatches } from "../../src/calls.ts";
import { EventStore } from "../../src/events.ts";
import type { AppRuntime, Table } from "../../src/table.ts";
import { silentLogger } from "../../src/util.ts";
import { BRG, INS, notesManifest, type World, WS } from "./world.ts";

export const PAYLOAD = { type: "object", additionalProperties: false, required: ["n"], properties: { n: { type: "integer" } } };

export const op = (id: string, crud: string[], effect: string, extra: Record<string, unknown> = {}) => ({
  id,
  title: id,
  description: `Test op ${id}`,
  input: { type: "object" },
  output: { type: "object" },
  crud,
  effect,
  idempotency: "none",
  receipt: effect !== "read",
  audience: "agent",
  ...extra,
});

export const ev = (name: string, visibleWith: string, audience: "granted" | "target" = "granted") => ({ name, title: name, payloadSchema: PAYLOAD, visibleWith, audience });

/**
 * The notes manifest with events: `note.created` (unscoped, granted, visible with notes_list), `note.pinged` (target),
 * `note.shared` (scoped: notes_s_read, read), `note.edited` (scoped: notes_s_update, update), `note.deleted` (unscoped,
 * notes_delete: crud delete).
 */
export function eventsManifest(version = "2.0.0", extraOps: unknown[] = [], extraEvents: unknown[] = []): Record<string, unknown> {
  return {
    ...notesManifest,
    version,
    operations: [...notesManifest.operations, op("notes_s_read", ["read"], "read", { scopeType: "notebook" }), op("notes_s_update", ["update"], "write", { scopeType: "notebook" }), ...extraOps],
    events: [ev("note.created", "notes_list"), ev("note.pinged", "notes_list", "target"), ev("note.shared", "notes_s_read"), ev("note.edited", "notes_s_update"), ev("note.deleted", "notes_delete"), ...extraEvents],
  };
}

let seq = 0;
/** one emit item (defaults: note.created, subject note/n1, data {n}) */
export function item(o: { name?: string; n?: number; data?: unknown; key?: string; to?: string[]; instanceId?: string; eligible?: { agent: string; authority: string }[]; causedBy?: string; summary?: string; [k: string]: unknown } = {}): Record<string, unknown> {
  const { name, n, data, key, ...rest } = o;
  seq += 1;
  return { kind: "emit", key: key ?? `key-${Date.now()}-${seq}`, name: name ?? "note.created", at: new Date().toISOString(), subject: { kind: "note", id: "n1" }, data: data ?? { n: n ?? 0 }, ...rest };
}

// ── synthetic tables (EventStore unit tests) ──────────────────────────────────────────────────────────────────────────

export const api: ManifestApi = manifestApi();

export function runtime(ins: string, product: string, manifest: Record<string, unknown>, entry: Partial<AppEntry> = {}): AppRuntime {
  const m = manifest as unknown as Manifest;
  const digest = api.manifestDigest(m);
  return {
    entry: { ins, product, version: String(manifest.version ?? "1.0.0"), sdkMajor: 1, manifestDigest: digest, internalUrl: "http://127.0.0.1:1", ownInfra: true, entitled: true, slice: "", ...entry } as AppEntry,
    manifest: m,
    digest,
    ops: new Map(api.withStandardOps(m).map((o) => [o.id, o])),
    scopeTypes: (m.scopes ?? []).map((s) => s.type),
    down: false,
    declaredHooks: m.hooks ?? [],
  };
}

export interface GrantSpec {
  agent: string;
  ins: string;
  crud?: string[];
  mode?: "free" | "bound";
  wf?: string[];
  /** epoch s */
  exp?: number;
}

export function table(o: { apps: AppRuntime[]; grants: GrantSpec[]; agents: string[]; pausedInstances?: string[]; pausedAgents?: string[]; pausedWorkspace?: boolean; hooks?: Table["hooks"]; rev?: number }): Table {
  const grants: Table["grants"] = new Map();
  for (const g of o.grants) {
    const claims = { iss: "tb:portal", sub: `tb:agt:${g.agent}`, aud: `tb:ins:${g.ins}`, iat: 0, exp: g.exp ?? Math.floor(Date.now() / 1000) + 30 * 86_400, jti: api.ulid(), ws: WS, cnf: { brg: BRG }, crud: g.crud ?? ["read", "create"], mode: g.mode ?? "free", held: [], caps: {}, wf: g.wf ?? [], polrev: 1 } as unknown as GrantClaims;
    grants.set(`tb:agt:${g.agent}|tb:ins:${g.ins}`, { token: "x", claims });
  }
  return {
    config: {} as Table["config"],
    jws: "",
    rev: o.rev ?? 1,
    exp: Math.floor(Date.now() / 1000) + 3600,
    ws: WS as Table["ws"],
    bridgeId: BRG as Table["bridgeId"],
    issuers: { keys: [] },
    bridgeKeys: { keys: [] },
    agents: new Map(o.agents.map((a) => [a, { agt: a, name: a, mode: "free" }])) as Table["agents"],
    connections: new Map(),
    apps: new Map(o.apps.map((a) => [a.entry.ins, a])),
    appsByProduct: new Map(o.apps.map((a) => [a.entry.product, a])),
    grants,
    instanceKeys: new Map(),
    hooks: o.hooks ?? [],
    revokedJtis: new Set(),
    pausedAgents: new Set(o.pausedAgents ?? []) as Table["pausedAgents"],
    pausedInstances: new Set(o.pausedInstances ?? []) as Table["pausedInstances"],
    pausedWorkspace: o.pausedWorkspace ?? false,
    standalone: false,
  };
}

/** A store on a fresh temp file (the caller closes it). */
export function openStore(dir = mkdtempSync(join(tmpdir(), "tb-events-test-"))): { store: EventStore; dir: string; path: string } {
  const path = join(dir, "events.db");
  return { store: new EventStore({ path, log: silentLogger, digestOf: (m) => api.manifestDigest(m), hookMatches: eventHookMatches }), dir, path };
}

// ── end-to-end: the app side and the agent side ───────────────────────────────────────────────────────────────────────

const nowS = () => Math.floor(Date.now() / 1000);

export async function postEvents(w: World, key: Ed25519KeyPair, items: unknown[], o: { svc?: string; raw?: Buffer; ins?: string } = {}): Promise<{ status: number; json: any; headers: Headers }> {
  const path = "/tb/v1/events";
  const ins = o.ins ?? INS;
  const body = o.raw ?? Buffer.from(JSON.stringify({ items }));
  const assertion = await w.api.signAssertion(
    "tb-instance-assert+jwt",
    { iss: `tb:ins:${ins}`, sub: `tb:ins:${ins}`, aud: `tb:brg:${BRG}`, iat: nowS(), exp: nowS() + 60, jti: w.api.ulid(), ...(o.svc ? { svc: o.svc } : {}) },
    key,
    { method: "POST", pathAndQuery: path, body },
  );
  const r = await fetch(`${w.internalUrl}${path}`, { method: "POST", headers: { "content-type": "application/json", "TB-Assert": assertion }, body: new Uint8Array(body) });
  const text = await r.text();
  let json: unknown = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = text;
  }
  return { status: r.status, json, headers: r.headers };
}

export interface SseFrame {
  id?: string;
  msg: any;
}

export interface Listener {
  frames: SseFrame[];
  ready: Promise<void>;
  close(): void;
  /** resolves when a frame matches, rejects after `ms` */
  until(pred: (f: SseFrame) => boolean, ms?: number): Promise<SseFrame>;
}

export interface Agent {
  sid: string;
  token: string;
  rpc(method: string, params?: unknown): Promise<any>;
  listen(lastEventId?: string): Listener;
}

export async function agentSession(w: World, agt: string, con: string): Promise<Agent> {
  const token = await w.agentTokenFor(agt, con);
  const init = await w.mcp(token, { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "events-test" } } });
  const sid = init.session as string;
  let id = 10;
  return {
    sid,
    token,
    rpc: async (method, params) => (await w.mcp(token, { jsonrpc: "2.0", id: id++, method, ...(params !== undefined ? { params } : {}) }, sid)).json,
    listen: (lastEventId) => listen(w, token, sid, lastEventId),
  };
}

function listen(w: World, token: string, sid: string, lastEventId?: string): Listener {
  const ac = new AbortController();
  const frames: SseFrame[] = [];
  let onReady: () => void = () => undefined;
  const ready = new Promise<void>((r) => {
    onReady = r;
  });
  void (async () => {
    const r = await fetch(`${w.publicUrl}/mcp`, { headers: { authorization: `Bearer ${token}`, "mcp-session-id": sid, accept: "text/event-stream", ...(lastEventId ? { "last-event-id": lastEventId } : {}) }, signal: ac.signal });
    const reader = (r.body as ReadableStream<Uint8Array>).getReader();
    let buf = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      onReady();
      buf += Buffer.from(value).toString("utf8");
      for (let i = buf.indexOf("\n\n"); i >= 0; i = buf.indexOf("\n\n")) {
        const block = buf.slice(0, i);
        buf = buf.slice(i + 2);
        let fid: string | undefined;
        let data = "";
        for (const line of block.split("\n")) {
          if (line.startsWith("id: ")) fid = line.slice(4);
          else if (line.startsWith("data: ")) data += line.slice(6);
        }
        if (data) frames.push({ ...(fid !== undefined ? { id: fid } : {}), msg: JSON.parse(data) });
      }
    }
  })().catch(() => undefined);
  return {
    frames,
    ready,
    close: () => ac.abort(),
    until: async (pred, ms = 3000) => {
      const end = Date.now() + ms;
      for (;;) {
        const f = frames.find(pred);
        if (f) return f;
        if (Date.now() > end) throw new Error(`no matching frame within ${ms} ms (frames: ${JSON.stringify(frames).slice(0, 400)})`);
        await new Promise((r) => setTimeout(r, 20));
      }
    },
  };
}

/** the `n` of an event's data */
export const nOf = (e: { data?: { n?: unknown } }): unknown => e.data?.n;
