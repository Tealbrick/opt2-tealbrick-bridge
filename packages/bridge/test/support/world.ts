/**
 * Test world: a fake Portal (enrol, config long-poll, ack), a fake app (SDK routes) and a real
 * deployed bridge started on free ports with the manifest test double.
 */
import { webcrypto } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer, type IncomingHttpHeaders, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo, Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { signKeySetStatement } from "@opt2-tealbrick/manifest";
import { type ManifestApi, manifestApi } from "@opt2-tealbrick/relay";
import type { StatusReport, WorkspaceConfig } from "@opt2-tealbrick/spec/bridge";
import type { Ed25519KeyPair } from "@opt2-tealbrick/spec/sdk";
import type { McpLimits } from "../../src/mcp.ts";
import { type ListenerLimits, type RunningBridge, startBridge } from "../../src/server.ts";
import { type Logger, pathOf, silentLogger } from "../../src/util.ts";
import type { ViewsLimits } from "../../src/views-shared.ts";
import { fakeApi } from "./fake-api.ts";

export const WS = "ws_01HZZZZZZZZZZZZZZZZZZZZZZZ";
export const BRG = "brg_01HZZZZZZZZZZZZZZZZZZZZZZZ";
export const AGT = "agt_01HAAAAAAAAAAAAAAAAAAAAAAA";
export const AGT2 = "agt_01HBBBBBBBBBBBBBBBBBBBBBBB";
export const CON = "con_01HAAAAAAAAAAAAAAAAAAAAAAA";
export const INS = "ins_01HNNNNNNNNNNNNNNNNNNNNNNN";
export const HOOKINS = "ins_01HHHHHHHHHHHHHHHHHHHHHHHH";
export const ENROL = "tbe_testenrolmentcode";
export const APP_CODE = "tbe_appinstancecode";
export const SVC_CODE = "tbe_servicecodeforengine";

const now = () => Math.floor(Date.now() / 1000);

const example = JSON.parse(readFileSync(fileURLToPath(import.meta.resolve("@opt2-tealbrick/spec/examples/notes.manifest.json")), "utf8"));
const { companions: _c, unlocks: _u, hooks: _h, ...exampleBase } = example;
const op = (id: string, crud: string[], effect: string, extra: Record<string, unknown> = {}) => ({
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

/** Valid manifests (spec example as the base) so the real validator accepts them. */
export const notesManifest = {
  ...exampleBase,
  id: "notes",
  operations: [
    op("notes_list", ["read"], "read"),
    op("notes_create", ["create"], "write", { idempotency: "required" }),
    op("notes_send", ["create"], "outward", { idempotency: "required" }),
    op("notes_delete", ["delete"], "destructive", { holdFamily: "destructive" }),
    op("notes_admin", ["read"], "read", { audience: "person" }),
  ],
  settings: { ...example.settings, keys: [{ name: "NOTES_API_KEY", label: "Notes key", provider: "Example", required: true, source: "account_default", usedBy: ["app"] }, { name: "NOTES_EXTRA_KEY", label: "Extra key", provider: "Example", required: false, source: "account_default", usedBy: ["app"] }] },
  publicRoutes: [{ path: "/oauth/callback", purpose: "oauth_callback" }],
  skills: [],
  ui: { launchPath: "/", configurePath: "/configure" },
};

export const hookManifest = {
  ...exampleBase,
  id: "guard",
  name: "Guard",
  operations: [op("guard_status", ["read"], "read")],
  scopes: [],
  skills: [],
  publicRoutes: [],
  hooks: [
    { id: "check", title: "Check", phase: "before", order: 1, match: { products: ["notes"] } },
    { id: "enrich", title: "Enrich", phase: "context", order: 2, match: { products: ["notes"] } },
    { id: "audit", title: "Audit", phase: "after", order: 3, match: { products: ["notes"] } },
  ],
};

export interface AppLog {
  ops: { op: string; auth: string | undefined; proof: string | undefined; body: Record<string, unknown> }[];
  /** every hook request the guard app received: the parsed body, the EXACT bytes and the `TB-Call` proof */
  hooks: { hook: string; body: Record<string, unknown>; raw: Buffer; proof: string | undefined }[];
}

export interface World {
  bridge: RunningBridge;
  publicUrl: string;
  /** key page origin (different host name, same port) */
  keysUrl: string;
  internalUrl: string;
  portalKid: string;
  api: ManifestApi;
  agentKey: Ed25519KeyPair;
  real: boolean;
  agentAssertion(agt: string, con: string): Promise<string>;
  signRaw(input: string): Promise<string>;
  acks: StatusReport[];
  appLog: AppLog;
  hookMode: { mode: "allow" | "deny" | "fail"; /** answer every hook request with this HTTP status and no body (a 401 test) */ status?: number; answer?: (hook: string, body: Record<string, unknown>) => unknown | Promise<unknown> };
  /** publish a new config revision (tweak: mutate THIS revision only) */
  publish(tweak?: (c: WorkspaceConfig) => void): Promise<number>;
  /** change the base config for every later revision (what Core keeps listing), then publish */
  amend(change: (c: WorkspaceConfig) => void): Promise<number>;
  rev(): number;
  close(): Promise<void>;
  /** stop the bridge process and start a new one on the same volume and ports */
  restart(): Promise<void>;
  /** the bridge's listener ports (kept across restarts) */
  ports: { public: number; internal: number };
  /** the env the bridge runs with (F57a: c023 starts the bridge as a real process with it) */
  bridgeEnv(): NodeJS.ProcessEnv;
  dataDir: string;
  pulls(): number;
  setAckFails(on: boolean): void;
  /** the app is updated: serves a new manifest (new digest) and fails its next `failures` manifest fetches */
  updateApp(failures: number): string;
  /** the app is updated to exactly this manifest (validity not checked); returns the digest the config lists */
  updateAppTo(manifest: Record<string, unknown>, failures?: number): string;
  rotateKey(phase: "announce" | "activate" | "retire"): Promise<void>;
  /** BSD-08 worlds (`keySet: true`): the test root, the current statement and its controls */
  keySet: {
    root: Ed25519KeyPair | undefined;
    current(): string | undefined;
    /** sign a statement over `keys` (default: the world's key entries) with seq + 1 (or `seq`) and make it current */
    bump(o?: { keys?: { key: Ed25519KeyPair; status: "pending" | "active" | "retired" }[]; seq?: number; root?: Ed25519KeyPair }): Promise<string>;
    /** what the enrolment response carries: the current statement, none, or a given JWS */
    enrol(mode: "current" | "none" | { jws: string }): void;
  };
  /** sign the next published configs with this key (default: the world's active Portal key) */
  setSigningKey(key: Ed25519KeyPair): void;
  /** bridge env overrides applied on the next restart */
  setEnv(k: string, v: string): void;
  /** serve a document signed by an untrusted key as the next revision */
  serveForged(): Promise<void>;
  configPulls(): number;
  /** stop answering as Portal (simulates Portal down) */
  portalDown(): void;
  rejectedBridgeAssertions(): number;
  agentToken(): Promise<string>;
  mcp(token: string, body: unknown, session?: string): Promise<{ status: number; json: any; session: string | null }>;
  signPortal(typ: string, claims: object): Promise<string>;
  /** like signPortal but WITHOUT the library's claim check: a token the library itself would refuse to sign (a malformed claim, GRANT-PRD tests) */
  signPortalUnchecked(typ: string, claims: object): Promise<string>;
  /** access token for any connection of the config (key method, the world's agent key) */
  agentTokenFor(agt: string, con: string): Promise<string>;
  /** requests the bridge's public listener received on this path, across restarts (failure diagnostics) */
  publicRequests(path: string): number;
  /** LA-1: the fake notes app's viewer route (`GET /v/notes/…`): every request it received, and the handler that answers (404 when none) */
  viewer: { seen: { url: string; headers: IncomingHttpHeaders }[]; handler?: (req: IncomingMessage, res: ServerResponse) => void };
  /** test hook in the fake app's op route: return true when it answered the request itself */
  appOps: { override?: (op: string, body: Record<string, unknown>, res: ServerResponse) => boolean };
  /**
   * the fake app's bridge-op route (`/tb/v1/bridge/<catalog|resolve|mark|scope-summary>`): every body it received (with the
   * TB-Call proof) and the handler that answers (`[]` when none)
   */
  bridgeOps: { seen: { path: string; body: any; proof: string | undefined }[]; answer?: (path: string, body: any) => unknown; /** answer every bridge op with this HTTP status and no body */ status?: number };
}

export interface WorldOptions {
  /** bridge logger (default: silent) */
  logger?: Logger;
  withHook?: boolean;
  real?: boolean;
  manifestFailures?: number;
  /** bridge env overrides (e.g. an https TB_PUBLIC_URL) */
  env?: Record<string, string>;
  limits?: Partial<ListenerLimits> & { mcp?: Partial<McpLimits>; views?: Partial<ViewsLimits> };
  /** extra key connections of the first agent */
  extraConnections?: string[];
  /** BSD-08: a test root signs key-set statements; the bridge pins it (start option) and Portal sends them.
   * Default on: every bridge needs a root-signed statement (C133, no transition path). */
  keySet?: boolean;
  /** the first enrolment response carries no statement */
  enrolWithoutKeySet?: boolean;
  /** replaces the roots the bridge pins (default: the test root); `[]` = a build without pinned roots */
  portalRoots?: Ed25519KeyPair["publicJwk"][];
  /** further own-infrastructure origins for TB_OWN_INFRA_ORIGINS (e.g. a real SDK app started by a test) */
  extraOwnInfraOrigins?: string[];
  /** BRG-29: the bridge form (default: the startBridge default, deployed) */
  form?: "deployed" | "own_infra";
  /**
   * C171: by default both test listeners bind 127.0.0.1 (TB_PUBLIC_HOST / TB_INTERNAL_HOST), so no other program on
   * this machine bound to a wildcard or 127.0.0.1 port can shadow the test bridge. true = leave both unset (tests of
   * the per-form defaults).
   */
  formDefaultHosts?: boolean;
  /** spec 0.1.73 BRIDGE §7.5: run the lazy-tools path although the pinned validator predates it (start option, test only) */
  lazyTools?: boolean;
}

async function listen(handler: (req: IncomingMessage, res: ServerResponse) => void): Promise<{ server: Server; url: string }> {
  const server = createServer(handler);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return { server, url: `http://127.0.0.1:${(server.address() as AddressInfo).port}` };
}

async function body(req: IncomingMessage): Promise<any> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  const t = Buffer.concat(chunks).toString("utf8");
  return t ? JSON.parse(t) : undefined;
}

export async function makeWorld(opts: WorldOptions = {}): Promise<World> {
  let manifestFailures = opts.manifestFailures ?? 0;
  let servedManifest: Record<string, unknown> = notesManifest;
  const real = !!opts.real;
  const api = real ? manifestApi() : fakeApi();
  const portalKey = await api.generateKeyPair();
  const agentKey = await api.generateKeyPair();
  const acks: StatusReport[] = [];
  const appLog: AppLog = { ops: [], hooks: [] };
  const hookMode: World["hookMode"] = { mode: "allow" };
  const appOps: World["appOps"] = {};
  const bridgeOps: World["bridgeOps"] = { seen: [] };
  const viewer: World["viewer"] = { seen: [] };
  let down = false;
  let pulls = 0;
  let ackFails = false;
  let assertFailures = 0;
  // every key that enrolled stays accepted: like conformance B20, a re-enrolment the bridge refuses (C63a) must not
  // cut the old identity off in this fake Portal
  const bridgeJwks: Ed25519KeyPair["publicJwk"][] = [];
  let configJws = "";
  let rev = 0;
  let signingKey = portalKey;
  let keyEntries: { key: Ed25519KeyPair; status: "pending" | "active" | "retired" }[] = [{ key: portalKey, status: "active" }];
  const sign = (typ: string, claims: object) => api.signJws(typ as never, claims, signingKey);
  // C133: a bridge refuses any body without a root-signed statement, so every world runs with a test root by default
  // (keySet: false only for a world that must have none). The root is a real Ed25519 key also in test-double worlds:
  // the double applies the real key-set rule (L1) to statements that list its portal keys.
  const keySetOn = opts.keySet ?? true;
  const root = keySetOn ? await (real ? api : manifestApi()).generateKeyPair() : undefined;
  let kssSeq = 0;
  let kss: string | undefined;
  let enrolKss: "current" | "none" | { jws: string } = opts.enrolWithoutKeySet ? "none" : "current";
  const envOverrides: Record<string, string> = {};
  const signKss = async (o: { keys?: typeof keyEntries; seq?: number; root?: Ed25519KeyPair } = {}): Promise<string> => {
    const r = o.root ?? root;
    if (!r) throw new Error("not a keySet world");
    const seq = o.seq ?? kssSeq + 1;
    const jws = await signKeySetStatement({ iss: "tb:portal-root", aud: "tb:portal-keys", seq, iat: now(), keys: (o.keys ?? keyEntries).map((k) => ({ jwk: k.key.publicJwk, status: k.status })) } as never, r);
    return jws;
  };
  if (root) {
    kss = await signKss();
    kssSeq = 1;
  }

  // ── fake app (notes) and hook app (guard) ──
  const app = await listen(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://x");
    if (url.pathname === "/tb/v1/manifest") {
      if (manifestFailures > 0) {
        manifestFailures -= 1;
        return res.writeHead(503).end();
      }
      return res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(servedManifest));
    }
    if (url.pathname.startsWith("/tb/v1/ops/")) {
      const op = url.pathname.slice(11);
      const b = await body(req);
      appLog.ops.push({ op, auth: req.headers.authorization, proof: req.headers["tb-call"] as string | undefined, body: b });
      if (appOps.override?.(op, b, res)) return;
      if (op === "notes_send") return res.writeHead(202, { "content-type": "application/json" }).end(JSON.stringify({ status: "held", holdId: "hold_1", expiresAt: new Date(Date.now() + 900_000).toISOString() }));
      if (op === "tb.hold_status") return res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ status: "ok", output: { status: "pending" } }));
      return res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ status: "ok", output: { op, secret: "s3cret", items: [1, 2] } }));
    }
    if (url.pathname.startsWith("/tb/v1/bridge/")) {
      const b = await body(req);
      const path = url.pathname.slice(14);
      bridgeOps.seen.push({ path, body: b, proof: req.headers["tb-call"] as string | undefined });
      if (bridgeOps.status !== undefined) return res.writeHead(bridgeOps.status).end();
      const custom = bridgeOps.answer?.(path, b);
      return res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(custom !== undefined ? custom : []));
    }
    if (url.pathname.startsWith("/v/notes/")) {
      viewer.seen.push({ url: req.url ?? "", headers: req.headers });
      if (viewer.handler) return viewer.handler(req, res);
      return res.writeHead(404).end();
    }
    if (url.pathname.startsWith("/a/notes/") || url.pathname.startsWith("/p/notes/")) {
      const b = req.method === "POST" ? await new Promise<string>((r) => { let s = ""; req.on("data", (c) => (s += c)); req.on("end", () => r(s)); }) : "";
      return res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ path: url.pathname, auth: req.headers.authorization ?? null, tb: req.headers["tb-call"] ?? null, body: b }));
    }
    res.writeHead(404).end();
  });
  // WebSocket upgrades: answer 101 and report the request headers the app received (base64 JSON)
  app.server.on("upgrade", (req: IncomingMessage, socket: Socket) => {
    const seen = Buffer.from(JSON.stringify(req.headers)).toString("base64url");
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: Upgrade\r\nx-seen: ${seen}\r\n\r\n`);
    socket.on("error", () => undefined);
    socket.on("end", () => socket.end());
  });
  const hookApp = await listen(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://x");
    if (url.pathname === "/tb/v1/manifest") return res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(hookManifest));
    if (url.pathname.startsWith("/tb/v1/hooks/")) {
      const chunks: Buffer[] = [];
      for await (const c of req) chunks.push(c as Buffer);
      const raw = Buffer.concat(chunks);
      const b = raw.length ? JSON.parse(raw.toString("utf8")) : undefined;
      appLog.hooks.push({ hook: url.pathname.slice(13), body: b, raw, proof: req.headers["tb-call"] as string | undefined });
      if (hookMode.status !== undefined) return res.writeHead(hookMode.status).end();
      if (hookMode.mode === "fail") return res.writeHead(500).end();
      const custom = await hookMode.answer?.(url.pathname.slice(13), b);
      if (custom !== undefined) return res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(custom));
      return res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ allow: hookMode.mode === "allow", reason: "blocked by test" }));
    }
    res.writeHead(404).end();
  });

  const brgRef = `tb:brg:${BRG}`;
  const grant = async (sub: string, crud: string[], extra: Record<string, unknown> = {}) =>
    sign("tb-grant+jwt", { iss: "tb:portal", sub, aud: `tb:ins:${INS}`, iat: now(), exp: now() + 43200, jti: api.ulid(), ws: WS, cnf: { brg: BRG }, crud, mode: "free", held: [], caps: {}, wf: [], polrev: 1, ...extra });
  const slice = await sign("tb-slice+jws", { v: 1, iss: "tb:portal", sub: `tb:ins:${INS}`, aud: `tb:ins:${INS}`, iat: now(), exp: now() + 43200, jti: api.ulid(), ws: WS, rev: 1, ins: INS, product: "notes" });
  const base: WorkspaceConfig = {
    v: 1,
    iss: "tb:portal",
    sub: brgRef as never,
    aud: brgRef as never,
    iat: now(),
    exp: now() + 43200,
    jti: api.ulid(),
    ws: WS,
    rev: 0,
    workspace: { id: WS, name: "Test workspace" },
    bridge: { id: BRG, publicUrl: "http://127.0.0.1" },
    portalKeys: [{ jwk: portalKey.publicJwk, status: "active" }],
    pause: { workspace: false, agents: [], instances: [] },
    revoked: { jtis: [] },
    connections: [CON, ...(opts.extraConnections ?? [])].map((con) => ({ con: con as never, agt: AGT as never, method: "key" as const, gen: 1, publicKey: agentKey.publicJwk, status: "active" as const })),
    instanceKeys: [],
    grants: [await grant(`tb:agt:${AGT}`, ["read", "create"])],
    apps: [
      { ins: INS as never, product: "notes", version: "1.0.0", sdkMajor: 1, manifestDigest: api.manifestDigest(notesManifest as never), internalUrl: app.url, ownInfra: true, entitled: true, slice },
      ...(opts.withHook ? [{ ins: HOOKINS as never, product: "guard", version: "1.0.0", sdkMajor: 1, manifestDigest: api.manifestDigest(hookManifest as never), internalUrl: hookApp.url, ownInfra: true, entitled: true, slice }] : []),
    ],
    agents: [
      { agt: AGT, name: "Agent One", mode: "free" },
      { agt: AGT2, name: "Agent Two", mode: "free" },
    ],
    // C117: every hook the guard manifest DECLARES is listed (a declared hook absent from config fails closed)
    hooks: opts.withHook
      ? [
          { id: "guard.check", ins: HOOKINS, product: "guard", hookId: "check", phase: "before", order: 1, timeoutMs: 1000, match: { products: ["notes"] } },
          // declared by the manifest, switched off by the owner (the guard app's test server answers before hooks only)
          { id: "guard.enrich", ins: HOOKINS, product: "guard", hookId: "enrich", phase: "context", order: 2, timeoutMs: 1000, match: { products: ["notes"] }, enabled: false },
          // an after hook, switched off the same way (hook-caller-product.test.ts switches it on)
          { id: "guard.audit", ins: HOOKINS, product: "guard", hookId: "audit", phase: "after", order: 3, timeoutMs: 1000, match: { products: ["notes"] }, enabled: false },
        ]
      : [],
    skills: { digest: "sha256:00", files: [{ product: "notes", id: "use-notes", title: "Using notes", content: "Hello {{agent.name}}" }] },
    keyRequirements: [{ name: "NOTES_API_KEY", label: "Notes key", ins: INS, product: "notes", required: true, source: "account_default", usedBy: ["app"] }],
    enrolCodes: [
      { digest: api.opaqueDigest(APP_CODE), kind: "instance", ins: INS, product: "notes", exp: now() + 3600 },
      { digest: api.opaqueDigest(SVC_CODE), kind: "service", ins: INS, service: "engine", product: "notes", exp: now() + 3600 },
    ],
  };
  const publish = async (tweak?: (c: WorkspaceConfig) => void): Promise<number> => {
    const c: WorkspaceConfig = structuredClone(base);
    const next = rev + 1;
    c.rev = next;
    c.iat = now();
    c.exp = now() + 43200;
    c.jti = api.ulid();
    if (kss) (c as { portalKeySet?: string }).portalKeySet = kss;
    tweak?.(c);
    c.portalKeys = keyEntries.map((k) => ({ jwk: k.key.publicJwk, status: k.status }));
    c.grants = await Promise.all(c.grants.map(async (g) => sign("tb-grant+jwt", JSON.parse(Buffer.from(g.split(".")[1] as string, "base64url").toString("utf8")))));
    configJws = await sign("tb-config+jws", c);
    // publish the revision only once its document is signed (a long-poll never sees rev N with document N-1)
    rev = next;
    return rev;
  };
  await publish();

  const portal = await listen(async (req, res) => {
    if (down) {
      req.socket.destroy();
      return;
    }
    const url = new URL(req.url ?? "/", "http://x");
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const raw = Buffer.concat(chunks);
    if (url.pathname === "/api/v1/bridge/enrol") {
      const b = JSON.parse(raw.toString("utf8"));
      bridgeJwks.push(b.publicKey);
      return res
        .writeHead(200, { "content-type": "application/json" })
        .end(
          JSON.stringify({
            bridgeId: BRG,
            workspaceId: WS,
            portalKeys: keyEntries.map((k) => ({ jwk: k.key.publicJwk, status: k.status })),
            ...(kss && enrolKss === "current" ? { portalKeySet: kss } : typeof enrolKss === "object" ? { portalKeySet: enrolKss.jws } : {}),
            configPath: "/api/v1/bridge/config",
            ackPath: "/api/v1/bridge/ack",
            waitMaxS: 60,
          }),
        );
    }
    const keys = bridgeJwks.length ? api.keySetFrom({ keys: bridgeJwks }, `tb:brg:${BRG}`) : { keys: [] };
    const v = api.verifyAssertion(String(req.headers["tb-assert"] ?? ""), keys, { typ: "tb-bridge-assert+jwt", aud: "tb:portal", iss: [`tb:brg:${BRG}`], now: now(), maxLifetimeS: 60, request: { method: req.method ?? "GET", pathAndQuery: req.url ?? "/", ...(raw.length ? { body: raw } : {}) } });
    if (!v.ok) {
      assertFailures += 1;
      return res.writeHead(401).end();
    }
    if (url.pathname === "/api/v1/bridge/config") {
      pulls += 1;
      const after = Number(url.searchParams.get("after"));
      const deadline = Date.now() + 300;
      while (rev <= after && Date.now() < deadline) await new Promise((r) => setTimeout(r, 25));
      if (rev > after) return res.writeHead(200, { "content-type": "application/jose" }).end(configJws);
      return res.writeHead(304).end();
    }
    if (url.pathname === "/api/v1/bridge/ack" && ackFails) return res.writeHead(503).end();
    if (url.pathname === "/api/v1/bridge/ack") {
      acks.push(JSON.parse(raw.toString("utf8")));
      return res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ accepted: true, configRevision: rev }));
    }
    res.writeHead(404).end();
  });

  const dir = mkdtempSync(join(tmpdir(), "tb-bridge-test-"));
  const loopback = opts.formDefaultHosts ? {} : { TB_PUBLIC_HOST: "127.0.0.1", TB_INTERNAL_HOST: "127.0.0.1" };
  const bridgeEnv = (): NodeJS.ProcessEnv => ({ ...loopback, TB_DATA_DIR: dir, TB_PORTAL_URL: portal.url, TB_PUBLIC_URL: "http://127.0.0.1", TB_KEYS_PUBLIC_URL: "http://localhost", TB_ENROL_CODE: ENROL, TB_KEK: "11".repeat(32), TB_OWN_INFRA_ORIGINS: [app.url, hookApp.url, ...(opts.extraOwnInfraOrigins ?? [])].join(","), ...opts.env, ...envOverrides });
  const roots = opts.portalRoots ?? (root ? [root.publicJwk] : undefined);
  const rootOpt = { ...(roots ? { portalRootKeys: roots } : {}), ...(opts.lazyTools !== undefined ? { lazyTools: opts.lazyTools } : {}) };
  let bridge: RunningBridge;
  try {
    bridge = await startBridge({
      api,
      logger: opts.logger ?? silentLogger,
      ports: { public: 0, internal: 0 },
      env: bridgeEnv(),
      ...(opts.limits ? { limits: opts.limits } : {}),
      ...(opts.form ? { form: opts.form } : {}),
      ...rootOpt,
    });
  } catch (e) {
    // a bridge that refuses to start (e.g. a refused enrolment) must not leave the fake servers running
    for (const s of [app.server, hookApp.server, portal.server]) {
      s.closeAllConnections();
      await new Promise((r) => s.close(r));
    }
    rmSync(dir, { recursive: true, force: true });
    throw e;
  }
  const seen = new Map<string, number>();
  const countRequests = (b: RunningBridge) =>
    b.publicServer.on("request", (req: IncomingMessage) => {
      const path = pathOf(req.url) ?? "(unparseable)";
      seen.set(path, (seen.get(path) ?? 0) + 1);
    });
  countRequests(bridge);
  const publicUrl = `http://127.0.0.1:${(bridge.publicServer.address() as AddressInfo).port}`;
  const keysUrl = `http://localhost:${(bridge.publicServer.address() as AddressInfo).port}`;
  const internalUrl = `http://127.0.0.1:${(bridge.internalServer.address() as AddressInfo).port}`;
  // wait for the first config
  for (let i = 0; i < 100 && !bridge.ctx.table; i++) await new Promise((r) => setTimeout(r, 20));

  const agentAssertion = (agt: string, con: string) => api.signAssertion("tb-agent-assert+jwt", { iss: `tb:agt:${agt}`, sub: `tb:agt:${agt}`, aud: brgRef, iat: now(), exp: now() + 60, jti: api.ulid(), con }, agentKey);
  const signRaw = async (input: string): Promise<string> =>
    real ? Buffer.from(await crypto.subtle.sign("Ed25519", agentKey.privateKey, new TextEncoder().encode(input))).toString("base64url") : `sig-${agentKey.kid}`;
  const agentTokenFor = async (agt: string, con: string) => {
    const assertion = await agentAssertion(agt, con);
    const r = await fetch(`${publicUrl}/oauth/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion }) });
    const j = (await r.json()) as { access_token: string };
    return j.access_token;
  };
  const agentToken = () => agentTokenFor(AGT, CON);
  const mcp = async (token: string, b: unknown, session?: string) => {
    const r = await fetch(`${publicUrl}/mcp`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${token}`, ...(session ? { "mcp-session-id": session } : {}) }, body: JSON.stringify(b) });
    const text = await r.text();
    return { status: r.status, json: text ? JSON.parse(text) : undefined, session: r.headers.get("mcp-session-id") };
  };

  const ports = { public: (bridge.publicServer.address() as AddressInfo).port, internal: (bridge.internalServer.address() as AddressInfo).port };
  const world: World = {
    bridge,
    ports,
    bridgeEnv,
    publicUrl,
    keysUrl,
    internalUrl,
    portalKid: portalKey.kid,
    api,
    agentKey,
    real,
    agentAssertion,
    signRaw,
    acks,
    appLog,
    hookMode,
    publish,
    rev: () => rev,
    agentToken,
    agentTokenFor,
    appOps,
    bridgeOps,
    viewer,
    publicRequests: (path) => seen.get(path) ?? 0,
    mcp,
    signPortal: sign,
    signPortalUnchecked: async (typ, claims) => {
      const enc = (v: unknown) => Buffer.from(JSON.stringify(v), "utf8").toString("base64url");
      const input = `${enc({ alg: "EdDSA", typ, kid: signingKey.kid })}.${enc(claims)}`;
      const sig = Buffer.from(await webcrypto.subtle.sign({ name: "Ed25519" }, signingKey.privateKey, Buffer.from(input, "ascii"))).toString("base64url");
      return `${input}.${sig}`;
    },
    async amend(change) {
      change(base);
      return publish();
    },
    async serveForged() {
      const stranger = await api.generateKeyPair();
      const c = JSON.parse(Buffer.from(configJws.split(".")[1] as string, "base64url").toString("utf8"));
      configJws = await api.signJws("tb-config+jws" as never, { ...c, rev: rev + 1, jti: api.ulid() }, stranger);
      rev += 1;
    },
    configPulls: () => pulls,
    async rotateKey(phase) {
      if (phase === "announce") keyEntries.push({ key: await api.generateKeyPair(), status: "pending" });
      if (phase === "activate") {
        const next = keyEntries.find((k) => k.status === "pending");
        if (!next) throw new Error("no pending key");
        for (const k of keyEntries) if (k.status === "active") k.status = "retired";
        next.status = "active";
        signingKey = next.key;
      }
      if (phase === "retire") keyEntries = keyEntries.filter((k) => k.status !== "retired");
      if (root) {
        kss = await signKss();
        kssSeq += 1;
      }
    },
    keySet: {
      root,
      current: () => kss,
      async bump(o = {}) {
        const jws = await signKss(o);
        kss = jws;
        kssSeq = o.seq ?? kssSeq + 1;
        return jws;
      },
      enrol(mode) {
        enrolKss = mode;
      },
    },
    setSigningKey(key) {
      signingKey = key;
    },
    setEnv(k, v) {
      envOverrides[k] = v;
    },
    updateAppTo(manifest, failures = 0) {
      servedManifest = manifest;
      manifestFailures = failures;
      let d: string;
      try {
        d = api.manifestDigest(manifest as never);
      } catch {
        d = `sha256:${"0".repeat(64)}`;
      }
      base.apps[0] = { ...(base.apps[0] as WorkspaceConfig["apps"][number]), version: String(manifest.version ?? "9.9.9"), manifestDigest: d as never };
      return d;
    },
    updateApp(failures) {
      servedManifest = { ...notesManifest, version: "1.0.1" };
      manifestFailures = failures;
      const d = api.manifestDigest(servedManifest as never);
      base.apps[0] = { ...(base.apps[0] as WorkspaceConfig["apps"][number]), version: "1.0.1", manifestDigest: d };
      return d;
    },
    async restart() {
      // stop() is idempotent: the bridge may already be stopped (a drain ends with stop)
      await bridge.stop();
      bridge = await startBridge({ api, logger: opts.logger ?? silentLogger, ports, env: bridgeEnv(), ...(opts.limits ? { limits: opts.limits } : {}), ...(opts.form ? { form: opts.form } : {}), ...rootOpt });
      countRequests(bridge);
      world.bridge = bridge;
    },
    dataDir: dir,
    pulls: () => pulls,
    setAckFails(on) {
      ackFails = on;
    },
    portalDown() {
      down = true;
      portal.server.closeAllConnections();
    },
    rejectedBridgeAssertions: () => assertFailures,
    async close() {
      // the temp dir goes even when a stop fails (no tb-bridge-test-* left behind)
      try {
        await bridge.stop();
        for (const s of [app.server, hookApp.server, portal.server]) {
          s.closeAllConnections();
          await new Promise((r) => s.close(r));
        }
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    },
  };
  return world;
}

export async function waitFor(cond: () => boolean, ms = 10000): Promise<void> {
  const end = Date.now() + ms;
  while (!cond()) {
    if (Date.now() > end) throw new Error("timeout waiting for condition");
    await new Promise((r) => setTimeout(r, 20));
  }
}
