/**
 * TEST DOUBLE of @opt2-tealbrick/manifest for bridge unit/integration tests until the real package
 * is released. It is NOT crypto: "signatures" are the signer's kid, so tests exercise the bridge's
 * own logic (claim checks, routing, state) — never ship or import this outside test/.
 */
import { createHash, randomBytes } from "node:crypto";
import * as realManifest from "@opt2-tealbrick/manifest";
import { isPrivateInternalUrl as realIsPrivateInternalUrl } from "@opt2-tealbrick/manifest";
import type { ManifestApi } from "@opt2-tealbrick/relay";

const b64 = (v: unknown) => Buffer.from(JSON.stringify(v)).toString("base64url");
const unb64 = (s: string) => JSON.parse(Buffer.from(s, "base64url").toString("utf8"));
const sortKeys = (v: unknown): unknown =>
  Array.isArray(v) ? v.map(sortKeys) : v && typeof v === "object" ? Object.fromEntries(Object.keys(v as object).sort().map((k) => [k, sortKeys((v as Record<string, unknown>)[k])])) : v;
const sha = (s: string | Uint8Array) => `sha256:${createHash("sha256").update(s).digest("hex")}` as const;
const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

export function fakeKey(): { publicJwk: { kty: "OKP"; crv: "Ed25519"; x: string }; privateKey: CryptoKey; kid: string } {
  const x = randomBytes(32).toString("base64url");
  return { publicJwk: { kty: "OKP", crv: "Ed25519", x }, privateKey: { fake: x } as unknown as CryptoKey, kid: `kid-${x.slice(0, 20)}` };
}

type Refusal = { ok: false; code: string; reason: string };
const refuse = (code: string, reason = code): Refusal => ({ ok: false, code, reason });

function verify(token: string, keys: { keys: { jwk: { x: string }; status: string }[] }, expect: { typ: string; aud: string; iss: readonly string[]; now: number; maxLifetimeS: number }) {
  const parts = token.split(".");
  if (parts.length !== 3) return refuse("invalid_token");
  let header: { typ: string; kid: string };
  let claims: Record<string, unknown>;
  try {
    header = unb64(parts[0] as string);
    claims = unb64(parts[1] as string);
  } catch {
    return refuse("invalid_token");
  }
  if (header.typ !== expect.typ) return refuse("invalid_token", "typ");
  const key = keys.keys.find((k) => `kid-${k.jwk.x.slice(0, 20)}` === header.kid && k.status !== "retired_x");
  if (!key || parts[2] !== `sig-${header.kid}`) return refuse("invalid_token", "sig");
  if (claims.aud !== expect.aud) return refuse("invalid_token", "aud");
  if (!expect.iss.includes(claims.iss as string)) return refuse("invalid_token", "iss");
  const iat = claims.iat as number;
  const exp = claims.exp as number;
  if (!(iat <= expect.now + 30 && expect.now < exp + 30 && exp - iat <= expect.maxLifetimeS)) return refuse("invalid_token", "time");
  return { ok: true as const, header: { typ: header.typ as never, kid: header.kid }, claims: claims as never };
}

export function fakeApi(): ManifestApi {
  const api: ManifestApi = {
    canonicalize: (v) => JSON.stringify(sortKeys(v)),
    digest: (v) => sha(JSON.stringify(sortKeys(v))),
    validateManifest: (json) => ({ ok: true, manifest: json as never, digest: sha(JSON.stringify(sortKeys(json))) }),
    manifestDigest: (m) => sha(JSON.stringify(sortKeys(m))),
    withStandardOps: (m) => [
      ...m.operations.map((o) => ({ ...o, standard: false as const })),
      { standard: true as const, id: "tb.hold_status", title: "Hold status", crud: ["read"], effect: "read", audience: "agent", idempotency: "none", receipt: false },
    ],
    generateKeyPair: async () => fakeKey(),
    thumbprint: (jwk) => `kid-${jwk.x.slice(0, 20)}`,
    keySetFrom: (jwks, issuer) => ({ keys: jwks.keys.map((jwk) => ({ jwk, status: "active" as const, issuer })) }),
    signJws: async (typ, claims, key) => `${b64({ alg: "EdDSA", typ, kid: key.kid })}.${b64(claims)}.sig-${key.kid}`,
    verifyJws: (token, keys, expect) => verify(token, keys, expect),
    verifyGrant: (token, ctx) => {
      const v = verify(token, ctx.issuers, { typ: "tb-grant+jwt", aud: ctx.self, iss: ["tb:portal", `tb:brg:${ctx.bridge}`], now: ctx.now, maxLifetimeS: 43200 });
      if (!v.ok) return refuse("grant_invalid");
      const c = v.claims as Record<string, unknown> & { cnf: { brg: string }; jti: string; sub: string };
      if (c.ws !== ctx.ws) return refuse("grant_invalid");
      if (c.cnf?.brg !== ctx.bridge) return refuse("grant_invalid");
      if (ctx.revokedJtis.has(c.jti)) return refuse("grant_revoked");
      const caller = c.sub.startsWith("tb:agt:") ? { type: "agent" as const, id: c.sub.slice(7) as never } : { type: "app" as const, id: c.sub.slice(7) as never };
      return { ok: true, token, claims: c as never, caller };
    },
    verifyConfig: (token, ctx) => {
      const v = verify(token, ctx.issuers, { typ: "tb-config+jws", aud: ctx.self, iss: ["tb:portal"], now: ctx.now, maxLifetimeS: 43200 });
      return v.ok ? { ok: true, claims: v.claims, body: v.claims } : v;
    },
    renderSkill: (_s, body, vars) => body.replaceAll("{{agent.name}}", vars.agent?.name ?? "").replaceAll("{{agent.id}}", vars.agent?.id ?? ""),
    gate: (input) => {
      if (input.paused.workspace || input.paused.agent || input.paused.connection || input.paused.instance) return { decision: "refuse", reason: "paused" };
      const g = api.verifyGrant(input.grant, input.trust);
      if (!g.ok) return { decision: "refuse", reason: g.code };
      if (input.op.standard && input.op.id === "tb.hold_status") return { decision: "pass", reason: "ok" };
      // manifest 0.1.27 (C283 A1): an op WITH a scopeType skips the crud ceiling here (the SDK enforces it); unscoped and standard ops keep it
      if ((input.op.standard || !input.op.scopeType) && !input.op.crud.every((c) => g.claims.crud.includes(c))) return { decision: "refuse", reason: "crud_exceeds_grant" };
      if (input.op.audience !== "agent") return { decision: "refuse", reason: "audience_not_agent" };
      if (!input.op.standard && input.op.scopeType && !input.declaredScopeTypes.includes(input.op.scopeType)) return { decision: "refuse", reason: "scope_type_unknown" };
      if (!realManifest.opInGrantWorkflow(g.claims, input.op.id, input.op.standard ? undefined : input.op.listing)) return { decision: "refuse", reason: "not_in_workflow" };
      return { decision: "pass", reason: "ok" };
    },
    // L1: the listing and workflow rules are never re-implemented, not even in the test double
    opVisibleToGrant: (op, claims, declared) => realManifest.opVisibleToGrant(op, claims, declared),
    opInGrantWorkflow: (claims: { mode: string; wf: readonly string[] }, opId: string, listing?: string) => realManifest.opInGrantWorkflow(claims, opId, listing),
    sdkMajorServed: (v, current) => {
      const m = /^(\d+)\.\d+\.\d+/.exec(v);
      if (!m) return false;
      const major = Number(m[1]) === 0 ? 1 : Number(m[1]);
      return major === current || major === current - 1;
    },
    kekFromEnv: (v) => {
      const raw = /^[0-9a-f]{64}$/i.test(v) ? Buffer.from(v, "hex") : Buffer.from(v, "base64url");
      if (raw.length !== 32) throw new Error("kek_invalid");
      return { id: sha(raw).slice(7, 23), key: new Uint8Array(raw) };
    },
    seal: (plaintext, kek, aad) => ({ v: 1, alg: "A256GCM", kek: kek.id, iv: "x", ct: Buffer.from(plaintext).toString("base64url"), tag: sha(`${aad}|${kek.id}`) }),
    unseal: (blob, keks, aad) => {
      const k = [keks.current, keks.previous].find((x) => x && x.id === blob.kek);
      if (!k || blob.tag !== sha(`${aad}|${k.id}`)) throw new Error("unseal failed");
      return new Uint8Array(Buffer.from(blob.ct, "base64url"));
    },
    exportPrivateKey: async (pair) => new Uint8Array(Buffer.from(JSON.stringify(pair.publicJwk))),
    importKeyPair: async (pkcs8) => {
      const publicJwk = JSON.parse(Buffer.from(pkcs8).toString("utf8"));
      return { publicJwk, privateKey: { fake: publicJwk.x } as unknown as CryptoKey, kid: `kid-${publicJwk.x.slice(0, 20)}` };
    },
    opaqueValue: (prefix) => `${prefix}${randomBytes(32).toString("base64url")}`,
    opaqueDigest: (v) => sha(v),
    digestEqual: (a, b) => a === b,
    ulid: () => Array.from(randomBytes(26), (b) => CROCKFORD[b % 32]).join(""),
    sha256Bytes: (body) => sha(body),
    signAssertion: async (typ, claims, key, request) =>
      `${b64({ alg: "EdDSA", typ, kid: key.kid })}.${b64({ ...claims, ...(request ? { htm: request.method, htu: request.pathAndQuery, ...(request.body?.length ? { bd: sha(request.body) } : {}) } : {}) })}.sig-${key.kid}`,
    verifyAssertion: (token, keys, expect) => {
      const v = verify(token, keys, expect);
      if (!v.ok || !expect.request) return v;
      const c = v.claims as Record<string, unknown>;
      if (c.htm !== expect.request.method || c.htu !== expect.request.pathAndQuery) return refuse("invalid_token", "binding");
      if ((expect.request.body?.length ? sha(expect.request.body) : undefined) !== c.bd) return refuse("invalid_token", "body");
      return v;
    },
    validateInput: (_op, input) => (input && typeof input === "object" && !Array.isArray(input) ? { ok: true } : { ok: false, errors: ["input must be an object"] }),
    signJwsWithSigner: async (typ, claims, signer) => {
      const input = `${b64({ alg: "EdDSA", typ, kid: signer.kid })}.${b64(claims)}`;
      return `${input}.${await signer.sign(input)}`;
    },
    // the double pins no build roots (worlds pass a test root as the start option); the key-set rule is the REAL one
    // (L1, C133): statements are real root signatures over the double's portal keys, so no transition path exists here
    portalRootKeys: () => [],
    trustedPortalKeys: (body, pinned, roots) => realManifest.trustedPortalKeys(body, pinned, roots),
    isPrivateInternalUrl: (url, opts) => realIsPrivateInternalUrl(url, opts),
    // shared rules are pure: the double uses the real implementations (L1)
    bridgeOpProofClaims: (bop, body) => realManifest.bridgeOpProofClaims(bop, body),
    deriveIdempotencyKey: (i) => realManifest.deriveIdempotencyKey(i),
    hookResponseProblem: (phase, body, product) => realManifest.hookResponseProblem(phase, body, product),
    reduceBeforeChain: (answers) => realManifest.reduceBeforeChain(answers as never) as never,
    holdVerdictClaim: (r) => realManifest.holdVerdictClaim(r as never),
    onBehalfOfFromMeta: (v) => realManifest.onBehalfOfFromMeta(v) as never,
    isValidLaunchPath: (p) => realManifest.isValidLaunchPath(p),
    requiredBridgeVersion: (mf) => realManifest.requiredBridgeVersion(mf as never),
    compareSemver: (a, b) => realManifest.compareSemver(a, b),
  };
  return api;
}

/** Signs with the fake scheme (used by the fake Portal and fake agents). */
export const fakeSign = (typ: string, claims: object, kid: string): string => `${b64({ alg: "EdDSA", typ, kid })}.${b64(claims)}.sig-${kid}`;
