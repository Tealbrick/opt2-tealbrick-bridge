/**
 * Test client of the bridge's INTERNAL listener, the way an app instance uses it: a claim (`POST /tb/v1/claim`, one-time
 * code) and signed status pushes (`POST /tb/v1/status`, instance assertion bound to method, path and body). Used by the
 * tests that need the bridge to hold an app's claim and status (scope summaries, hook proof capabilities).
 */
import type { Ed25519KeyPair } from "@opt2-tealbrick/spec/sdk";
import { APP_CODE, BRG, INS, type World } from "./world.ts";

const now = () => Math.floor(Date.now() / 1000);

export interface AppClient {
  ins: string;
  key: Ed25519KeyPair;
  /** HTTP status of the claim */
  claimStatus: number;
  /** push an AppStatus (the default body is a `ready` app at scopesRev 0); returns the HTTP status (200/204 = accepted) */
  status(extra?: Record<string, unknown>, o?: { omit?: string[]; /** seconds: sign the assertion this long ago (a push held back by an attacker) */ age?: number }): Promise<number>;
}

export interface ClaimOptions {
  code?: string;
  ins?: string;
  version?: string;
  sdkVersion?: string;
  /** members added to the ClaimRequest as given (e.g. `proofClaims`) */
  claim?: Record<string, unknown>;
  /** the manifest digest of the claim (default: the digest the config lists for the instance) */
  manifestDigest?: string;
  /** a runtime service name (a companion service claim); the app instance must have claimed already */
  service?: string;
  key?: Ed25519KeyPair;
}

export async function claimApp(w: World, o: ClaimOptions = {}): Promise<AppClient> {
  const ins = o.ins ?? INS;
  const key = o.key ?? (await w.api.generateKeyPair());
  const entry = w.bridge.ctx.table?.config.apps.find((a) => a.ins === ins);
  const version = o.version ?? "1.0.0";
  const sdkVersion = o.sdkVersion ?? "0.1.37";
  const res = await fetch(`${w.internalUrl}/tb/v1/claim`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      code: o.code ?? APP_CODE,
      instancePublicKey: key.publicJwk,
      manifestDigest: o.manifestDigest ?? entry?.manifestDigest,
      version,
      sdkVersion,
      ...(o.service ? { service: o.service } : {}),
      ...(o.claim ?? {}),
    }),
  });
  await res.body?.cancel();
  const svc = o.service;
  return {
    ins,
    key,
    claimStatus: res.status,
    status: async (extra = {}, opt = {}) => {
      const pathAndQuery = "/tb/v1/status?wait=0";
      const payload: Record<string, unknown> = { readiness: "ready", version, sdkVersion, scopesRev: 0, sliceRevision: -1, keysRev: -1, pendingHolds: 0, ...extra };
      for (const k of opt.omit ?? []) delete payload[k];
      const body = Buffer.from(JSON.stringify(payload));
      const assertion = await w.api.signAssertion(
        "tb-instance-assert+jwt",
        { iss: `tb:ins:${ins}`, sub: `tb:ins:${ins}`, aud: `tb:brg:${BRG}`, iat: now() - (opt.age ?? 0), exp: opt.age ? now() + 30 : now() + 60, jti: w.api.ulid(), ...(svc ? { svc } : {}) },
        key,
        { method: "POST", pathAndQuery, body },
      );
      const r = await fetch(`${w.internalUrl}${pathAndQuery}`, { method: "POST", headers: { "content-type": "application/json", "TB-Assert": assertion }, body });
      await r.body?.cancel();
      return r.status;
    },
  };
}
