/**
 * Bridge 0.2.5 (spec 0.1.52, C268 B / C268b / C268c; BRIDGE hooks step 6): the hook call proof binds the whole request.
 *
 * `bd` = sha256 of the EXACT body bytes the bridge sends, ONLY to a hook app whose stored capability set lists "bd" (its
 * ClaimRequest.proofClaims, then each AppStatus push; the newest wins; app instance only). The stored set changes ONLY on:
 * a config change of that app's manifestDigest / version / candidateManifestDigest / candidateVersion (drop), a re-claim
 * (the claim's set), a push whose version or set differs (the push's set). NEVER on a connect failure, a timeout or a 401,
 * and a 401 is never retried without `bd`. Real manifest crypto: the receiving side is the manifest `verifyHookProof` with the
 * received body bytes, the check miniapp-sdk 0.1.37 makes.
 */
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import { digest, hookCallerRef, sha256Bytes, verifyHookProof } from "@opt2-tealbrick/manifest";
import { CallRouter } from "../src/calls.ts";
import { trustFor } from "../src/table.ts";
import { BridgeError } from "../src/util.ts";
import { type AppClient, claimApp } from "./support/app-client.ts";
import { AGT, CON, HOOKINS, INS, makeWorld, type World, waitFor } from "./support/world.ts";

const now = () => Math.floor(Date.now() / 1000);
const CODES = ["tbe_hookbdcode_000001", "tbe_hookbdcode_000002", "tbe_hookbdcode_000003", "tbe_hookbdcode_000004"] as const;
const SVC_CODE = "tbe_hookbdservice_0001";

type Hook = World["appLog"]["hooks"][number];
const claimsOf = (h: Hook): Record<string, unknown> => JSON.parse(Buffer.from((h.proof as string).split(".")[1] as string, "base64url").toString("utf8"));

describe("C268c: bd in the hook call proof, by capability", () => {
  let w: World;
  let hookApp: AppClient;

  before(async () => {
    w = await makeWorld({ real: true, withHook: true });
    // the owner switches the declared context and after hooks on; the codes for the hook app (instance) and its service
    await w.amend((c) => {
      for (const h of c.hooks) if (h.ins === HOOKINS) delete (h as { enabled?: boolean }).enabled;
      for (const code of CODES) c.enrolCodes.push({ digest: w.api.opaqueDigest(code), kind: "instance", ins: HOOKINS, product: "guard", exp: now() + 3600 } as never);
      c.enrolCodes.push({ digest: w.api.opaqueDigest(SVC_CODE), kind: "service", ins: HOOKINS, service: "engine", product: "guard", exp: now() + 3600 } as never);
    });
    await waitFor(() => w.bridge.ctx.table?.rev === w.rev() && w.bridge.ctx.table?.hooks.every((h) => h.enabled !== false) === true, 15000);
    w.hookMode.mode = "allow";
    w.hookMode.answer = (hook) => (hook === "enrich" ? { add: {} } : hook === "audit" ? {} : undefined);
  });
  after(async () => {
    w.hookMode.answer = undefined;
    w.hookMode.status = undefined;
    await w.close();
  });

  /** one agent call through the pipeline: the hook requests (before, context, after) the guard app received */
  const callHooks = async (): Promise<Hook[]> => {
    const t = w.bridge.ctx.table;
    const app = t?.apps.get(INS as never);
    const op = app?.ops.get("notes_list");
    assert.ok(app && op);
    const from = w.appLog.hooks.length;
    await new CallRouter(w.bridge.ctx).route({ caller: { type: "agent", agt: AGT as never, con: CON as never }, target: { app, op }, input: {} as never });
    return w.appLog.hooks.slice(from);
  };
  const phases = (hs: Hook[]) => hs.map((h) => h.body.phase);

  /** what miniapp-sdk 0.1.37 does: bind hook, phase, ctx, in, sub, call and the digest of the RAW received bytes */
  const verify = (h: Hook, raw: Buffer = h.raw) => {
    const t = w.bridge.ctx.table;
    assert.ok(t);
    const call = h.body.call as { id: string; caller: unknown; input: never };
    return verifyHookProof(h.proof as string, trustFor(t, HOOKINS as never, now()), {
      hook: h.hook,
      phase: h.body.phase as never,
      contextDigest: digest(h.body.context as never),
      inputDigest: digest(call.input),
      sub: hookCallerRef(call.caller),
      call: call.id,
      bodyDigest: sha256Bytes(raw),
    });
  };
  const expectNoBd = async (why: string) => {
    const hs = await callHooks();
    assert.deepEqual(phases(hs), ["before", "context", "after"], why);
    for (const h of hs) {
      assert.ok(!("bd" in claimsOf(h)), `${why}: ${h.body.phase} carries no bd`);
      assert.equal(verify(h).ok, true, `${why}: a verifier accepts a proof without bd`);
    }
  };
  const expectBd = async (why: string) => {
    const hs = await callHooks();
    assert.deepEqual(phases(hs), ["before", "context", "after"], why);
    for (const h of hs) {
      assert.equal(claimsOf(h).bd, sha256Bytes(h.raw), `${why}: ${h.body.phase} bd = sha256 of the exact bytes received`);
      assert.equal(verify(h).ok, true, `${why}: ${h.body.phase} verified with the received bytes`);
    }
    return hs;
  };
  const push = async (extra: Record<string, unknown> = {}, omit: string[] = []) => assert.ok([200, 204].includes(await hookApp.status(extra, { omit })));
  const changeApp = async (change: (a: Record<string, unknown>) => void) => {
    await w.amend((c) => change(c.apps.find((a) => a.ins === HOOKINS) as unknown as Record<string, unknown>));
    await waitFor(() => w.bridge.ctx.table?.rev === w.rev() && w.bridge.ctx.table?.apps.get(HOOKINS as never)?.down === false, 15000);
  };

  test("an app that declares no proofClaims (SDK 0.1.35, or 0.1.36 without the flag) gets no bd, on all three phases", async () => {
    hookApp = await claimApp(w, { ins: HOOKINS, code: CODES[0], sdkVersion: "0.1.36" });
    assert.equal(hookApp.claimStatus, 200);
    await expectNoBd("claim without proofClaims");
    await push({ sdkVersion: "0.1.36" });
    await expectNoBd("push without proofClaims");
  });

  test("missing, non-array, unknown and malformed proofClaims mean none", async () => {
    for (const bad of [[], ["x"], ["BD"], [1], [null], [["bd"]], "bd", { bd: true }, 7, true]) {
      await push({ proofClaims: bad });
      await expectNoBd(`proofClaims ${JSON.stringify(bad)}`);
    }
  });

  test("an app that lists bd: all three phases carry bd = sha256 of the exact bytes sent, and the verifier accepts them; a changed byte is refused", async () => {
    await push({ proofClaims: ["bd"] });
    const hs = await expectBd("push lists bd");
    for (const h of hs) {
      // the bytes the app received ARE what the bridge serialised once (no second serialisation)
      assert.equal(h.raw.toString("utf8"), JSON.stringify(h.body), `${h.body.phase}: the body is the one serialisation`);
      // fire-on-bad: the same proof over a body that differs by one byte (a space after a colon; JSON-equal, byte-different) is refused
      const tampered = Buffer.from(h.raw.toString("utf8").replace('"phase":', '"phase": '));
      assert.notEqual(tampered.toString(), h.raw.toString());
      assert.equal(verify(h, tampered).ok, false, `${h.body.phase}: a changed byte breaks bd`);
    }
  });

  test("the newest push wins: other entries beside bd keep it, a push without it removes it, a push with it restores it", async () => {
    await push({ proofClaims: ["bd", "future_claim"] });
    await expectBd("bd with an unknown entry");
    await push({}, ["proofClaims"]);
    await expectNoBd("a push without proofClaims states none");
    await push({ proofClaims: ["bd"] });
    await expectBd("listed again");
  });

  test("a config change of the app's version, candidate or manifest digest drops the capability until the next push; other changes do not", async () => {
    await push({ proofClaims: ["bd"] });
    await expectBd("before");
    // an unrelated revision (nothing about this app changes) keeps it
    await w.publish();
    await waitFor(() => w.bridge.ctx.table?.rev === w.rev(), 15000);
    await expectBd("unrelated config revision");

    // (1) version
    await changeApp((a) => {
      a.version = "1.0.1";
    });
    await expectNoBd("version changed in the config");
    await expectNoBd("still none: nothing but a push restores it");
    await push({ version: "1.0.1", proofClaims: ["bd"] });
    await expectBd("push after the version change");

    // (2) update candidate (both members appear, G2b): the serving digest stays
    const realDigest = w.bridge.ctx.table?.config.apps.find((a) => a.ins === HOOKINS)?.manifestDigest as string;
    await changeApp((a) => {
      a.candidateManifestDigest = realDigest;
      a.candidateVersion = "1.1.0";
    });
    await expectNoBd("candidate appeared");
    await push({ version: "1.0.1", proofClaims: ["bd"] });
    await expectBd("push after the candidate appeared");
    // the candidate version alone changes
    await changeApp((a) => {
      a.candidateVersion = "1.1.1";
    });
    await expectNoBd("candidateVersion changed");
    await push({ version: "1.0.1", proofClaims: ["bd"] });
    await expectBd("push after candidateVersion changed");

    // (3) manifest digest alone (the candidate digest is the one that runs, so the app stays up)
    await changeApp((a) => {
      a.manifestDigest = digest({ other: 1 } as never);
    });
    await expectNoBd("manifestDigest changed");
    await push({ version: "1.0.1", proofClaims: ["bd"] });
    await expectBd("push after the manifest digest changed");

    // (4) the attempt ends (E3 rollback or commit): the candidate disappears, the serving digest is the running one again
    await changeApp((a) => {
      a.manifestDigest = realDigest;
      a.candidateManifestDigest = undefined;
      a.candidateVersion = undefined;
    });
    await expectNoBd("attempt ended");
    await push({ version: "1.0.1", proofClaims: ["bd"] });
    await expectBd("push after the attempt ended");
  });

  test("a 401 neither drops the capability nor is retried without bd; the same for a connect failure and a timeout", async () => {
    await push({ proofClaims: ["bd"] });
    await expectBd("before");

    // 401 from the hook app: the call ends hook_failed with ONE request (no second try, with or without bd)
    w.hookMode.status = 401;
    const from = w.appLog.hooks.length;
    await assert.rejects(callHooks(), (e: unknown) => e instanceof BridgeError && e.code === "hook_failed");
    const seen = w.appLog.hooks.slice(from);
    assert.equal(seen.length, 1, "exactly one request: no retry");
    assert.equal(claimsOf(seen[0] as Hook).bd, sha256Bytes((seen[0] as Hook).raw), "the one request carried bd");
    w.hookMode.status = undefined;
    await expectBd("after the 401");

    // connect failure and timeout of the bridge's fetch to the hook app
    const ctx = w.bridge.ctx as unknown as { fetch: typeof fetch };
    const original = ctx.fetch;
    for (const failure of [Object.assign(new TypeError("fetch failed"), { cause: { code: "ECONNREFUSED" } }), new DOMException("The operation timed out.", "TimeoutError")]) {
      let hookRequests = 0;
      ctx.fetch = ((input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) => {
        if (String(input).includes("/tb/v1/hooks/")) {
          hookRequests += 1;
          return Promise.reject(failure);
        }
        return original(input, init);
      }) as typeof fetch;
      try {
        await assert.rejects(callHooks(), (e: unknown) => e instanceof BridgeError && e.code === "hook_failed");
        assert.equal(hookRequests, 1, `${failure.name}: no retry`);
      } finally {
        ctx.fetch = original;
      }
      await expectBd(`after ${failure.name}`);
    }
  });

  test("a companion service claim or push never sets or clears it", async () => {
    // the app instance says none; its service claims with bd and pushes with bd: still none
    await push({ proofClaims: [] });
    await expectNoBd("app says none");
    const svc = await claimApp(w, { ins: HOOKINS, code: SVC_CODE, service: "engine", claim: { proofClaims: ["bd"] } });
    assert.equal(svc.claimStatus, 200, "the service claim is accepted");
    await expectNoBd("after a service claim that lists bd");
    assert.ok([200, 204].includes(await svc.status({ proofClaims: ["bd"] })));
    await expectNoBd("after a service push that lists bd");
    // and the other way: the app says bd, the service says none
    await push({ proofClaims: ["bd"] });
    await expectBd("app lists bd");
    assert.ok([200, 204].includes(await svc.status({}, { omit: ["proofClaims"] })));
    await expectBd("a service push without proofClaims does not clear it");
  });

  test("a re-claim sets the claim's set: with bd → bd (before any push), without → none", async () => {
    const withBd = await claimApp(w, { ins: HOOKINS, code: CODES[1], claim: { proofClaims: ["bd"] } });
    assert.equal(withBd.claimStatus, 200);
    await expectBd("claim lists bd");
    const without = await claimApp(w, { ins: HOOKINS, code: CODES[2] });
    assert.equal(without.claimStatus, 200);
    await expectNoBd("a later claim without proofClaims");
    const junk = await claimApp(w, { ins: HOOKINS, code: CODES[3], claim: { proofClaims: ["nope"] } });
    assert.equal(junk.claimStatus, 200);
    await expectNoBd("a claim with an unknown entry only");
  });
});
