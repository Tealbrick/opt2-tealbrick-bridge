/**
 * Sprint S1 (REDTEAM-S1 M1 residuals): a stable advertised internal host and the boot-read own-infra allow-list.
 *  - TB_INTERNAL_HOST as a NAME is advertised (claim answer / ctx.internalUrl), never bound; an IP address keeps the
 *    BRG-29 meaning (bound and advertised); unset keeps today's chain (RAILWAY_PRIVATE_DOMAIN, bound host, hostname()).
 *  - TB_OWN_INFRA_ORIGINS is read once at boot: adding an app means a bridge restart.
 */
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import { hostname } from "node:os";
import { describe, test } from "node:test";
import { internalHostName, internalListenHost } from "../src/server.ts";
import { makeWorld, type World } from "./support/world.ts";

/** the advertised internal URL is http://<host>:<port> (tests ask for port 0, so the port is any number) */
const advertised = (host: string) => new RegExp(`^http://${host.replace(/[.[\]]/g, "\\$&")}:\\d+$`);
const boundAddress = (w: World) => (w.bridge.internalServer.address() as AddressInfo).address;

describe("S1: TB_INTERNAL_HOST as an advertised name", () => {
  test("internalHostName: names are accepted, IP addresses and unset are not names, bad values throw", () => {
    assert.equal(internalHostName({}), undefined);
    assert.equal(internalHostName({ TB_INTERNAL_HOST: "" }), undefined);
    assert.equal(internalHostName({ TB_INTERNAL_HOST: "  " }), undefined);
    assert.equal(internalHostName({ TB_INTERNAL_HOST: "127.0.0.1" }), undefined, "IPv4 stays the BRG-29 bind address");
    assert.equal(internalHostName({ TB_INTERNAL_HOST: "::1" }), undefined, "IPv6 stays the BRG-29 bind address");
    assert.equal(internalHostName({ TB_INTERNAL_HOST: "tb-bridge" }), "tb-bridge");
    assert.equal(internalHostName({ TB_INTERNAL_HOST: " tb-bridge " }), "tb-bridge", "trimmed");
    assert.equal(internalHostName({ TB_INTERNAL_HOST: "tb_bridge.ws1.internal" }), "tb_bridge.ws1.internal", "docker service names and dots");
    for (const bad of ["http://tb-bridge", "tb-bridge:8788", "tb-bridge/x", "-tb", "tb-", "a..b", "tb bridge", "tb@evil", "[::1]", "a".repeat(64), `${"a.".repeat(130)}a`]) {
      assert.throws(() => internalHostName({ TB_INTERNAL_HOST: bad }), /TB_INTERNAL_HOST/, bad);
    }
  });

  test("internalListenHost: a name does not change the bind; an IP does; a name on own_infra is refused", () => {
    assert.deepEqual(internalListenHost("deployed", { TB_INTERNAL_HOST: "tb-bridge" }), { host: "::", explicit: false }, "name = bind as unset (so the EAFNOSUPPORT fallback stays)");
    assert.deepEqual(internalListenHost("deployed", { TB_INTERNAL_HOST: "10.0.0.5" }), { host: "10.0.0.5", explicit: true }, "unchanged");
    assert.deepEqual(internalListenHost("own_infra", { TB_INTERNAL_HOST: "10.0.0.5" }), { host: "10.0.0.5", explicit: true }, "unchanged");
    assert.throws(() => internalListenHost("own_infra", { TB_INTERNAL_HOST: "tb-bridge" }), /deployed form/);
  });

  test("deployed + name: advertised as http://<name>:<port>, bound to the form default, not to the name", async () => {
    const w = await makeWorld({ real: true, formDefaultHosts: true, env: { TB_INTERNAL_HOST: "tb-bridge" } });
    try {
      assert.match(w.bridge.ctx.internalUrl, advertised("tb-bridge"));
      assert.ok(["::", "0.0.0.0"].includes(boundAddress(w)), `bound ${boundAddress(w)}`);
    } finally {
      await w.close();
    }
  });

  test("the name wins over RAILWAY_PRIVATE_DOMAIN and over the container host name", async () => {
    const w = await makeWorld({ real: true, formDefaultHosts: true, env: { TB_INTERNAL_HOST: "tb-bridge", RAILWAY_PRIVATE_DOMAIN: "bridge.railway.internal" } });
    try {
      assert.match(w.bridge.ctx.internalUrl, advertised("tb-bridge"));
    } finally {
      await w.close();
    }
  });

  test("Railway behaviour unchanged: no TB_INTERNAL_HOST -> RAILWAY_PRIVATE_DOMAIN; neither -> the container host name", async () => {
    const railway = await makeWorld({ real: true, formDefaultHosts: true, env: { RAILWAY_PRIVATE_DOMAIN: "bridge.railway.internal" } });
    try {
      assert.match(railway.bridge.ctx.internalUrl, advertised("bridge.railway.internal"));
    } finally {
      await railway.close();
    }
    const plain = await makeWorld({ real: true, formDefaultHosts: true });
    try {
      assert.match(plain.bridge.ctx.internalUrl, advertised(hostname()));
    } finally {
      await plain.close();
    }
  });

  test("an IP address in TB_INTERNAL_HOST is still bound and advertised as before (RAILWAY_PRIVATE_DOMAIN still first)", async () => {
    const w = await makeWorld({ real: true, env: { TB_INTERNAL_HOST: "127.0.0.1" } });
    try {
      assert.equal(boundAddress(w), "127.0.0.1");
      assert.match(w.bridge.ctx.internalUrl, advertised("127.0.0.1"));
    } finally {
      await w.close();
    }
    const r = await makeWorld({ real: true, env: { TB_INTERNAL_HOST: "127.0.0.1", RAILWAY_PRIVATE_DOMAIN: "bridge.railway.internal" } });
    try {
      assert.match(r.bridge.ctx.internalUrl, advertised("bridge.railway.internal"));
    } finally {
      await r.close();
    }
  });
});

describe("S1: TB_OWN_INFRA_ORIGINS is read at boot", () => {
  test("the list is fixed when the bridge starts; a later env change does nothing until a restart", async () => {
    const env: Record<string, string> = { TB_OWN_INFRA_ORIGINS: "http://tb-notes:9000" };
    const w = await makeWorld({ real: true, env });
    try {
      assert.deepEqual(w.bridge.ctx.ownInfraOrigins, ["http://tb-notes:9000"]);
      env.TB_OWN_INFRA_ORIGINS = "http://tb-notes:9000,http://tb-other:9000";
      assert.deepEqual(w.bridge.ctx.ownInfraOrigins, ["http://tb-notes:9000"], "a running bridge keeps the list it booted with");
      await w.restart();
      assert.deepEqual(w.bridge.ctx.ownInfraOrigins, ["http://tb-notes:9000", "http://tb-other:9000"], "adding an app = restart (drain), then the bridge reads it");
    } finally {
      await w.close();
    }
  });
});
