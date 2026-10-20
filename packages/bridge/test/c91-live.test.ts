/**
 * C91 live: the REAL bridge calls a REAL miniapp-sdk app (startApp, real HTTP) for every bridge op — catalog (list
 * mode), catalog search (search mode), resolve and scope_summary. No fake app: the SDK verifies each proof with its
 * own binding, so the S1 catalog/scope_summary mismatch fails here. Only Portal is faked (world).
 */
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import { CallRouter } from "../src/calls.ts";
import { freePort, type RealSdkApp, startRealSdkApp } from "./support/sdk-app.ts";
import { AGT, makeWorld, type World } from "./support/world.ts";

const SDKINS = "ins_01HSDKAPPSDKAPPSDKAPPSDKAP";
const AGENT = AGT as `agt_${string}`;

const dyn = (id: string, mode: "list" | "search") => ({
  id,
  title: id,
  description: `Dynamic ${mode} op`,
  crud: ["read"],
  effect: "read",
  idempotency: "supported",
  receipt: false,
  audience: "agent",
  dynamic: { mode, crudCeiling: ["read"], effectCeiling: "read" },
});

describe("C91 live: real bridge → real SDK app bridge ops", () => {
  let w: World;
  let sdk: RealSdkApp;
  const searches: unknown[] = [];

  before(async () => {
    const port = await freePort();
    w = await makeWorld({ real: true, extraOwnInfraOrigins: [`http://127.0.0.1:${port}`] });
    const entries = [{ name: "gmail_list", title: "Gmail list", description: "List Gmail messages", inputSchema: { type: "object" as const }, crud: ["read" as const], effect: "read" as const }];
    sdk = await startRealSdkApp(w, {
      ins: SDKINS,
      product: "dyna",
      code: "tbe_sdkappinstancecode01",
      port,
      operations: [dyn("catalog_all", "list"), dyn("lookup", "search")],
      dynamic: {
        catalog_all: { catalog: async () => entries, resolve: async () => ({ crud: ["read"], effect: "read" }), call: async () => ({}) },
        lookup: {
          catalog: async (q: unknown) => {
            searches.push(q);
            return entries;
          },
          resolve: async (tool: string) => (tool === "gmail_list" ? { crud: ["read"], effect: "read" } : null),
          call: async () => ({}),
        },
      },
    });
  });
  after(async () => {
    await sdk?.stop();
    await w?.close();
  });

  test("catalog (list), catalog search, resolve and scope_summary are accepted by the real SDK", async () => {
    const app = w.bridge.ctx.table?.apps.get(SDKINS as never);
    assert.ok(app?.manifest, "the bridge fetched the real app's manifest");
    const r = new CallRouter(w.bridge.ctx);
    const list = await r.catalog(app, "catalog_all", AGENT);
    assert.deepEqual(
      list.map((e) => e.name),
      ["gmail_list"],
    );
    const found = await r.search(app, "lookup", "gmail list messages", 5, AGENT);
    assert.equal(found[0]?.name, "gmail_list");
    assert.deepEqual(searches.at(-1), { query: "gmail list messages", limit: 5 }, "the search query reaches the app");
    const resolved = await r.bridgeOp<{ tool: string; effect: string }>(app, "resolve", { op: "lookup", tool: "gmail_list" });
    assert.equal(resolved.effect, "read");
    const summary = await r.bridgeOp<unknown[]>(app, "scope_summary", {});
    assert.ok(Array.isArray(summary));
  });
});
