/**
 * Bridge 0.2.8 / spec 0.1.66 (C336 RQ-2, RQ-3; BRIDGE v0.1.66):
 * - RQ-2: a dynamic call's hook requests carry `call.target.tool` = the catalog entry name, with crud/effect/holdFamily =
 *   that entry's resolution; a static op's hook requests carry no `tool` key.
 * - RQ-3: an op with `secretOutput: true` gets no `after` hook, no idempotency key is forwarded to the app, and no bridge
 *   log line carries its result. Positive control: the same op without the flag runs the after hook (fire-on-bad).
 */
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import type { OperationView } from "@opt2-tealbrick/spec/sdk";
import { CallRouter } from "../src/calls.ts";
import { jsonLogger } from "../src/util.ts";
import { AGT, CON, HOOKINS, INS, makeWorld, type World, waitFor } from "./support/world.ts";

const CANARY = "CANARY-SECRET-5b9d";

interface HookTarget {
  instance: string;
  product: string;
  op: string;
  tool?: string;
  crud: string[];
  effect: string;
  holdFamily?: string;
}

describe("C336: hook target tool (RQ-2) and secretOutput ops (RQ-3)", () => {
  let w: World;
  const lines: string[] = [];

  before(async () => {
    w = await makeWorld({ real: true, withHook: true, logger: jsonLogger((l) => lines.push(l)) });
    // the owner switches the declared context and after hooks on (they are listed with enabled:false by default)
    await w.publish((c) => {
      for (const h of c.hooks) if (h.ins === HOOKINS) delete (h as { enabled?: boolean }).enabled;
    });
    await waitFor(() => w.bridge.ctx.table?.rev === w.rev() && w.bridge.ctx.table?.apps.get(INS as never)?.down === false && w.bridge.ctx.table?.hooks.every((h) => h.enabled !== false) === true, 15000);
    w.hookMode.mode = "allow";
    w.hookMode.answer = (hook) => (hook === "enrich" ? { add: {} } : hook === "audit" ? {} : undefined);
  });
  after(async () => {
    w.hookMode.answer = undefined;
    w.appOps.override = undefined;
    w.bridgeOps.answer = undefined;
    await w.close();
  });

  const appAndOp = () => {
    const app = w.bridge.ctx.table?.apps.get(INS as never);
    const op = app?.ops.get("notes_list");
    assert.ok(app && op);
    return { app, op };
  };
  const agent = { type: "agent" as const, agt: AGT as never, con: CON as never };
  const hooksSince = (from: number) => w.appLog.hooks.slice(from).map((h) => ({ phase: h.body.phase as string, target: (h.body.call as { target: HookTarget }).target, body: h.body }));

  test("RQ-2: a dynamic call — before, context and after hooks see target.tool = the entry and the entry's resolved crud/effect/holdFamily", async () => {
    const { app, op } = appAndOp();
    // a dynamic family whose ceiling allows a write; the app resolves this entry to a write with an outward family
    const dyn = { ...op, id: "notes_list", dynamic: { mode: "list", crudCeiling: ["read", "create"], effectCeiling: "outward" } } as unknown as OperationView;
    w.bridgeOps.answer = (path, body) => (path === "resolve" ? { tool: body.tool, crud: ["create"], effect: "outward", holdFamily: "first_contact" } : undefined);
    const from = w.appLog.hooks.length;
    const r = await new CallRouter(w.bridge.ctx).route({ caller: agent, target: { app, op: dyn, tool: "gmail_send" }, input: { tool: "gmail_send", arguments: {} } as never, idempotencyKey: "key_dyn_00000001" });
    assert.equal(r.result.status, "ok");
    const seen = hooksSince(from);
    assert.deepEqual(
      seen.map((s) => s.phase),
      ["before", "context", "after"],
    );
    for (const s of seen) {
      assert.deepEqual(s.target, { instance: INS, product: "notes", op: "notes_list", tool: "gmail_send", crud: ["create"], effect: "outward", holdFamily: "first_contact" }, s.phase);
    }
    w.bridgeOps.answer = undefined;
  });

  test("RQ-2: a static op — no `tool` key on any hook target (quiet on good)", async () => {
    const { app, op } = appAndOp();
    const from = w.appLog.hooks.length;
    await new CallRouter(w.bridge.ctx).route({ caller: agent, target: { app, op, tool: "ignored_for_static" }, input: {} as never });
    const seen = hooksSince(from);
    assert.deepEqual(
      seen.map((s) => s.phase),
      ["before", "context", "after"],
    );
    for (const s of seen) {
      assert.equal("tool" in s.target, false, `${s.phase}: absent for a static op`);
      assert.deepEqual(s.target, { instance: INS, product: "notes", op: "notes_list", crud: ["read"], effect: "read" });
    }
  });

  test("RQ-3: a secretOutput op — no after hook, no idempotency key forwarded, the caller gets the output, no log line carries it", async () => {
    const { app, op } = appAndOp();
    w.appOps.override = (name, _body, res) => {
      if (name !== "notes_list") return false;
      res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ status: "ok", output: { token: CANARY } }));
      return true;
    };
    try {
      // positive control: the same op WITHOUT the flag runs the after hook, which sees the output (the detector works)
      let from = w.appLog.hooks.length;
      let ops = w.appLog.ops.length;
      const plain = await new CallRouter(w.bridge.ctx).route({ caller: agent, target: { app, op }, input: {} as never, idempotencyKey: "key_plain_000001" });
      assert.equal(plain.result.status, "ok");
      const plainHooks = hooksSince(from);
      assert.deepEqual(
        plainHooks.map((s) => s.phase),
        ["before", "context", "after"],
      );
      assert.ok(JSON.stringify(plainHooks.at(-1)?.body).includes(CANARY), "control: an after hook of a normal op sees the output");
      assert.equal(w.appLog.ops[ops]?.body.idempotencyKey, "key_plain_000001", "control: a normal op forwards the key");

      const secret = { ...op, secretOutput: true } as unknown as OperationView;
      from = w.appLog.hooks.length;
      ops = w.appLog.ops.length;
      const logFrom = lines.length;
      const r = await new CallRouter(w.bridge.ctx).route({ caller: agent, target: { app, op: secret }, input: {} as never, idempotencyKey: "key_secret_00001" });
      assert.equal(r.result.status, "ok");
      assert.deepEqual(r.result.status === "ok" ? r.result.output : null, { token: CANARY }, "the caller gets the output unchanged");
      assert.deepEqual(
        hooksSince(from).map((s) => s.phase),
        ["before", "context"],
        "no after hook for a secretOutput op",
      );
      assert.equal(w.appLog.ops.length, ops + 1);
      assert.equal("idempotencyKey" in (w.appLog.ops[ops]?.body ?? {}), false, "no idempotency key reaches the app");
      const callLines = lines.slice(logFrom);
      assert.ok(
        callLines.some((l) => l.includes('"bridge.call"')),
        "the call is logged (an empty capture cannot pass)",
      );
      assert.deepEqual(
        lines.filter((l) => l.includes(CANARY)),
        [],
        "no bridge log line carries the output",
      );
    } finally {
      w.appOps.override = undefined;
    }
  });
});
