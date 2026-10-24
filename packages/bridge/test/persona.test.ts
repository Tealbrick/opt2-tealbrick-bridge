/**
 * v0.1.63 (BRIDGE §15.6, C320, C312a), row RM-7: the agent card's persona (config `agents[].persona`) leads the MCP
 * `initialize.instructions`, is the resource `tb://agent/persona` of that agent only, and a change sends
 * `notifications/resources/list_changed` on that agent's sessions. A paused agent gets only the pause text.
 */
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import { buildStatusReport } from "../src/portal.ts";
import { AGT, makeWorld, type World, waitFor } from "./support/world.ts";

const PAUSED = "Teal Brick: this agent is paused by the owner. No tools are available until the owner resumes it.";

describe("RM-7: agent persona in instructions and as a resource", () => {
  let w: World;
  before(async () => {
    w = await makeWorld({ real: true });
  });
  after(async () => {
    await w.close();
  });

  const setPersona = async (persona: string | undefined, paused = false) => {
    await w.amend((c) => {
      const a = c.agents.find((x) => x.agt === AGT) as (typeof c.agents)[number];
      if (persona === undefined) delete a.persona;
      else a.persona = persona;
      c.pause.agents = (paused ? [AGT] : []) as never;
    });
    await waitFor(() => w.bridge.ctx.table?.rev === w.rev(), 15000);
  };
  const session = async () => {
    const token = await w.agentToken();
    const init = await w.mcp(token, { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } } });
    assert.equal(init.status, 200);
    return { token, sid: init.session as string, instructions: init.json.result.instructions as string };
  };
  const list = async (s: { token: string; sid: string }) => (await w.mcp(s.token, { jsonrpc: "2.0", id: 2, method: "resources/list" }, s.sid)).json.result.resources as { uri: string; mimeType: string }[];
  const read = async (s: { token: string; sid: string }) => (await w.mcp(s.token, { jsonrpc: "2.0", id: 3, method: "resources/read", params: { uri: "tb://agent/persona" } }, s.sid)).json;

  test("no persona: instructions as before, no persona resource", async () => {
    const s = await session();
    assert.match(s.instructions, /^Teal Brick apps are available as tools/);
    assert.ok(!(await list(s)).some((r) => r.uri === "tb://agent/persona"));
    assert.equal((await read(s)).error.code, -32002);
  });

  test("a persona leads the instructions, is listed and read; a change sends resources/list_changed", async () => {
    const s0 = await session();
    await list(s0); // the session has listed its resources: a change is announced to it
    const stream = await fetch(`${w.publicUrl}/mcp`, { headers: { authorization: `Bearer ${s0.token}`, "mcp-session-id": s0.sid, accept: "text/event-stream" } });
    assert.equal(stream.status, 200);
    const reader = (stream.body as ReadableStream<Uint8Array>).getReader();
    let events = "";
    const reading = (async () => {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) return;
        events += new TextDecoder().decode(value);
      }
    })().catch(() => undefined);

    await setPersona("You are Ada. Answer briefly.\n\nAsk before you send anything.");
    await waitFor(() => events.includes("notifications/resources/list_changed"), 5000);
    await reader.cancel();
    await reading;

    const s = await session();
    assert.ok(s.instructions.startsWith("Your persona, set by the owner:\nYou are Ada. Answer briefly.\n\nAsk before you send anything.\n\nTeal Brick apps are available as tools"), s.instructions);
    const resources = await list(s);
    assert.deepEqual(resources[0] && { uri: resources[0].uri, mimeType: resources[0].mimeType }, { uri: "tb://agent/persona", mimeType: "text/markdown" });
    assert.ok(resources.some((r) => r.uri.startsWith("tealbrick://skills/")), "skills stay listed");
    assert.deepEqual((await read(s)).result.contents, [{ uri: "tb://agent/persona", mimeType: "text/markdown", text: "You are Ada. Answer briefly.\n\nAsk before you send anything." }]);
  });

  test("the 4 KB limit cuts only the tools/skills part, never the persona", async () => {
    const long = `${"Be careful. ".repeat(600)}END`;
    await setPersona(long);
    const s = await session();
    const head = `Your persona, set by the owner:\n${long}\n\n`;
    assert.ok(s.instructions.startsWith(head), "the whole persona");
    assert.ok(Buffer.byteLength(s.instructions.slice(head.length)) <= 4096);
  });

  test("a persona of exactly 8,000 UTF-16 units is delivered; 8,001 is dropped (never cut) and counted in rejected", async () => {
    const rejected = () => buildStatusReport(w.bridge.ctx).rejected.find((r) => r.kind === "config" && r.code === "persona_too_long")?.count ?? 0;
    const exact = `${"é".repeat(3999)}😀${"x".repeat(3999)}`;
    assert.equal(exact.length, 8000, "length counts UTF-16 units");
    await setPersona(exact);
    const s = await session();
    assert.ok(s.instructions.startsWith(`Your persona, set by the owner:\n${exact}\n\n`));
    assert.equal((await read(s)).result.contents[0].text, exact);
    assert.equal(rejected(), 0);
    await setPersona(`${exact}y`);
    const s2 = await session();
    assert.match(s2.instructions, /^Teal Brick apps are available as tools/, "dropped, not cut");
    assert.ok(!(await list(s2)).some((r) => r.uri === "tb://agent/persona"));
    assert.equal((await read(s2)).error.code, -32002);
    assert.equal(rejected(), 1, "rejected {kind: config, code: persona_too_long}");
  });

  test("a paused agent gets only the pause text and no persona resource", async () => {
    await setPersona("You are Ada.", true);
    const s = await session();
    assert.equal(s.instructions, PAUSED);
    assert.ok(!(await list(s)).some((r) => r.uri === "tb://agent/persona"));
    assert.equal((await read(s)).error.code, -32002);
  });
});
