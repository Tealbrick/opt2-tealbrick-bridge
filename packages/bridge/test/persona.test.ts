/**
 * v0.1.63 (BRIDGE §15.6, C320, C312a), row RM-7: the agent card's persona (config `agents[].persona`) leads the MCP
 * `initialize.instructions`, is the resource `tb://agent/persona` of that agent only, and a change sends
 * `notifications/resources/list_changed` on that agent's sessions. A paused agent gets only the pause text.
 */
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import { personaProblem } from "../src/context.ts";
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

  test("a persona outside PERSONA_PATTERN (spec 0.1.71) is persona_invalid; script characters and markers pass", () => {
    // the spec's own lists, copied verbatim (specs main 0b39be8 = spec 0.1.71, packages/spec/test/models.test.ts)
    const refused = ["\u0001", "\u000b", "\u000c", "\u001f", "\u0080", "\u009f", "\u115f", "\u1160", "\u3164", "\uffa0",
      "\u17b4", "\u17b5", "\u0008", "\u001b", "\u2028", "\u2029", "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
      "\u2060", "\u2061", "\u2064", "\u2065", "\u2066", "\u2067", "\u2068", "\u2069", "\u206a", "\u206f", "\ufeff",
      "\ufff0", "\ufff8", "\ufff9", "\ufffb", "\udbff", "\udfff", "\u{e0000}", "\u{e0041}", "\u{e007f}", "\u{e0080}",
      "\u{1bca0}", "\ufe0f\ufe0f", "\ufe00\ufe01", "\u{e0100}\u{e0101}", "\ufe0f\u200d\ufe0f", "x\u200d\ufe0f", "\u200c\ufe00",
      "\u0600\ufe0f", "\u00ad\u{e0100}", `😀${"\ufe0f".repeat(54)}`];
    for (const bad of [...refused, "\r", "\u007f"]) assert.equal(personaProblem(`a${bad}b`), "persona_invalid", JSON.stringify(bad));
    const allowed = ["\t", "\n", "\u00ad", "\u034f", "\u061c", "\u180b", "\u180d", "\u180e", "\u180f", "\u200a", "\u200b",
      "\u200c", "\u200d", "\u200e", "\u200f", "\u2027", "\u202f", "\u205f", "\u2070", "\u115e", "\u1161", "\u3163",
      "\u3165", "\uff9f", "\uffa1", "\ufdff", "\ufe00", "\ufe0f", "\ufffc", "\u{e0100}", "\u{e01ef}", "\u{1f600}",
      "👨\u200d👩\u200d👧", "❤\ufe0f", "1\ufe0f\u20e3", "\u0628\u200c\u0627", "\u05d0\u200f\u05d1", "\u0600", "\u0605", "\u06dd", "\u070f", "\u0890", "\u0891", "\u08e2", "\u{110bd}", "\u{110cd}", " \ufe0f", "a\ufe00",
      "\u0661\u0600\u0662", "🏳\ufe0f\u200d🌈", "❤\ufe0f\u200d🔥", "👁\ufe0f\u200d🗨\ufe0f", "\u00a0", " !~"];
    for (const ok of allowed) assert.equal(personaProblem(`a${ok}b`), undefined, JSON.stringify(ok));
    // QA-BRIDGE22-5: a VS/ZWJ/VS payload after an emoji is refused; Arabic number signs and prepended marks are delivered
    assert.equal(personaProblem("Helpful 😀\ufe0f\u200d\ufe0f"), "persona_invalid");
    assert.equal(personaProblem("\u0600\u0661\u0662 ok \u070f \u{110bd}"), undefined);
    assert.equal(personaProblem("x".repeat(8001)), "persona_too_long");
  });

  test("a persona with a bidi override in config is not delivered and is counted in rejected", async () => {
    const rejected = () => buildStatusReport(w.bridge.ctx).rejected.find((r) => r.kind === "config" && r.code === "persona_invalid")?.count ?? 0;
    await setPersona("Be kind.\u202e.dniK eB");
    const s = await session();
    assert.match(s.instructions, /^Teal Brick apps are available as tools/, "dropped, not cleaned");
    assert.ok(!(await list(s)).some((r) => r.uri === "tb://agent/persona"));
    assert.equal(rejected(), 1);
    await setPersona("Be kind. 😀");
    assert.ok((await session()).instructions.startsWith("Your persona, set by the owner:\nBe kind. 😀\n\n"));
  });

  test("a paused agent gets only the pause text and no persona resource", async () => {
    await setPersona("You are Ada.", true);
    const s = await session();
    assert.equal(s.instructions, PAUSED);
    assert.ok(!(await list(s)).some((r) => r.uri === "tb://agent/persona"));
    assert.equal((await read(s)).error.code, -32002);
  });
});
