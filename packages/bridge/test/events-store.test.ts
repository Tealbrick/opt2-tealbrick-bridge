/**
 * Bridge 0.2.7 (spec 0.1.57, BRIDGE §14, MANIFEST §16.2; C274c/C274d): the per-agent event log, as fast unit tests on
 * synthetic tables (real manifest rules from @opt2-tealbrick/manifest, real node:sqlite). Every BRIDGE §14.4 case that does
 * not need the wire is here; the wire (ingest auth, MCP methods, SSE frames) is in events-e2e.test.ts.
 */
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, describe, test } from "node:test";
import type { AgentEvent } from "@opt2-tealbrick/spec/bridge";
import { bridgeCaps } from "../src/caps.ts";
import { EVENT_FANOUT_LIMIT, EVENT_RETENTION_ROWS, EventIngestLimit, EventStore, isStorageFailure, ulidAfter } from "../src/events.ts";
import type { Table } from "../src/table.ts";
import { silentLogger } from "../src/util.ts";
import { api, ev, eventsManifest, item, nOf, op, openStore, runtime, table } from "./support/events.ts";
import { AGT, AGT2 } from "./support/world.ts";

const AGT3 = "agt_01HCCCCCCCCCCCCCCCCCCCCCCC";
const INS_A = "ins_01HQQQQQQQQQQQQQQQQQQQQQQQ";
const INS_B = "ins_01HRRRRRRRRRRRRRRRRRRRRRRR";
const DAY = 86_400_000;

const dirs: string[] = [];
const stores: EventStore[] = [];
const fresh = (): EventStore => {
  const o = openStore();
  dirs.push(o.dir);
  stores.push(o.store);
  return o.store;
};
after(() => {
  for (const s of stores) s.close();
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

const mA = eventsManifest("2.0.0");
const mB = { ...eventsManifest("1.0.0"), id: "memo", name: "Memo" };
const appA = runtime(INS_A, "notes", mA);
const appB = runtime(INS_B, "memo", mB);
/** AGT: read+create on A and B; AGT2: read+create+update+delete on A; AGT3: no grant */
const world = (o: Partial<Parameters<typeof table>[0]> = {}): Table =>
  table({
    apps: [appA, appB],
    agents: [AGT, AGT2, AGT3],
    grants: [
      { agent: AGT, ins: INS_A },
      { agent: AGT, ins: INS_B },
      { agent: AGT2, ins: INS_A, crud: ["read", "create", "update", "delete"] },
    ],
    ...o,
  });

const poll = (s: EventStore, t: Table, agent: string, cursor: string | null = null, limit = 100) => s.poll(t, agent, cursor, limit, false);
const ns = (evs: AgentEvent[]) => evs.map(nOf);

describe("ingest and fan-out (BRIDGE §14.1, MANIFEST §16.2 rules 1–4)", () => {
  test("B-EV-1 / emit: every granted agent that passes rule 1 gets one row; id = origin; envelope shape", () => {
    const s = fresh();
    const t = world();
    const r = s.ingest(t, appA, [item({ n: 1, summary: "Hello", untrusted: true })]);
    assert.deepEqual(r.result.results.map((x) => [x.status, x.recipients]), [["stored", 2]]);
    assert.deepEqual([...r.agents].sort(), [AGT, AGT2].sort());
    const p = poll(s, t, AGT);
    assert.equal(p.events.length, 1);
    const e = p.events[0] as AgentEvent;
    assert.equal(e.id, e.origin);
    assert.equal(e.type, "notes.note.created");
    assert.equal(e.app, "notes");
    assert.equal(e.summary, "Hello");
    assert.equal(e.untrusted, true);
    assert.deepEqual(e.subject, { kind: "note", id: "n1" });
    assert.deepEqual(e.data, { n: 1 });
    assert.equal(e.instanceId, undefined);
    assert.equal(p.cursor, e.id);
    assert.equal(p.truncated, false);
  });

  test("B-EV-2: an agent with no grant, or whose grant does not admit the op (crud), gets nothing and no list entry", () => {
    const s = fresh();
    const t = world();
    s.ingest(t, appA, [item({ n: 1 }), item({ name: "note.deleted", n: 2 })]);
    assert.deepEqual(ns(poll(s, t, AGT3).events), []);
    assert.deepEqual(ns(poll(s, t, AGT).events), [1], "note.deleted needs delete: not in AGT's grant");
    assert.deepEqual(ns(poll(s, t, AGT2).events), [1, 2]);
    assert.deepEqual(s.list(t, AGT3).types, []);
    const listed = s.list(t, AGT).types.filter((x) => x.app === "notes").map((x) => x.type);
    assert.ok(!listed.includes("notes.note.deleted"));
    assert.ok(listed.includes("notes.note.created"));
  });

  test("B-EV-3 / B-EV-14: a scoped event never reaches an agent outside `eligible`; bounded keeps op.crud ⊆ grant.crud, owner skips it", () => {
    const s = fresh();
    const t = world();
    const r = s.ingest(t, appA, [
      item({ name: "note.shared", n: 1, instanceId: "nb1", eligible: [] }),
      item({ name: "note.shared", n: 2, instanceId: "nb1", eligible: [{ agent: AGT, authority: "bounded" }] }),
      // update is above AGT's grant (read, create): bounded → nothing, owner → delivered (C283 A1)
      item({ name: "note.edited", n: 3, instanceId: "nb1", eligible: [{ agent: AGT, authority: "bounded" }] }),
      item({ name: "note.edited", n: 4, instanceId: "nb1", eligible: [{ agent: AGT, authority: "owner" }] }),
      // an eligible agent without a grant to the instance gets nothing, whatever the authority
      item({ name: "note.shared", n: 5, instanceId: "nb1", eligible: [{ agent: AGT3, authority: "owner" }] }),
    ]);
    assert.deepEqual(r.result.results.map((x) => x.recipients), [0, 1, 0, 1, 0]);
    const p = poll(s, t, AGT);
    assert.deepEqual(ns(p.events), [2, 4]);
    assert.equal(p.events[0]?.instanceId, "nb1");
    assert.deepEqual(ns(poll(s, t, AGT2).events), [], "AGT2 is not in any eligible list");
  });

  test("B-EV-4: the causing agent never gets the event; the others do", () => {
    const s = fresh();
    const t = world();
    s.ingest(t, appA, [item({ n: 1, causedBy: AGT })]);
    assert.deepEqual(ns(poll(s, t, AGT).events), []);
    const other = poll(s, t, AGT2).events;
    assert.deepEqual(ns(other), [1]);
    assert.equal(other[0]?.causedBy, AGT);
  });

  test("audience target: only the agents in `to` that pass rule 1", () => {
    const s = fresh();
    const t = world();
    const r = s.ingest(t, appA, [item({ name: "note.pinged", n: 1, to: [AGT, AGT3] })]);
    assert.equal(r.result.results[0]?.recipients, 1);
    assert.deepEqual(ns(poll(s, t, AGT).events), [1]);
    assert.deepEqual(ns(poll(s, t, AGT2).events), []);
  });

  test("B-EV-5: a stored cursor, 3 emits, a poll with that cursor → exactly those 3 in emit order", () => {
    const s = fresh();
    const t = world();
    s.ingest(t, appA, [item({ n: 1 })]);
    const c0 = poll(s, t, AGT).cursor;
    s.ingest(t, appA, [item({ n: 2 }), item({ n: 3 })]);
    s.ingest(t, appB, [item({ n: 4 })]);
    const p = poll(s, t, AGT, c0);
    assert.deepEqual(ns(p.events), [2, 3, 4]);
    // ids strictly increase in emit order
    assert.ok(p.events.every((e, i) => i === 0 || e.id > (p.events[i - 1] as AgentEvent).id));
  });

  test("B-EV-12: undeclared, app tb.*, invalid payload and every shape rule → refused with its code, nothing stored, key not consumed", () => {
    const s = fresh();
    const t = world();
    const big = "x".repeat(4100);
    const items = [
      item({ name: "note.unknown" }),
      item({ name: "tb.conformance" }),
      item({ name: "tb.hold.unknown" }),
      item({ data: { n: "not an integer" } }),
      item({ data: { n: 1, extra: true } }),
      item({ key: "short" }),
      item({ subject: { kind: "Note", id: "n1" } }),
      item({ subject: { kind: "note", id: "" } }),
      item({ summary: "s".repeat(281) }),
      item({ data: { n: 1 }, pad: big }),
      item({ data: { n: 1 }, instanceId: "nb1" }),
      item({ name: "note.shared", instanceId: "nb1" }),
      item({ name: "note.shared", eligible: [] }),
      item({ name: "note.pinged" }),
      item({ name: "note.pinged", to: [] }),
      item({ to: [AGT] }),
      item({ name: "note.shared", instanceId: "nb1", eligible: Array.from({ length: 501 }, (_, i) => ({ agent: `agt_${i}`, authority: "owner" })) }),
      item({ name: "note.shared", instanceId: "nb1", eligible: [{ agent: AGT, authority: "admin" }] }),
      item({ untrusted: false }),
      { kind: "other", key: "key-other-1" },
      "not an object",
    ];
    const r = s.ingest(t, appA, items);
    assert.deepEqual(
      r.result.results.map((x) => `${x.status} ${x.code ?? ""}`.trim()),
      [
        "refused event_undeclared",
        "refused event_reserved",
        "refused event_reserved",
        "refused event_payload_invalid",
        "refused event_payload_invalid",
        "refused event_payload_invalid",
        "refused event_payload_invalid",
        "refused event_payload_invalid",
        "refused event_too_large",
        "refused event_too_large",
        "refused event_instance_invalid",
        "refused event_instance_invalid",
        "refused event_instance_invalid",
        "refused event_target_invalid",
        "refused event_target_invalid",
        "refused event_target_invalid",
        "refused event_payload_invalid",
        "refused event_payload_invalid",
        "refused event_payload_invalid",
        "refused event_payload_invalid",
        "refused event_payload_invalid",
      ],
    );
    assert.equal(r.result.results.length, items.length, "one result per item, same order");
    assert.deepEqual(r.result.results.map((x) => x.key).slice(0, 2), [(items[0] as { key: string }).key, (items[1] as { key: string }).key]);
    assert.deepEqual(poll(s, t, AGT).events, []);
    // a refused key is not consumed: the corrected item with the same key is stored
    const fixed = s.ingest(t, appA, [{ ...(items[3] as object), data: { n: 7 } }]);
    assert.equal(fixed.result.results[0]?.status, "stored");
  });

  test("B-EV-10: product tb → event_reserved for every emit; tb.hold.decided from an app is accepted (target, any valid grant)", () => {
    const s = fresh();
    const tbApp = runtime("ins_01HTTTTTTTTTTTTTTTTTTTTTTT", "tb", { ...eventsManifest("1.0.0"), id: "tb" });
    const t = table({ apps: [appA, tbApp], agents: [AGT], grants: [{ agent: AGT, ins: INS_A }, { agent: AGT, ins: tbApp.entry.ins }] });
    assert.deepEqual(s.ingest(t, tbApp, [item({ n: 1 }), item({ name: "tb.hold.decided", to: [AGT], data: { holdId: `hld_${"0".repeat(26)}`, op: "notes_send", decision: "approved" } })]).result.results.map((x) => x.code), ["event_reserved", "event_reserved"]);
    const hd = s.ingest(t, appA, [{ ...item({ name: "tb.hold.decided", to: [AGT], data: { holdId: `hld_${"0".repeat(26)}`, op: "notes_send", decision: "denied" } }), subject: { kind: "hold", id: `hld_${"0".repeat(26)}` } }]);
    assert.equal(hd.result.results[0]?.status, "stored");
    const e = poll(s, t, AGT).events[0] as AgentEvent;
    assert.equal(e.type, "tb.hold.decided");
    assert.equal(e.app, "notes");
    const listed = s.list(t, AGT).types;
    assert.deepEqual(listed.filter((x) => x.type === "tb.hold.decided").map((x) => x.app), ["notes"], "no tb.hold.decided for product tb");
  });

  test("B-EV-13: the same (app instance, key) twice → stored then duplicate (one event); another instance may reuse the key; 7 days later it is new", () => {
    const s = fresh();
    const t = world();
    const it = item({ n: 1, key: "same-key-0001" });
    assert.equal(s.ingest(t, appA, [it]).result.results[0]?.status, "stored");
    const dup = s.ingest(t, appA, [it, { ...it, data: { n: 2 } }]).result.results;
    assert.deepEqual(dup.map((x) => x.status), ["duplicate", "duplicate"]);
    assert.equal(s.ingest(t, appB, [{ ...it, data: { n: 3 } }]).result.results[0]?.status, "stored");
    assert.deepEqual(ns(poll(s, t, AGT).events), [1, 3]);
    const real = s.now;
    s.now = () => real() + 7 * DAY + 1000;
    try {
      assert.equal(s.ingest(t, appA, [{ ...it, data: { n: 4 } }]).result.results[0]?.status, "stored");
    } finally {
      s.now = real;
    }
  });

  test("B-EV-15 / B-EV-16: purge {agent, instanceId} and purge {instanceId}; delivered or not; purge keys deduped (a retry deletes nothing stored after it)", () => {
    const s = fresh();
    const t = world();
    const el = [
      { agent: AGT, authority: "bounded" },
      { agent: AGT2, authority: "bounded" },
    ];
    s.ingest(t, appA, [item({ name: "note.shared", n: 1, instanceId: "a", eligible: el }), item({ name: "note.shared", n: 2, instanceId: "b", eligible: el }), item({ n: 3 })]);
    assert.deepEqual(ns(poll(s, t, AGT).events), [1, 2, 3], "delivered before the purge");
    const purgeA = { kind: "purge", key: "purge-key-a-1", agent: AGT, instanceId: "a" };
    assert.equal(s.ingest(t, appA, [purgeA]).result.results[0]?.status, "stored");
    assert.deepEqual(ns(poll(s, t, AGT).events), [2, 3], "AGT's rows of instance a are gone, delivered or not");
    assert.deepEqual(ns(poll(s, t, AGT2).events), [1, 2, 3], "another agent keeps its rows");
    // events stored after the purge survive its retry
    s.ingest(t, appA, [item({ name: "note.shared", n: 4, instanceId: "a", eligible: el })]);
    assert.equal(s.ingest(t, appA, [purgeA]).result.results[0]?.status, "duplicate");
    assert.deepEqual(ns(poll(s, t, AGT).events), [2, 3, 4]);
    // without agent: every agent's rows of that app instance and instanceId
    assert.equal(s.ingest(t, appA, [{ kind: "purge", key: "purge-key-all-1", instanceId: "a" }]).result.results[0]?.status, "stored");
    assert.deepEqual(ns(poll(s, t, AGT).events), [2, 3]);
    assert.deepEqual(ns(poll(s, t, AGT2).events), [2, 3]);
    // another app's instance with the same instanceId is not touched
    assert.deepEqual(s.ingest(t, appA, [{ kind: "purge", key: "bad" }, { kind: "purge", key: "purge-key-no-ins" }]).result.results.map((x) => x.code), ["event_payload_invalid", "event_payload_invalid"]);
  });
});

describe("delivery re-check (BRIDGE §14.2, rules 1, 5, 6)", () => {
  test("B-EV-6: a grant revoked, narrowed (wf) or expired between write and read → not delivered, the row is dropped", () => {
    const s = fresh();
    const t = world({ grants: [{ agent: AGT, ins: INS_A, mode: "bound", wf: ["notes_list"] }, { agent: AGT2, ins: INS_A }, { agent: AGT3, ins: INS_A }] });
    s.ingest(t, appA, [item({ n: 1 })]);
    const narrowed = world({ grants: [{ agent: AGT, ins: INS_A, mode: "bound", wf: ["notes_create"] }, { agent: AGT3, ins: INS_A, exp: Math.floor(Date.now() / 1000) - 1 }] });
    assert.deepEqual(poll(s, narrowed, AGT).events, [], "wf no longer has the op");
    assert.deepEqual(poll(s, narrowed, AGT2).events, [], "grant removed");
    assert.deepEqual(poll(s, narrowed, AGT3).events, [], "grant expired");
    assert.equal(s.rows(AGT).length, 0, "dropped, not kept");
    assert.equal(poll(s, narrowed, AGT).truncated, false, "a dropped row is not truncation");
  });

  test("B-EV-9: a matching enabled before/after hook → no summary; enabled: false → with it; declared but not listed → none (fail closed)", () => {
    const s = fresh();
    const hook = (phase: "before" | "after" | "context", enabled: boolean, operations?: string[]) => ({ id: `g.${phase}`, ins: INS_B, product: "memo", hookId: phase, phase, order: 1, timeoutMs: 1000, match: { products: ["notes"], ...(operations ? { operations } : {}) }, enabled }) as Table["hooks"][number];
    const base = world();
    s.ingest(base, appA, [item({ n: 1, summary: "Secret-ish" })]);
    const read = (t: Table) => s.rows(AGT).length && (s.page(t, AGT, null, 10)[0] as AgentEvent).summary;
    assert.equal(read(world({ hooks: [hook("before", true)] })), undefined);
    assert.equal(read(world({ hooks: [hook("after", true, ["notes_list"])] })), undefined);
    assert.equal(read(world({ hooks: [hook("after", true, ["notes_create"])] })), "Secret-ish", "a hook on another op");
    assert.equal(read(world({ hooks: [hook("context", true)] })), "Secret-ish", "context hooks do not strip");
    assert.equal(read(world({ hooks: [hook("before", false)] })), "Secret-ish", "switched off by the owner");
    const declaring = runtime(INS_B, "memo", { ...mB, hooks: [{ id: "guard", title: "Guard", phase: "before", order: 1, match: { products: ["*"] } }] });
    assert.equal(read(table({ apps: [appA, declaring], agents: [AGT], grants: [{ agent: AGT, ins: INS_A }] })), undefined, "declared, not in config.hooks");
  });

  test("B-EV-7: instance paused → rows held at write; another app moves the cursor past them; resume → NEW ids > cursor, same origin, old order, before later events", () => {
    const s = fresh();
    const paused = world({ pausedInstances: [INS_A] });
    s.ingest(paused, appA, [item({ n: 1 }), item({ n: 2 })]);
    s.ingest(paused, appB, [item({ n: 3 })]);
    const firstIds = s.rows(AGT).filter((r) => r.held).map((r) => r.id);
    assert.equal(firstIds.length, 2);
    const p1 = poll(s, paused, AGT);
    assert.deepEqual(ns(p1.events), [3]);
    assert.ok((p1.cursor as string) > (firstIds[1] as string), "the cursor moved past the held rows");
    const resumed = world();
    assert.deepEqual(s.onTable(resumed), { released: 4, dropped: 0 }, "two rows each for AGT and AGT2");
    s.ingest(resumed, appA, [item({ n: 4 })]);
    const p2 = poll(s, resumed, AGT, p1.cursor);
    assert.deepEqual(ns(p2.events), [1, 2, 4]);
    const [e1, e2] = p2.events as [AgentEvent, AgentEvent];
    assert.deepEqual([e1.origin, e2.origin], firstIds);
    assert.ok(e1.id !== e1.origin && e1.id > (p1.cursor as string) && e2.id > e1.id);
  });

  test("a row a poll reaches while its instance is paused is marked held (not delivered, not dropped) and re-id'd on resume", () => {
    const s = fresh();
    s.ingest(world(), appA, [item({ n: 1 })]);
    s.ingest(world(), appB, [item({ n: 2 })]);
    const paused = world({ pausedInstances: [INS_A] });
    const p = poll(s, paused, AGT);
    assert.deepEqual(ns(p.events), [2]);
    assert.deepEqual(s.rows(AGT).map((r) => r.held), [true, false]);
    s.onTable(world());
    const after = poll(s, world(), AGT, p.cursor);
    assert.deepEqual(ns(after.events), [1]);
    assert.notEqual(after.events[0]?.id, after.events[0]?.origin);
  });

  test("re-id: across agents and apps, released rows get new ids in OLD-id order; nothing while still paused", () => {
    const s = fresh();
    const paused = world({ pausedInstances: [INS_A, INS_B] });
    s.ingest(paused, appA, [item({ n: 1 })]);
    s.ingest(paused, appB, [item({ n: 2 })]);
    s.ingest(paused, appA, [item({ n: 3 })]);
    assert.deepEqual(s.onTable(paused), { released: 0, dropped: 0 });
    const before = s.rows(AGT).map((r) => r.origin);
    s.onTable(world());
    const rows = s.rows(AGT);
    assert.deepEqual(rows.map((r) => r.origin), before, "same relative order");
    assert.ok(rows.every((r) => !r.held && r.id !== r.origin));
    assert.deepEqual(ns(poll(s, world(), AGT).events), [1, 2, 3]);
    assert.deepEqual(ns(poll(s, world(), AGT2).events), [1, 3]);
  });

  test("agent or workspace pause: poll answers paused with the cursor unchanged; nothing is dropped; stream says paused", () => {
    const s = fresh();
    s.ingest(world(), appA, [item({ n: 1 })]);
    assert.deepEqual(s.poll(world({ pausedAgents: [AGT] }), AGT, null, 50, true), { events: [], cursor: null, truncated: false, paused: true });
    assert.deepEqual(s.stream(AGT, "01HZZZZZZZZZZZZZZZZZZZZZZZ", true), { cursor: "01HZZZZZZZZZZZZZZZZZZZZZZZ", truncated: false, paused: true });
    assert.deepEqual(ns(poll(s, world(), AGT).events), [1]);
  });

  test("a ULID cursor newer than every row = nothing yet (no error); the cursor is kept", () => {
    const s = fresh();
    s.ingest(world(), appA, [item({ n: 1 })]);
    const far = "7ZZZZZZZZZZZZZZZZZZZZZZZZZ";
    assert.deepEqual(poll(s, world(), AGT, far), { events: [], cursor: far, truncated: false });
  });
});

describe("retention (BRIDGE §14.2, C274d ruling 3)", () => {
  test(`B-EV-11: more than ${EVENT_RETENTION_ROWS} rows → the oldest by ingest go; droppedThrough; truncated for a cursor before it; the oldest kept follow in order`, () => {
    const s = fresh();
    const t = world();
    const total = EVENT_RETENTION_ROWS + 50;
    for (let i = 0; i < total; i += 100) s.ingest(t, appB, Array.from({ length: Math.min(100, total - i) }, (_, k) => item({ n: i + k })));
    assert.equal(s.rows(AGT).length, EVENT_RETENTION_ROWS);
    const ret = s.retention(AGT);
    assert.ok(ret.droppedThrough);
    const p = poll(s, t, AGT, null, 3);
    assert.equal(p.truncated, true);
    assert.deepEqual(ns(p.events), [50, 51, 52]);
    assert.equal(poll(s, t, AGT, ret.droppedThrough, 1).truncated, false, "a cursor at droppedThrough lost nothing");
    assert.equal(poll(s, t, AGT, p.cursor, 1).truncated, false);
  });

  test("B-EV-8: a HELD row removed by retention → truncated: true on the next poll whatever the cursor; the flag clears once answered", () => {
    const s = fresh();
    const paused = world({ pausedInstances: [INS_A] });
    s.ingest(paused, appA, [item({ n: 0 })]);
    // the agent reads past it (another app), so its cursor is above the held row's id
    s.ingest(paused, appB, [item({ n: 1 })]);
    const c = poll(s, paused, AGT).cursor;
    s.exec("UPDATE rows SET ingest_at = ingest_at - ? WHERE held = 1", 8 * DAY);
    assert.equal(poll(s, paused, AGT, c).truncated, true, "the held row (below the cursor) was removed");
    assert.equal(s.retention(AGT).heldDropped, false);
    assert.equal(poll(s, paused, AGT, c).truncated, false, "answered once");
  });

  test("age: 7 days from INGEST, and a re-id does not extend it (the oldest by ingest goes first even when its id is the newest)", () => {
    const s = fresh();
    const real = s.now;
    let clock = real();
    s.now = () => clock;
    try {
      s.ingest(world({ pausedInstances: [INS_A] }), appA, [item({ n: 1 })]); // held; ingest = t0
      clock += 2 * DAY;
      s.ingest(world({ pausedInstances: [INS_A] }), appB, [item({ n: 2 })]); // t0 + 2 d
      clock += 1 * DAY;
      s.onTable(world()); // n=1 re-id'd at t0 + 3 d: newest id, oldest ingest
      const rows = s.rows(AGT);
      assert.deepEqual(rows.map((r) => r.type), ["memo.note.created", "notes.note.created"], "id order: the re-id'd row is last");
      clock += 4 * DAY + 1000; // t0 + 7 d + 1 s: n=1 is past 7 days, n=2 is not
      const p = poll(s, world(), AGT);
      assert.deepEqual(ns(p.events), [2]);
      assert.equal(p.truncated, true);
      assert.equal(s.retention(AGT).droppedThrough, rows[1]?.id, "droppedThrough = the re-id'd row's (new) id");
      // the sweep applies the age rule to agents nobody reads
      clock += 3 * DAY;
      s.sweep();
      assert.equal(s.rows(AGT).length, 0);
      assert.equal(s.rows(AGT2).length, 0);
    } finally {
      s.now = real;
    }
  });
});

describe("G2b: the update candidate's declarations (BRIDGE §14.1 step 1, §14.2)", () => {
  const candOps = [op("notes_archive", ["read"], "read")];
  const mCand = eventsManifest("3.0.0", candOps, [ev("note.archived", "notes_archive")]);
  const candDigest = runtime(INS_A, "notes", mCand).digest as string;
  /** serving = mA (running), candidate = mCand */
  const attempt = () => runtime(INS_A, "notes", mA, { candidateManifestDigest: candDigest as never, candidateVersion: "3.0.0" });

  test("a name only the candidate declares: needs the candidate's manifest; stored HELD; the switch releases it with a new id", () => {
    const s = fresh();
    const a = attempt();
    const t = world({ apps: [a, appB] });
    s.onTable(t);
    assert.deepEqual(s.needs(a, [item({ name: "note.archived" })]), { missing: "candidate" });
    assert.deepEqual(s.needs(a, [item({ name: "note.created" })]), { missing: null }, "the serving manifest declares it");
    s.remember(candDigest, mCand as never);
    assert.deepEqual(s.needs(a, [item({ name: "note.archived" })]), { missing: null });
    const r = s.ingest(t, a, [item({ name: "note.archived", n: 1 }), item({ n: 2 })]);
    assert.deepEqual(r.result.results.map((x) => x.recipients), [2, 2]);
    const p0 = poll(s, t, AGT);
    assert.deepEqual(ns(p0.events), [2], "the op is not in the serving manifest yet: held");
    assert.deepEqual(s.onTable(t), { released: 0, dropped: 0 }, "still waiting while the attempt runs");
    // the switch: the candidate becomes serving
    const switched = world({ apps: [runtime(INS_A, "notes", mCand), appB] });
    assert.deepEqual(s.onTable(switched), { released: 2, dropped: 0 });
    const p = poll(s, switched, AGT, p0.cursor);
    assert.deepEqual(ns(p.events), [1], "released after the cursor that moved past it");
    assert.notEqual(p.events[0]?.id, p.events[0]?.origin);
  });

  test("rollback: a held row whose op the serving manifest lacks is dropped once no attempt runs", () => {
    const s = fresh();
    const a = attempt();
    const t = world({ apps: [a, appB] });
    s.remember(candDigest, mCand as never);
    s.ingest(t, a, [item({ name: "note.archived", n: 1 })]);
    assert.equal(s.rows(AGT).length, 1);
    assert.deepEqual(s.onTable(world()), { released: 0, dropped: 2 });
    assert.deepEqual(poll(s, world(), AGT).events, []);
  });

  test("the serving declaration wins over the candidate's; an op whose scopeType changed by the switch drops the row", () => {
    const s = fresh();
    const t = world();
    s.ingest(t, appA, [item({ n: 1 })]);
    // the new serving release makes notes_list scoped: rows recorded as unscoped no longer match → dropped
    const mScoped = { ...mA, version: "4.0.0", operations: (mA.operations as { id: string }[]).map((o) => (o.id === "notes_list" ? { ...o, scopeType: "notebook" } : o)) };
    const t2 = world({ apps: [runtime(INS_A, "notes", mScoped), appB] });
    assert.deepEqual(poll(s, t2, AGT).events, []);
    assert.equal(s.rows(AGT).length, 0);
  });

  test("manifests are content-addressed: a cached manifest is used only under its own digest; digests the config no longer names are forgotten", () => {
    const s = fresh();
    s.remember(candDigest, mA as never); // wrong bytes for that digest: ignored
    assert.equal(s.candidate(attempt()), undefined);
    s.remember(candDigest, mCand as never);
    s.onTable(world({ apps: [attempt(), appB] }));
    assert.ok(s.candidate(attempt()));
    s.onTable(world());
    assert.equal(s.candidate(attempt()), undefined, "forgotten once no entry names it");
  });
});

describe("ids (BRIDGE §14.2: a ULID, strictly increasing per bridge)", () => {
  test("strictly increasing under a burst, after the clock steps back, and after a reopen of the same file", () => {
    const o = openStore();
    dirs.push(o.dir);
    let s = o.store;
    const t = world();
    for (let i = 0; i < 20; i++) s.ingest(t, appB, Array.from({ length: 100 }, (_, k) => item({ n: i * 100 + k })));
    const real = s.now;
    s.now = () => real() - 3_600_000; // an hour back
    s.ingest(t, appB, [item({ n: 99_999 })]);
    const ids = s.rows(AGT).map((r) => r.id);
    assert.equal(ids.length, 2001);
    assert.ok(ids.every((id, i) => /^[0-9A-HJKMNP-TV-Z]{26}$/.test(id) && (i === 0 || id > (ids[i - 1] as string))));
    const last = ids.at(-1) as string;
    s.close();
    s = new EventStore({ path: o.path, log: silentLogger, digestOf: () => "", hookMatches: () => false });
    stores.push(s);
    s.now = () => real() - 7_200_000;
    s.ingest(t, appB, [item({ n: 100_000 })]);
    const after = s.rows(AGT).map((r) => r.id);
    assert.ok((after.at(-1) as string) > last, "the reopened store continues above the last id");
  });

  test("ulidAfter increments the last character with carry", () => {
    assert.equal(ulidAfter("01HZZZZZZZZZZZZZZZZZZZZZZ0"), "01HZZZZZZZZZZZZZZZZZZZZZZ1");
    assert.equal(ulidAfter("01HZZZZZZZZZZZZZZZZZZZZZZZ"), "01J00000000000000000000000");
    assert.throws(() => ulidAfter("ZZZZZZZZZZZZZZZZZZZZZZZZZZ"));
  });
});

describe("tealbrick/events/list (BRIDGE §14.3)", () => {
  test("the types visible now: rule 1 for unscoped types, the owner rule (agent op + wf) for scoped ones, tb.hold.decided per granted app", () => {
    const s = fresh();
    const t = world();
    const types = s.list(t, AGT).types;
    const notes = types.filter((x) => x.app === "notes").map((x) => `${x.type}${x.scoped ? " (scoped)" : ""}`);
    assert.deepEqual(notes, ["notes.note.created", "notes.note.pinged", "notes.note.shared (scoped)", "notes.note.edited (scoped)", "tb.hold.decided"]);
    assert.ok(types.every((x) => JSON.stringify(x.delivery) === JSON.stringify(["poll", "stream"])));
    // a bound grant whose wf lacks the scoped op: not listed
    const bound = world({ grants: [{ agent: AGT, ins: INS_A, mode: "bound", wf: ["notes_list"] }] });
    assert.deepEqual(
      s.list(bound, AGT).types.map((x) => x.type),
      ["notes.note.created", "notes.note.pinged", "tb.hold.decided"],
    );
  });
});

describe("rules from @opt2-tealbrick/manifest (L1)", () => {
  test("the store imports the shared event rules and keeps no copy of them", async () => {
    const { readFileSync } = await import("node:fs");
    const src = readFileSync(new URL("../src/events.ts", import.meta.url), "utf8");
    const imports = src.slice(0, src.indexOf('from "@opt2-tealbrick/manifest"'));
    for (const name of ["eventDecl", "eventScopeType", "eventVisibleToGrant", "validateEventPayload", "EVENT_KEY_RE", "EVENT_ITEM_MAX_BYTES"]) assert.ok(new RegExp(`\\b${name}\\b`).test(imports), `${name} imported`);
    assert.ok(!/function (eventDecl|eventScopeType|eventVisibleToGrant|validateEventPayload)\b/.test(src));
  });
});

describe("review round 1 (bridge#16): limits, failures, documented edges", () => {
  const many = Array.from({ length: 500 }, (_, i) => `agt_01HM${String(i).padStart(22, "0")}`);
  const crowd = (o: Partial<Parameters<typeof table>[0]> = {}): Table =>
    table({ apps: [appA, appB], agents: [...many, AGT], grants: [...many.map((agent) => ({ agent, ins: INS_A })), { agent: AGT, ins: INS_B }], ...o });

  test(`S3: stored rows per app instance are limited (${EVENT_FANOUT_LIMIT.perMinute}/min, burst ${EVENT_FANOUT_LIMIT.burst}); a 500-agent flood is throttled with 429 + Retry-After, nothing of the refused batch is stored, other apps keep arriving`, () => {
    const s = fresh();
    const real = s.now;
    let clock = real();
    s.now = () => clock;
    try {
      const t = crowd();
      const batch = () => Array.from({ length: 10 }, () => item({ n: 1 }));
      for (let i = 0; i < 6; i++) assert.equal(s.ingest(t, appA, batch()).result.results[0]?.recipients, 500); // 30 000 rows
      const refused = batch();
      assert.throws(
        () => s.ingest(t, appA, refused),
        (e: unknown) => e instanceof EventIngestLimit && e.status === 429 && e.retryAfterS >= 1,
      );
      assert.equal(s.rows(many[0] as string).length, 60, "nothing of the refused batch was stored");
      // another app instance is not limited by A's bucket
      assert.equal(s.ingest(t, appB, [item({ n: 2 })]).result.results[0]?.recipients, 1);
      // the SDK retries the SAME keys after Retry-After: not duplicates (the keys were not consumed), stored now
      clock += 60_000;
      assert.deepEqual(s.ingest(t, appA, refused).result.results.map((x) => x.status), Array(10).fill("stored"));
    } finally {
      s.now = real;
    }
  });

  test("S3: a batch that alone fans out beyond the burst → 413 (the SDK halves the batch); nothing stored", () => {
    const s = fresh();
    assert.throws(
      () => s.ingest(crowd(), appA, Array.from({ length: 61 }, () => item({ n: 1 }))),
      (e: unknown) => e instanceof EventIngestLimit && e.status === 413,
    );
    assert.equal(s.rows(many[0] as string).length, 0);
  });

  test("S4b: a rolled-back batch leaves no stale row counts (no false retention deletes afterwards)", () => {
    const s = fresh();
    const t = crowd();
    // AGT holds 9 990 rows of app B
    for (let i = 0; i < 9_990; i += 100) s.ingest(t, appB, Array.from({ length: Math.min(100, 9_990 - i) }, (_, k) => item({ n: i + k })));
    // a batch where AGT is one of 501 recipients per item and that is refused (413) after many inserts
    const both = table({ apps: [appA, appB], agents: [...many, AGT], grants: [...many.map((agent) => ({ agent, ins: INS_A })), { agent: AGT, ins: INS_A }, { agent: AGT, ins: INS_B }] });
    assert.throws(() => s.ingest(both, appA, Array.from({ length: 60 }, () => item({ n: 1 }))), EventIngestLimit);
    s.ingest(t, appB, Array.from({ length: 10 }, (_, k) => item({ n: 20_000 + k })));
    assert.equal(s.rows(AGT).length, 10_000);
    assert.equal(s.retention(AGT).droppedThrough, null, "nothing was removed: exactly 10 000 rows");
  });

  const withHealth = (path?: string) => {
    const dir = path ? undefined : mkdtempSync(join(tmpdir(), "tb-events-health-"));
    if (dir) dirs.push(dir);
    const flips: boolean[] = [];
    const st = new EventStore({ path: path ?? join(dir as string, "events.db"), log: silentLogger, digestOf: (m) => api.manifestDigest(m), hookMatches: () => false, onHealth: (x) => flips.push(x) });
    stores.push(st);
    flips.length = 0; // the first open is not a flip
    return { st, flips, dir: dir as string };
  };

  test("round 2 / 2: only I/O-class SQLite errors mark the store unhealthy; other errors are that request's failure", () => {
    const { st } = withHealth();
    assert.equal(isStorageFailure({ errcode: 13 }), true, "FULL");
    assert.equal(isStorageFailure({ errcode: 266 }), true, "IOERR_READ (extended code)");
    for (const c of [8, 10, 11, 14, 26]) assert.equal(isStorageFailure({ errcode: c }), true);
    for (const c of [1, 5, 19, 2067]) assert.equal(isStorageFailure({ errcode: c }), false, `code ${c}`);
    assert.equal(isStorageFailure(new Error("x")), false);
    st.exec("CREATE TRIGGER fail_rows BEFORE INSERT ON rows BEGIN SELECT RAISE(ABORT, 'refused by a trigger'); END");
    assert.throws(() => st.ingest(world(), appA, [item({ n: 1 })]));
    assert.equal(st.healthy, true, "a logic/constraint error is not a storage failure");
    st.exec("DROP TRIGGER fail_rows");
    assert.equal(st.ingest(world(), appA, [item({ n: 2 })]).result.results[0]?.status, "stored");
  });

  test("round 2 / 2: hysteresis — ingest refuses at once; the cap goes only after 5 min unhealthy and comes back after 3 good probes; no flip inside the window", () => {
    const { st, flips } = withHealth();
    let clock = Date.now();
    st.now = () => clock;
    st.exec("PRAGMA query_only = 1"); // every write now fails with SQLITE_READONLY
    assert.throws(() => st.ingest(world(), appA, [item({ n: 1 })]));
    assert.equal(st.healthy, false, "ingest answers 503 at once");
    assert.equal(st.available, true);
    assert.deepEqual(bridgeCaps({ events: st }), ["owner_rows", "events"], "the cap stays inside the window");
    clock += 4 * 60_000;
    assert.equal(st.probe(), false);
    assert.deepEqual(bridgeCaps({ events: st }), ["owner_rows", "events"]);
    assert.deepEqual(flips, [], "no status poke inside the window");
    clock += 60_000; // 5 min continuously unhealthy
    st.probe();
    assert.deepEqual(bridgeCaps({ events: st }), ["owner_rows"]);
    assert.equal(st.available, false);
    assert.deepEqual(flips, [false]);
    st.exec("PRAGMA query_only = 0");
    for (let i = 1; i <= 2; i++) {
      clock += 60_000;
      assert.equal(st.probe(), true);
      assert.equal(st.available, false, `${i} good probe(s): not yet`);
      assert.equal(st.healthy, false, "no ingest while the cap is withdrawn");
    }
    clock += 60_000;
    st.probe();
    assert.equal(st.available, true);
    assert.equal(st.healthy, true);
    assert.deepEqual(flips, [false, true]);
    // a bad probe in between restarts the count of good ones
    st.exec("PRAGMA query_only = 1");
    st.probe();
    clock += 5 * 60_000;
    st.probe();
    assert.deepEqual(flips, [false, true, false]);
    st.exec("PRAGMA query_only = 0");
    st.probe();
    st.probe();
    st.exec("PRAGMA query_only = 1");
    st.probe();
    st.exec("PRAGMA query_only = 0");
    st.probe();
    st.probe();
    assert.equal(st.available, false, "2 + 2 good probes with a bad one between: not restored");
    st.probe();
    assert.equal(st.available, true);
  });

  test("round 2 / 2: a short outage (recovered within 5 min) never withdraws the cap and pokes nothing; onTable never throws", () => {
    const { st, flips } = withHealth();
    let clock = Date.now();
    st.now = () => clock;
    st.exec("PRAGMA query_only = 1");
    assert.throws(() => st.ingest(world(), appA, [item({ n: 1 })]));
    const other = runtime(INS_A, "notes", { ...mA, version: "9.0.0" });
    assert.deepEqual(st.onTable(world({ apps: [other, appB] })), { released: 0, dropped: 0 }, "an event-log failure never throws into the config apply");
    clock += 2 * 60_000;
    st.exec("PRAGMA query_only = 0");
    assert.equal(st.probe(), true);
    assert.equal(st.healthy, true);
    clock += 10 * 60_000;
    st.sweep();
    assert.deepEqual(flips, []);
    assert.deepEqual(bridgeCaps({ events: st }), ["owner_rows", "events"]);
    assert.deepEqual(bridgeCaps({ events: undefined }), ["owner_rows"], "no store: no events cap");
  });

  test("round 2 / 3: a NOTADB file is moved aside and a fresh log starts with a reset point: truncated only for a cursor below it", () => {
    const dir = mkdtempSync(join(tmpdir(), "tb-events-corrupt-"));
    dirs.push(dir);
    const path = join(dir, "events.db");
    writeFileSync(path, "this is not a sqlite database at all, just bytes".repeat(100));
    const oldCursor = ulidAfter("01HZZZZZZZZZZZZZZZZZZZZZZZ"); // an id of the lost log
    const { st } = withHealth(path);
    assert.equal(st.available, true);
    assert.ok(readdirSync(dir).some((f) => /^events\.db\.corrupt-\d+$/.test(f)));
    st.ingest(world(), appA, [item({ n: 1 })]);
    const first = st.rows(AGT)[0]?.id ?? "";
    assert.match(first, /^[0-9A-HJKMNP-TV-Z]{26}$/);
    assert.equal(poll(st, world(), AGT, oldCursor).truncated, true, "a cursor of the old log");
    assert.equal(poll(st, world(), AGT, oldCursor).truncated, true, "every time, not once");
    assert.equal(poll(st, world(), AGT, null).truncated, false, "no cursor: not truncated");
    assert.equal(poll(st, world(), AGT, first).truncated, false, "a cursor of the new log");
    st.close();
    // the reset point survives a reopen
    const { st: again } = withHealth(path);
    assert.equal(poll(again, world(), AGT, oldCursor).truncated, true);
    again.ingest(world(), appA, [item({ n: 2 })]);
    assert.ok((again.rows(AGT).at(-1)?.id ?? "") > first);
  });

  test("round 2 / 3: any other open failure (a NEWER schema, an unopenable path) never renames the file; the bridge runs without the log and the probe retries", async () => {
    const { DatabaseSync } = await import("node:sqlite");
    const { st, dir } = withHealth();
    st.ingest(world(), appA, [item({ n: 1 })]);
    st.close();
    const path = join(dir, "events.db");
    const raw = new DatabaseSync(path);
    raw.prepare("UPDATE meta SET v = '99' WHERE k = 'schema'").run();
    raw.close();
    const { st: newer, flips } = withHealth(path);
    assert.equal(newer.available, false);
    assert.equal(newer.healthy, false);
    assert.deepEqual(bridgeCaps({ events: newer }), ["owner_rows"]);
    assert.ok(!readdirSync(dir).some((f) => f.includes("corrupt")), "never renamed");
    assert.equal(newer.probe(), false, "still newer");
    // the downgrade is undone (this bridge's schema again): the probe opens it, rows intact
    const fix = new DatabaseSync(path);
    fix.prepare("UPDATE meta SET v = '1' WHERE k = 'schema'").run();
    fix.close();
    assert.equal(newer.probe(), true);
    assert.equal(newer.available, true);
    assert.deepEqual(flips, [true]);
    assert.equal(newer.rows(AGT).length, 1);
    const { st: nowhere } = withHealth(join(dir, "missing", "dir", "events.db"));
    assert.equal(nowhere.available, false);
    assert.equal(nowhere.probe(), false);
    assert.ok(!existsSync(join(dir, "missing")));
  });

  test("S4c (documented, spec-literal): a re-id'd row the agent already read under its old id, later removed by retention, answers truncated: true", () => {
    const s = fresh();
    const real = s.now;
    let clock = real();
    s.now = () => clock;
    try {
      s.ingest(world(), appA, [item({ n: 1 })]);
      const read = poll(s, world(), AGT); // delivered under its first id
      assert.deepEqual(ns(read.events), [1]);
      // a stale reader (cursor null) reaches it while the instance is paused: held, then re-id'd on resume
      poll(s, world({ pausedInstances: [INS_A] }), AGT, null);
      s.onTable(world());
      clock += 2 * DAY;
      s.ingest(world(), appB, [item({ n: 2 })]);
      clock += 5 * DAY + 1000; // the n=1 row is past 7 days from ingest
      const p = poll(s, world(), AGT, read.cursor);
      // BRIDGE §14.3 as written: droppedThrough (the row's NEW id) > the cursor → truncated, although the agent had read it
      assert.equal(p.truncated, true);
      assert.deepEqual(ns(p.events), [2]);
    } finally {
      s.now = real;
    }
  });

  test("S4e: events/list skips paused and down instances, as tools/list does", () => {
    const s = fresh();
    assert.ok(s.list(world(), AGT).types.some((x) => x.app === "notes"));
    assert.ok(!s.list(world({ pausedInstances: [INS_A] }), AGT).types.some((x) => x.app === "notes"));
    assert.ok(!s.list(world({ apps: [{ ...appA, down: true }, appB] }), AGT).types.some((x) => x.app === "notes"));
    assert.ok(s.list(world({ pausedInstances: [INS_A] }), AGT).types.some((x) => x.app === "memo"));
  });
});
