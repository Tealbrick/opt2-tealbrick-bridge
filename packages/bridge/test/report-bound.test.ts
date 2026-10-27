// QA bridge#26: the status report stays under Core's 256 KiB ack cap whatever one app reports (S2: 443 KB on main), and the
// scope sources carry only the app's own instance ids with labels cut at a code point (a lone surrogate breaks Postgres jsonb).
import assert from "node:assert/strict";
import { test } from "node:test";
import type { StatusReport } from "@opt2-tealbrick/spec/bridge";
import { boundStatusReport, REPORT_ATTENTION_MAX, REPORT_CONNECTIONS_SEEN_MAX, REPORT_PER_APP_MAX, STATUS_REPORT_MAX_BYTES } from "../src/portal.ts";
import { clampCodePoints, isOwnInstanceId, SOURCE_ID_RE, scopeSourceItems } from "../src/scope-summary.ts";

const INS = "ins_01M5Q00000000000000000BIG0";
const INS2 = "ins_01M5Q00000000000000000SMAL";
const base = (): StatusReport =>
  ({
    rev: 1, appliedAt: "2026-10-24T09:00:00.000Z", bridge: { id: "brg_x", version: "0.2.7", form: "deployed", boot: "b", sdkMajors: [0], mcpVersions: [] },
    portalReachable: true, apps: [], keys: [], scopeSummaries: [], connectionsCreated: [], connectionsRevoked: [], claims: [], rejected: [], toolsOmitted: [],
  }) as unknown as StatusReport;
const bytes = (r: StatusReport) => Buffer.byteLength(JSON.stringify(r), "utf8");
const marker = (r: StatusReport, code: string, ins: string) => r.rejected.find((x) => x.kind === "bridge_op" && x.code === code && x.ins === ins)?.count;

test("a small report is returned unchanged (same object, no marker)", () => {
  const r = base();
  assert.equal(boundStatusReport(r), r);
});

test("S2: one app with thousands of omitted tools is cut per app with a marker; another app's rows stay", () => {
  const r = base();
  r.toolsOmitted = [
    ...Array.from({ length: 4000 }, (_, i) => ({ ins: INS as never, name: `${"x".repeat(110)}_${i}`, code: "ceiling" as const })),
    { ins: INS2 as never, name: "small_tool", code: "ceiling" as const },
  ];
  assert.ok(bytes(r) > STATUS_REPORT_MAX_BYTES, "the input is over the cap (like the 443 KB report)");
  const out = boundStatusReport(r);
  assert.ok(bytes(out) <= STATUS_REPORT_MAX_BYTES);
  assert.equal(out.toolsOmitted.filter((t) => t.ins === INS).length, REPORT_PER_APP_MAX);
  assert.equal(marker(out, "report_truncated_tools", INS), 4000 - REPORT_PER_APP_MAX);
  assert.ok(out.toolsOmitted.some((t) => t.ins === INS2), "the small app keeps its row");
  assert.equal(marker(out, "report_truncated_tools", INS2), undefined);
});

test("sources are stripped only from the app that grew; another app keeps its sources", () => {
  const r = base();
  const big = Array.from({ length: 20 }, (_, i) => ({ type: "account", id: `acc_${i}`, label: "L".repeat(60), access: "read" }));
  const small = [{ type: "account", id: "acc_small", label: "Small", access: "read" }];
  r.scopeSummaries = [
    ...Array.from({ length: 300 }, (_, i) => ({ agt: `agt_${i}` as never, ins: INS as never, label: "1 account", sources: big }) as never),
    { agt: "agt_small" as never, ins: INS2 as never, label: "1 account", sources: small } as never,
  ];
  const out = boundStatusReport(r);
  assert.ok(bytes(out) <= STATUS_REPORT_MAX_BYTES);
  assert.deepEqual((out.scopeSummaries.find((s) => s.ins === INS2) as { sources?: unknown[] }).sources, small);
  assert.equal(marker(out, "report_truncated_sources", INS2), undefined);
});

test("QA round 2: long attention reasons of many apps are shortened (heaviest first), with a marker per app", () => {
  const r = base();
  r.apps = Array.from({ length: 64 }, (_, i) => ({ ins: `ins_${i}` as never, state: "degraded", version: "1.0.0", sdkVersion: "0.1.38", manifestDigest: null, lastSeen: null, pendingHolds: 0, attention: { code: "engine_down", reason: "R".repeat(16_000) } }) as never);
  assert.ok(bytes(r) > STATUS_REPORT_MAX_BYTES);
  const out = boundStatusReport(r);
  assert.ok(bytes(out) <= STATUS_REPORT_MAX_BYTES);
  const reasons = out.apps.map((a) => (a.attention as { reason: string } | undefined)?.reason.length ?? 0);
  assert.ok(reasons.some((n) => n === REPORT_ATTENTION_MAX), "shortened, not dropped");
  assert.ok(out.apps.every((a) => (a.attention as { code: string } | undefined)?.code === "engine_down"), "the code stays");
  assert.ok(out.rejected.filter((x) => x.code === "report_truncated_attention").length > 0);
});

test("sources go first: when dropping them is enough, nothing else is cut", () => {
  const r = base();
  const sources = Array.from({ length: 20 }, (_, i) => ({ type: "account", id: `acc_${i}`, label: "L".repeat(60), access: "read" }));
  r.scopeSummaries = Array.from({ length: 300 }, (_, i) => ({ agt: `agt_${i}` as never, ins: INS as never, label: "1 account", sources }) as never);
  assert.ok(bytes(r) > STATUS_REPORT_MAX_BYTES);
  const out = boundStatusReport(r);
  assert.ok(bytes(out) <= STATUS_REPORT_MAX_BYTES);
  assert.equal(out.scopeSummaries.length, 300, "every label stays");
  assert.ok(out.scopeSummaries.every((s) => !("sources" in s)));
  assert.equal(marker(out, "report_truncated_sources", INS), 300);
});

test("scope summaries are cut per app, then dropped whole, only when still over", () => {
  const r = base();
  r.scopeSummaries = Array.from({ length: 4000 }, (_, i) => ({ agt: `agt_${i}` as never, ins: INS as never, label: "L".repeat(80) }));
  const out = boundStatusReport(r);
  assert.ok(bytes(out) <= STATUS_REPORT_MAX_BYTES);
  assert.equal(out.scopeSummaries.length, REPORT_PER_APP_MAX);
  assert.equal(marker(out, "report_truncated_scopes", INS), 4000 - REPORT_PER_APP_MAX);
});

test("the source id is the app's own: Tealbrick ids and slugs pass, provider-shaped ids are dropped", () => {
  // the ids the apps use today: Connect accounts, Task Board projects and agent projects, Knowledge areas
  for (const id of ["cna_01M5PNG40MSQ8RJG3CEZ95Z0ZY", "prj_01M5PNG40MSQ8RJG3CEZ95Z0ZY", "agt_01M5PM72GE2Q843A6AJ77DWQH0", "company", "agent-01m5pm72ge2q843a6aj77dwqh0", "nb_1", "area-sales"]) {
    assert.ok(isOwnInstanceId(id), id);
  }
  for (const id of ["cus_bYze8b07KDY7UK", "C04ACMESUPP", "U0HUMAN001", "1hP4rQ7vXyZ", "ann@example.test", "14155550100", "", "x".repeat(65)]) assert.ok(!SOURCE_ID_RE.test(id), id);
  // QA round 2: lower-case provider-shaped ids
  for (const id of ["3f2504e0-4f89-11d3-9a0c-0305e82c3301", "acct_1nfj39fjk2", "cus_ab12cd34ef", "ch_3mmllrlkdiwhu7ix"]) assert.ok(!isOwnInstanceId(id), id);
  const items = scopeSourceItems([
    { type: "account", id: "cna_01M5PNG40MSQ8RJG3CEZ95Z0ZY", label: "Acme data", access: "read" },
    { type: "account", id: "cus_bYze8b07KDY7UK", label: "Stripe customer", access: "read" },
  ]);
  assert.deepEqual(items?.map((i) => i.id), ["cna_01M5PNG40MSQ8RJG3CEZ95Z0ZY"]);
});

test("QA round 2: a lone surrogate already in the input label becomes U+FFFD (Postgres jsonb would refuse the report)", () => {
  const lone = String.fromCharCode(0xd83d);
  const items = scopeSourceItems([{ type: "account", id: "acc_1", label: `Team ${lone}notes`, access: "read" }]);
  assert.equal(items?.[0]?.label, `Team ${String.fromCharCode(0xfffd)}notes`);
  assert.equal(items?.[0]?.label.isWellFormed(), true);
  assert.equal(clampCodePoints(`x${String.fromCharCode(0xdc00)}`, 60).isWellFormed(), true);
});

test("labels are cut at a code point: no lone surrogate", () => {
  const emoji = String.fromCodePoint(0x1f600);
  const label = `${"a".repeat(59)}${emoji}${emoji}`;
  assert.equal(label.slice(0, 60).at(-1)?.charCodeAt(0) === 0xd83d, true, "a UTF-16 cut would leave half a pair");
  const cut = clampCodePoints(label, 60);
  assert.equal(Array.from(cut).length, 60);
  assert.ok(!/[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/u.test(cut), "no lone surrogate");
  const items = scopeSourceItems([{ type: "account", id: "acc_1", label, access: "read" }]);
  assert.equal(items?.[0]?.label, cut);
});

test("QA-BR26D-2: stages 3 and 4 on the same app leave ONE marker per code with the total cut; attention stages 2 and 5 count the app once", () => {
  const r = base();
  r.toolsOmitted = Array.from({ length: 60 }, (_, i) => ({ ins: INS as never, name: `${"t".repeat(60)}${i}`, code: "ceiling" as const }));
  r.scopeSummaries = Array.from({ length: 60 }, (_, i) => ({ agt: `agt_${i}` as never, ins: INS as never, label: "L".repeat(80) }));
  r.apps = [{ ins: INS as never, state: "degraded", version: "1.0.0", sdkVersion: "0.1.38", manifestDigest: null, lastSeen: null, pendingHolds: 0, attention: { code: "engine_down", reason: "R".repeat(2000) } } as never];
  const out = boundStatusReport(r, 300);
  // every cut ran: stage 3 left 50 + 50, stage 4 emptied both, stage 2 shortened the reason, stage 5 dropped it
  assert.equal(out.toolsOmitted.length, 0);
  assert.equal(out.scopeSummaries.length, 0);
  assert.equal(out.apps[0]?.attention, undefined);
  const rows = (code: string) => out.rejected.filter((x) => x.kind === "bridge_op" && x.code === code && x.ins === INS);
  assert.deepEqual(rows("report_truncated_tools").map((x) => x.count), [60], "10 cut by stage 3 + 50 by stage 4");
  assert.deepEqual(rows("report_truncated_scopes").map((x) => x.count), [60]);
  assert.deepEqual(rows("report_truncated_attention").map((x) => x.count), [1], "one attention, cut twice");
  const keys = out.rejected.map((x) => `${x.kind}|${x.code}|${x.ins ?? ""}`);
  assert.equal(new Set(keys).size, keys.length, "no duplicate (kind, code, app) row");
});

test("a marker the bridge did not add is not merged into (an app's own bridge_op row keeps its count)", () => {
  const r = base();
  r.rejected = [{ kind: "bridge_op", code: "report_truncated_tools", count: 7, ins: INS as never }];
  r.toolsOmitted = Array.from({ length: 4000 }, (_, i) => ({ ins: INS as never, name: `${"x".repeat(110)}_${i}`, code: "ceiling" as const }));
  const out = boundStatusReport(r);
  assert.deepEqual(out.rejected.map((x) => x.count), [7, 4000 - REPORT_PER_APP_MAX]);
});

const ROLES = ["embeddings", "rerank", "reasoning", "utility", "dreaming", "summarize", "vision", "transcribe"] as const;
function maxReport(n: number): { r: StatusReport; apps: { ins: string }[] } {
  const r = base();
  const apps = Array.from({ length: n }, (_, i) => ({ ins: `ins_${String(i).padStart(26, "0")}` }));
  r.apps = apps.map(({ ins }) => ({
    ins: ins as never, state: "degraded", version: "10.20.30-rc.1234567890123456789012345678901234567890", sdkVersion: "0.1.38", manifestDigest: `sha256:${"a".repeat(64)}`,
    lastSeen: "2026-10-27T00:00:00.000Z", pendingHolds: 999999, sliceRevision: 123456789, attention: { code: "engine_down", reason: "R".repeat(300) },
    schemaVersion: { app: 123456789, sdk: 123456789 }, minCompatibleCode: "999999999.999999999.999999999",
    failure: { phase: "app_migrations", code: "c".repeat(64), reason: "r".repeat(64), file: `0001_${"x".repeat(80)}.ts`, at: "2026-10-27T00:00:00.000Z" },
    preUpdateSnapshot: { file: "f".repeat(200), sha256: "0".repeat(64), createdAt: "2026-10-27T00:00:00.000Z", from: "1.0.0", to: "2.0.0" },
  }) as never);
  r.keys = apps.flatMap(({ ins }) => Array.from({ length: 10 }, (_, k) => ({ name: `KEY_${"N".repeat(40)}${k}`, ins: ins as never, set: true })));
  r.roles = apps.flatMap(({ ins }) => ROLES.map((role) => ({ role, ins: ins as never, set: true, policyOk: true, provider: "openrouter", model: "m".repeat(128), dataPolicy: "standard" as const, policyBasis: "verified" as const })));
  r.connectionsSeen = Array.from({ length: 500 }, (_, i) => ({ con: `con_${String(i).padStart(26, "0")}` as never, lastSeen: "2026-10-27T00:00:00.000Z" }));
  // fields that are never cut: the apps' own refusals (two per app), one claim per app and the bridge caps
  r.rejected = apps.flatMap(({ ins }) => ["manifest_invalid", "bridge_cap_missing"].map((code) => ({ kind: "manifest" as const, code, count: 5, ins: ins as never })));
  r.claims = apps.map(({ ins }) => ({ kind: "app", ins: ins as never, publicKey: { kty: "OKP", crv: "Ed25519", x: "x".repeat(43) }, manifestDigest: `sha256:${"b".repeat(64)}`, version: "10.20.30", internalUrl: `http://${"h".repeat(60)}.railway.internal:8080`, codeDigest: `sha256:${"c".repeat(64)}`, claimedAt: "2026-10-27T00:00:00.000Z" }) as never);
  r.bridge.caps = Array.from({ length: 30 }, (_, i) => `cap_${i}` as never);
  return { r, apps };
}

test("QA-BR26D-3: 40 max-size apps with roles, keys and connectionsSeen at their maxima stay under the bound (connectionsSeen cut first)", () => {
  const { r } = maxReport(40);
  assert.ok(bytes(r) > STATUS_REPORT_MAX_BYTES, `the input is over the cap (${bytes(r)})`);
  const out = boundStatusReport(r);
  assert.ok(bytes(out) <= STATUS_REPORT_MAX_BYTES, `bounded (${bytes(out)})`);
  assert.equal(out.connectionsSeen?.length, REPORT_CONNECTIONS_SEEN_MAX);
  assert.equal(out.connectionsSeen?.at(-1)?.con, r.connectionsSeen?.at(-1)?.con, "the newest connections stay");
  assert.equal(out.connectionsSeen?.[0]?.con, r.connectionsSeen?.[500 - REPORT_CONNECTIONS_SEEN_MAX]?.con);
  assert.deepEqual(out.rejected.filter((x) => x.code === "report_truncated_connections"), [{ kind: "bridge_op", code: "report_truncated_connections", count: 500 - REPORT_CONNECTIONS_SEEN_MAX }]);
  assert.equal(out.apps.length, 40);
  assert.equal(out.keys.length, 400, "keys are never cut");
  assert.deepEqual(out.roles, r.roles, "when connectionsSeen is enough, the roles stay whole");
});

const N = 50;
test(`QA-BR26D-3: ${N} max-size apps: after connectionsSeen, the role detail goes app by app, required members stay, one marker per app`, () => {
  const { r } = maxReport(N);
  const out = boundStatusReport(r);
  assert.ok(bytes(out) <= STATUS_REPORT_MAX_BYTES, `bounded (${bytes(out)})`);
  assert.equal(out.connectionsSeen?.length, REPORT_CONNECTIONS_SEEN_MAX);
  assert.equal(out.keys.length, N * 10, "keys are never cut");
  assert.equal(out.roles?.length, N * ROLES.length, "no role row is dropped");
  const marks = out.rejected.filter((x) => x.code === "report_truncated_roles");
  const slimmed = new Set(marks.map((x) => x.ins));
  assert.equal(slimmed.size, marks.length, "one marker per app");
  assert.ok(slimmed.size > 0 && slimmed.size < N, `some apps were cut (${slimmed.size}), the cut stopped when the report fit`);
  for (const m of marks) assert.equal(m.count, ROLES.length);
  for (const x of out.roles ?? []) {
    if (slimmed.has(x.ins)) assert.deepEqual([x.provider, x.model, x.dataPolicy, x.policyBasis, x.set, x.policyOk], [null, null, null, undefined, true, true]);
    else assert.deepEqual([x.provider, x.dataPolicy, x.policyBasis], ["openrouter", "standard", "verified"]);
  }
});
