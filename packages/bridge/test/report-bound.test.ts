// QA bridge#26: the status report stays under Core's 256 KiB ack cap whatever one app reports (S2: 443 KB on main), and the
// scope sources carry only the app's own instance ids with labels cut at a code point (a lone surrogate breaks Postgres jsonb).
import assert from "node:assert/strict";
import { test } from "node:test";
import type { StatusReport } from "@opt2-tealbrick/spec/bridge";
import { boundStatusReport, REPORT_PER_APP_MAX, STATUS_REPORT_MAX_BYTES } from "../src/portal.ts";
import { clampCodePoints, SOURCE_ID_RE, scopeSourceItems } from "../src/scope-summary.ts";

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
  for (const id of ["cna_01M5PNG40MSQ8RJG3CEZ95Z0ZY", "company", "nb_1", "area-sales"]) assert.ok(SOURCE_ID_RE.test(id), id);
  for (const id of ["cus_bYze8b07KDY7UK", "C04ACMESUPP", "U0HUMAN001", "1hP4rQ7vXyZ", "ann@example.test", "14155550100", "", "x".repeat(65)]) assert.ok(!SOURCE_ID_RE.test(id), id);
  const items = scopeSourceItems([
    { type: "account", id: "cna_01M5PNG40MSQ8RJG3CEZ95Z0ZY", label: "Acme data", access: "read" },
    { type: "account", id: "cus_bYze8b07KDY7UK", label: "Stripe customer", access: "read" },
  ]);
  assert.deepEqual(items?.map((i) => i.id), ["cna_01M5PNG40MSQ8RJG3CEZ95Z0ZY"]);
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
