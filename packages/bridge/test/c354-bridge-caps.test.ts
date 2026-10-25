/**
 * spec 0.1.68 (C354, MANIFEST `requires.bridgeCaps`, QA-C354-2): at app registration (the manifest fetch) the bridge refuses an
 * app whose `requires.bridgeCaps`, or a feature it uses (a `secretOutput` op → `secret_output`), names a capability this build
 * does not declare: rejected kind `manifest`, code `bridge_cap_missing`, the missing cap in the log detail, the app is not routed.
 * A declared cap registers normally. The check only refuses; it never widens.
 *
 * The pinned validator (manifest 0.1.30) predates `requires.bridgeCaps` and `secretOutput` and refuses both keys (schema), so the
 * end-to-end tests stand in for the re-pinned validator: they validate the manifest WITHOUT those keys with the real validator and
 * hand the full manifest on (`// spec 0.1.68`; drop the seam at the re-pin).
 */
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import { BRIDGE_CAPS_DECLARED, missingBridgeCap } from "../src/caps.ts";
import { buildStatusReport } from "../src/portal.ts";
import { jsonLogger } from "../src/util.ts";
import { INS, makeWorld, notesManifest, type World, waitFor } from "./support/world.ts";

describe("missingBridgeCap (C354)", () => {
  test("declared caps pass, a missing one is named; secretOutput implies secret_output; the shared requiredBridgeCaps is used when the API has it", () => {
    assert.deepEqual([...BRIDGE_CAPS_DECLARED].includes("hook_tool"), true);
    assert.equal(missingBridgeCap({ requires: { bridgeCaps: ["hook_tool", "owner_rows"] }, operations: [] }), undefined);
    assert.equal(missingBridgeCap({ operations: [] }), undefined, "no requirement → nothing missing");
    assert.equal(missingBridgeCap({ requires: { bridgeCaps: ["hook_tool", "secret_output"] }, operations: [] }), "secret_output");
    assert.equal(missingBridgeCap({ requires: { bridgeCaps: ["lazy_tools"] }, operations: [] }), "lazy_tools");
    assert.equal(missingBridgeCap({ operations: [{ id: "lease", secretOutput: true }] }), "secret_output", "implied by a secretOutput op even when undeclared");
    assert.equal(missingBridgeCap({ requires: { bridgeCaps: ["hook_tool"] } }, { requiredBridgeCaps: () => ["model_roles"] }), "model_roles", "the shared function wins");
    assert.equal(missingBridgeCap({ requires: { bridgeCaps: ["secret_output"] } }, {}, ["secret_output"]), undefined, "a bridge that declares it accepts it");
  });
});

/** spec 0.1.68 seam (see the file comment): the real validator on the manifest without the two new keys, the full manifest on. */
function seam(w: World): void {
  const api = w.bridge.ctx.api as unknown as { validateManifest: (j: unknown) => { ok: boolean; manifest?: unknown; digest?: string }; manifestDigest: (m: unknown) => string };
  const real = api.validateManifest.bind(api);
  api.validateManifest = (json: unknown) => {
    const m = structuredClone(json) as { requires?: { bridgeCaps?: unknown }; operations?: { secretOutput?: unknown }[] };
    if (m.requires) delete m.requires.bridgeCaps;
    if (m.requires && Object.keys(m.requires).length === 0) delete m.requires;
    for (const o of m.operations ?? []) delete o.secretOutput;
    const v = real(m);
    return v.ok ? { ...v, manifest: json, digest: api.manifestDigest(json) } : v;
  };
}

describe("registration: requires.bridgeCaps against the declared caps (C354)", () => {
  let w: World;
  const lines: string[] = [];
  const rejected = () => buildStatusReport(w.bridge.ctx).rejected.filter((r) => r.kind === "manifest" && r.code === "bridge_cap_missing");
  before(async () => {
    w = await makeWorld({ real: true, logger: jsonLogger((l) => lines.push(l)) });
    seam(w);
  });
  after(async () => {
    await w.close();
  });

  test("a declared cap (hook_tool) → the app registers and is routed", async () => {
    w.updateAppTo({ ...notesManifest, version: "3.0.0", requires: { bridgeCaps: ["hook_tool"] } });
    await w.publish();
    await waitFor(() => (w.bridge.ctx.table?.apps.get(INS as never)?.manifest as { version?: string } | undefined)?.version === "3.0.0", 15000);
    assert.ok(w.bridge.ctx.table?.apps.get(INS as never)?.ops.has("notes_list"));
    assert.equal(rejected().length, 0);
  });

  test("a cap the bridge does not declare (secret_output) → refused bridge_cap_missing with the cap in the detail; the app is not routed", async () => {
    const from = lines.length;
    w.updateAppTo({ ...notesManifest, version: "3.0.1", requires: { bridgeCaps: ["hook_tool", "secret_output"] } });
    await w.publish();
    await waitFor(() => rejected().some((r) => r.ins === INS), 15000);
    assert.equal(w.bridge.ctx.table?.apps.get(INS as never)?.manifest, undefined, "not routed");
    const line = lines.slice(from).find((l) => l.includes('"bridge.rejected"') && l.includes("bridge_cap_missing"));
    assert.ok(line, "a rejection line");
    assert.match(line, /missing bridge cap secret_output/);
  });
});

// a fresh world: the previous refusal leaves the app in the manifest retry backoff
describe("registration: a secretOutput op implies secret_output (C354)", () => {
  let w: World;
  const lines: string[] = [];
  before(async () => {
    w = await makeWorld({ real: true, logger: jsonLogger((l) => lines.push(l)) });
    seam(w);
  });
  after(async () => {
    await w.close();
  });

  test("a secretOutput op without the declaration is refused the same way (the cap is implied, never skipped)", async () => {
    const from = lines.length;
    const ops = [...notesManifest.operations, { ...notesManifest.operations[0], id: "notes_lease", receipt: true, secretOutput: true }];
    w.updateAppTo({ ...notesManifest, version: "3.0.2", operations: ops });
    await w.publish();
    await waitFor(() => lines.slice(from).some((l) => l.includes("bridge_cap_missing") && l.includes("missing bridge cap secret_output")), 15000);
    assert.equal(w.bridge.ctx.table?.apps.get(INS as never)?.manifest, undefined, "not routed");
  });
});
