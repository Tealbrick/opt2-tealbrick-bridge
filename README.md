# Tealbrick bridge

The workspace's one public door. It verifies agents, gates and routes every call to apps on the private network, runs the hook chain, serves MCP and OAuth, proxies person launches, serves the key-entry page, and connects OUT to Portal for signed configuration.

- Repository: `Tealbrick/opt2-tealbrick-bridge` (GitHub organisation `Tealbrick`)
- Licence: the Tealbrick Software Licence, version 1.1 (Part A; https://tealbrick.com/software-licence). `LICENSE` and `NOTICE` ship in every package and in the image (`/app/LICENSE`). Versions released before this change declared MIT and stay MIT; see `LICENSING.md`.
- Status: bridge and bridge-server 0.2.9 (manifest 0.1.30, spec 0.1.57, conformance 0.1.28; spec 0.1.68 fields read structurally until the re-pin). 0.2.9 (C336 RQ-2/RQ-3, spec 0.1.68): cap `hook_tool` (`secret_output` follows the manifest re-pin, C354); hook requests of a dynamic call carry `call.target.tool` = the resolution's canonical tool (a mismatched or malformed resolution is refused `dynamic_resolve_failed`); a `secretOutput` op is never listed for agents, agent calls are refused `secret_output_app_only`, and app calls get no `after` hook and no forwarded idempotency key (CHANGELOG.md). Before that, 0.2.8 (patch, C358): an unparseable request target (for example `GET //`) is a 400, not a process exit; Node 24.22.1 base image (Node.js security release 2026-10-21); no other behaviour change. 0.2.7 (C274, spec 0.1.57 BRIDGE §14): app events as a platform primitive: ingest `POST /tb/v1/events` (internal), one log per agent in `node:sqlite` on the bridge volume (fan-out by MANIFEST §16.2 rules 1–4, re-check of rules 1, 5 and 6 at delivery, instance-pause and G2b holds with re-ids, retention 7 days / 10 000 rows with `truncated`, purges), and `tealbrick/events/{list,poll,stream}` + `notifications/tealbrick/event` frames on the agent's `/mcp` session; the bridge declares the `events` cap (ARCHITECTURE.md section 12, CHANGELOG.md). Before that, 0.2.6 (C296, INC-20261020-03): the MCP tool index no longer keeps dynamic list entries for a whole config revision; a stale index with dynamic list entries is rebuilt in the background after 5 min (a failed refresh keeps the last good entries), one whose catalog failed after 30 s, and sessions get `notifications/tools/list_changed` when the rebuilt tool set differs (an app whose engine came up after the index was built showed no engine tools until the next revision). Before that, 0.2.5: (1) C283 A1 owner-row filter: an owner-set scope row may admit a scoped op above the Portal grant's `crud`; tools/list lists a static scoped op above `grant.crud` that the app's `scope_summary` names in `admittedOps` for that agent, the dynamic catalog body carries `agent` and an entry marked `admitted: "owner"` is listed, and `gate()` (manifest 0.1.27) skips `op.crud ⊆ grant.crud` for ops WITH a `scopeType` (the SDK enforces; unscoped ops keep the ceiling). Display only; pause, revoke and expiry still refuse first. (2) `StatusReport.bridge.caps = ["owner_rows"]` (C292/C292a): declared only because (1) is implemented; a standalone bridge writes it into the slices it re-mints. (3) C268 B/c hook proof `bd`: the call proof of a hook request carries `bd` = sha256 of the exact body bytes sent, only to a hook app whose claim or status push lists `"bd"` in `proofClaims`; it changes only on a config change of the app's digest/version/candidate, a re-claim or a push, never on a connect failure, timeout or 401, and a 401 is never retried without `bd`. Before that, 0.2.4 (G2b, INC-20261019-04: accepts the update CANDIDATE manifest digest of spec 0.1.51 `apps[].candidateManifestDigest` + `candidateVersion` in the routing table, the manifest retry and the claim, so a bridge that restarts during a health-gated app update no longer refuses the new image with manifest_mismatch; it uses and reports the digest that runs; the port of 0.1.33 to this line. Before that, 0.2.3: C230 GRANT-PRD: companion grants with the optional `prd` claim verify (manifest 0.1.23, spec 0.1.46) and a `prd` that differs from the instance table withholds `call.caller.product` from hooks with a warning; no viewer token or person ticket in any log line, proven by a planted-token test). 0.2.2 added HOOK-CALLER-PRODUCT: hook requests carry `call.caller.product` for app callers; C232 LA-1: immutable `/_s/` assets on the viewer path and `TB_VIEWS_KEY` rotation through `TB_VIEWS_KEY_PREVIOUS`; manifest 0.1.22, spec 0.1.45 at 0.2.2). 0.2.1 added the views role `TB_ROLE=views` and the private views route. 0.2.0 was repo split part 1, C158: the agent side moved out. CI template ci-v9.9. The target is a PRIVATE source repo; it stays public until the server image can be built and published to GHCR from Woodpecker (C222: no paid GitHub Actions for private repos; today the image is built by the free public-repo Action). The server image is PUBLIC: `ghcr.io/tealbrick/opt2-tealbrick-bridge-server`. The repo split: the agent-side code (stdio relay, MCP client, CLI, harnesses) lives in the CLI repo (`Tealbrick/opt2-tealbrick-cli`). This repo imports the relay as `@opt2-tealbrick/relay` from the dist host (private to public only) and carries no copy of it.

Do not put secrets, tokens, keys, customer data or personal data in this repository, its issues or its pull requests. This repository is public for now and must stay clean either way. Runtime secrets live in the deployment platform (Railway variables, Woodpecker secrets), and `.env` files are never committed. A secret scan (gitleaks) is the first step of the CI pipeline (`.woodpecker/ci.yaml`). GitHub secret scanning and push protection are NOT enabled on this repository (checked 2026-10-17), so the gitleaks step and the optional local guard are the only scans. An optional local guard is `pre-commit install`. If a secret is committed, rotate it first, then remove it from history.

## What this repo is and is not

The bridge DOES: verify every caller, run `gate()` on every routed call, run before, context and after hooks, forward to apps with a grant and a call proof, serve MCP, act as OAuth authorization server for its own MCP resource, proxy person launches, serve the key page, store account-default keys sealed, pull signed config, relay instance slices, report status.

The bridge does NOT: run agents or schedules, call any model, hold app data, holds or receipts, decide run or hold (the app does), check licences (Core withholds grants instead), send payloads or key values to Portal, or accept a connection from Portal.

The bridge core is one package, the `deployed` form (the enforcement point; holds grants and the key store). The local relay form (holds only the agent identity and forwards to the deployed bridge) is `@opt2-tealbrick/relay`, built in the CLI repo.

## Two roles, one image

The server image starts in one of two roles, chosen by `TB_ROLE` (BRIDGE §9.2):

- `bridge` (default, `TB_ROLE` unset): the workspace bridge described above.
- `views` (`TB_ROLE=views`): the workspace views service "tb-views" (LA-1). It serves what anyone with a link may see: `GET /v/<product>/<rest>` goes to the bridge private route `GET /tb/v1/views/<product>/<rest>` with the header `TB-Views-Key`, and from there to the app's own `GET /v/<product>/<rest>`. It holds no state: no volume, no Portal connection, no enrolment, no keys. Env: `TB_VIEWS_UPSTREAM` (the bridge private origin), `TB_VIEWS_KEY`, `PORT`. It exits with a message if `TB_ENROL_CODE`, `TB_KEK` or `TB_PORTAL_URL` is set, so a misconfigured views service never becomes a second bridge. It serves `/v/*`, `/healthz`, `/readyz` only (everything else 404, HEAD and OPTIONS 405).

The views service does the edge duties (request-header allow-list, 120 requests per minute per client IP by the first `X-Forwarded-For` hop, 32 in flight, 2 MiB, 10 s). The bridge route does the rest again where it matters (key, pause, routing to the app whose manifest declares a `viewer` public route, its own in-flight cap, floor and `_d` gate). The header rules are the manifest package's (`VIEWER_HEADER_FLOOR`, `VIEWER_REQUEST_HEADERS`, `viewerResponseHeaderDropped`, `isViewerDocumentPath`, `viewerDocumentCspOk`, `viewerFloorOverride`); nothing here re-implements them. The app may replace only two floor headers: `Content-Security-Policy` (always; the `_d` gate still applies) and `Cache-Control` (only as one `public, max-age=<n>, immutable` value on a static asset path `/v/<product>/_s/…`). A token page, a data answer and a `_d` document stay `no-store`, so a revoked link is never served from a cache. Both the views service and the bridge route apply this rule. The bridge role reads `TB_VIEWS_KEY` (the same key; unset or too short means every views request is 404) and, only during a key rotation, `TB_VIEWS_KEY_PREVIOUS` (the retiring key; accepted as well while it is set) and `TB_VIEWS_PUBLIC_URL` (the tb-views origin; set, the bridge probes its `/readyz` and reports `StatusReport.views`). The main origin and the keys origin answer 404 for `/v/*`.

### Rotating the views key

The views service sends exactly one key, its own `TB_VIEWS_KEY`. The bridge private route accepts `TB_VIEWS_KEY` and, while it is set, `TB_VIEWS_KEY_PREVIOUS`. Both are compared in constant time; any other value, or none, is the same 404 as an unknown path. Neither key is logged, reported or put in a metric. Rotation order, so the views service never has a moment without a key the bridge accepts:

1. Core sets `TB_VIEWS_KEY_PREVIOUS` = the old key and `TB_VIEWS_KEY` = the new key on the bridge, and `TB_VIEWS_KEY` = the new key on tb-views. The bridge restarts and accepts both keys.
2. Core redeploys tb-views. It now sends the new key.
3. Core removes `TB_VIEWS_KEY_PREVIOUS` from the bridge. The old key is a 404 from the next start.

A `TB_VIEWS_KEY_PREVIOUS` shorter than 16 characters is not a key: it is ignored with a warning that names the variable, never the value. The views role ignores `TB_VIEWS_KEY_PREVIOUS`.

## Quick start

pnpm workspaces; TypeScript run directly by Node 24+ (type stripping).

```sh
corepack enable && pnpm install --frozen-lockfile --ignore-scripts
pnpm typecheck && pnpm lint && pnpm test
pnpm conformance        # real tb-conformance against the real bridge build (bridge target)
pnpm build
```

Run the container image the way Core deploys it: a volume at `/data`, `TB_KEK`, `TB_PORTAL_URL`, `TB_PUBLIC_URL`, `TB_ENROL_CODE`. For your own infrastructure see the runbooks in `Tealbrick/opt2-tealbrick-docs`.

## Layout

| Path | Purpose |
|---|---|
| `packages/bridge` | Core library (`@opt2-tealbrick/bridge`): server, portal link, state, routing table, call router, MCP, OAuth, identity, person surfaces, internal listener, standalone, pages |
| `packages/bridge/src/views-edge.ts`, `views-route.ts`, `views-shared.ts` | The two views pieces (0.2.1): the views role (tb-views), the bridge private views route, and what they share |
| `packages/bridge-server` | Docker entry (both roles): privilege drop, signal handling, `bridge-runtime.json` (platform-readable runtime descriptor) |
| (not here) `relay`, `cli`, `harness-claude`, `harness-eve` | The agent side. The source is `Tealbrick/opt2-tealbrick-cli`; this repo depends on `@opt2-tealbrick/relay` only (dist URL and integrity in `pnpm-lock.yaml`). Removed here in 0.2.0 |
| `packages/bridge/assets` | Generated kit CSS subset, Nunito, mark, favicon for the bridge pages |
| `scripts/conformance.ts`, `conformance-waivers.json` | Real conformance run against the bridge (waivers: none) |
| `scripts/agent-side-gate.ts` | One owner per module (L1): fails if this repo defines relay or MCP-client symbols, carries an agent-side package or module, or imports one by a relative path. Run by `pnpm lint` and `pnpm test` |
| `scripts/check-literals.ts` | Deny-list guard (old names, tailnet hosts, product names) |
| `tealbrick-ci.json` | Repo-specific CI settings (kind `bridge`; builds the `opt2-tealbrick-bridge-server` image) |

## Configuration

Bridge role, required: `TB_DATA_DIR`, `TB_KEK`, `TB_PORTAL_URL`, `TB_PUBLIC_URL`; `TB_ENROL_CODE` on first start; `TB_KEYS_PUBLIC_URL` for the key page. Optional (workspaces with a views service): `TB_VIEWS_KEY`, `TB_VIEWS_PUBLIC_URL`; `TB_VIEWS_KEY_PREVIOUS` only during a key rotation. Views role: `TB_ROLE=views`, `TB_VIEWS_UPSTREAM`, `TB_VIEWS_KEY`, `PORT`. Full list and meanings: the environments document in `Tealbrick/opt2-tealbrick-docs`. There is no `.env.example`.

## CI and release

Woodpecker CI with the shared opt2 pipeline template ci-v9.9 (`.woodpecker/ci.yaml` and `.github/workflows/opt2-release.yml` are generated copies; do not edit them, change `tealbrick-ci.json` or the template in `Tealbrick/opt2-tealbrick-platform`). Library pins (spec, manifest, conformance, miniapp SDK) come from the dist host (`Tealbrick/opt2-tealbrick-dist`).

Tag `v<x>` pushes the image; tag `bridge-v<x>` attaches the library tarball; the platform `registry-sync` signs the `bridge` index entry; Core deploys the digest into customer workspaces.

## Language

New code is TypeScript (Node 24+).

## Documentation

- `ARCHITECTURE.md` explains the design.
- `CONTRIBUTING.md` explains how to change it.
- The contract is in `Tealbrick/opt2-tealbrick-specs`: `docs/BRIDGE.md` and `CREDENTIALS.md`.
- System documentation (overview, environments, runbooks) lives in the private repo Tealbrick/opt2-tealbrick-docs.
