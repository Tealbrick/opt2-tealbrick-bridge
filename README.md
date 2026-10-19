# Tealbrick bridge

The workspace's one public door. It verifies agents, gates and routes every call to apps on the private network, runs the hook chain, serves MCP and OAuth, proxies person launches, serves the key-entry page, and connects OUT to Portal for signed configuration.

- Repository: `Tealbrick/opt2-tealbrick-bridge` (GitHub organisation `Tealbrick`)
- Licence: the Tealbrick Software Licence, version 1.1 (Part A; https://tealbrick.com/software-licence). `LICENSE` and `NOTICE` ship in every package and in the image (`/app/LICENSE`). Versions released before this change declared MIT and stay MIT; see `LICENSING.md`.
- Status: bridge and bridge-server 0.1.33 (hotfix line 0.1.x on top of 0.1.32, G2b, INC-20261019-04: accepts the update CANDIDATE manifest digest of spec 0.1.51 `apps[].candidateManifestDigest` + `candidateVersion` in the routing table, the manifest retry and the claim, so a bridge that restarts during a health-gated app update no longer refuses the new image with manifest_mismatch; it uses and reports the digest that runs; a digest equal to neither still refuses. 0.1.32 and 0.2.0-0.2.3 do NOT have this). 0.1.32 was the first release under the Tealbrick Software Licence (C220; forwards the upgrade-safety status fields, including the pre-update snapshot ref, typed by spec 0.1.40). CI template ci-v9.9. The target is a PRIVATE source repo; it stays public until the server image can be built and published to GHCR from Woodpecker (C222: no paid GitHub Actions for private repos; today the image is built by the free public-repo Action). The server image is PUBLIC: `ghcr.io/tealbrick/opt2-tealbrick-bridge-server`. The repo split is half done: the agent-side code was copied to the CLI repo (`Tealbrick/opt2-tealbrick-cli`), but this repo still contains an old CLI (0.1.22), both harnesses and the relay modules. No bridge 0.2.0 exists.

Do not put secrets, tokens, keys, customer data or personal data in this repository, its issues or its pull requests. This repository is public for now and must stay clean either way. Runtime secrets live in the deployment platform (Railway variables, Woodpecker secrets), and `.env` files are never committed. A secret scan (gitleaks) is the first step of the CI pipeline (`.woodpecker/ci.yaml`). GitHub secret scanning and push protection are NOT enabled on this repository (checked 2026-10-17), so the gitleaks step and the optional local guard are the only scans. An optional local guard is `pre-commit install`. If a secret is committed, rotate it first, then remove it from history.

## What this repo is and is not

The bridge DOES: verify every caller, run `gate()` on every routed call, run before, context and after hooks, forward to apps with a grant and a call proof, serve MCP, act as OAuth authorization server for its own MCP resource, proxy person launches, serve the key page, store account-default keys sealed, pull signed config, relay instance slices, report status.

The bridge does NOT: run agents or schedules, call any model, hold app data, holds or receipts, decide run or hold (the app does), check licences (Core withholds grants instead), send payloads or key values to Portal, or accept a connection from Portal.

The bridge core is one package in two forms: `deployed` (the enforcement point; holds grants and the key store) and `relay` (local; holds only the agent identity and forwards to the deployed bridge).

## Quick start

pnpm workspaces; TypeScript run directly by Node 24+ (type stripping).

```sh
corepack enable && pnpm install --frozen-lockfile --ignore-scripts
pnpm typecheck && pnpm lint && pnpm test
pnpm conformance        # real tb-conformance against the real bridge build, plus the relay target
pnpm build
```

Run the container image the way Core deploys it: a volume at `/data`, `TB_KEK`, `TB_PORTAL_URL`, `TB_PUBLIC_URL`, `TB_ENROL_CODE`. For your own infrastructure see the runbooks in `Tealbrick/opt2-tealbrick-docs`.

## Layout

| Path | Purpose |
|---|---|
| `packages/bridge` | Core library (`@opt2-tealbrick/bridge`): server, portal link, state, routing table, call router, MCP, OAuth, identity, person surfaces, internal listener, standalone, pages, relay |
| `packages/bridge-server` | Docker entry: privilege drop, signal handling, `bridge-runtime.json` (platform-readable runtime descriptor) |
| `packages/cli`, `packages/harness-claude`, `packages/harness-eve` | OLD copies. The live source is now `Tealbrick/opt2-tealbrick-cli`. To be removed in bridge 0.2.0 |
| `packages/bridge/assets` | Generated kit CSS subset, Nunito, mark, favicon for the bridge pages |
| `scripts/conformance.ts`, `conformance-waivers.json` | Real conformance run (waivers: none) |
| `scripts/check-literals.ts` | Deny-list guard (old names, tailnet hosts, product names) |
| `tealbrick-ci.json` | Repo-specific CI settings (kind `bridge`; builds the `opt2-tealbrick-bridge-server` image) |

## Configuration

Required: `TB_DATA_DIR`, `TB_KEK`, `TB_PORTAL_URL`, `TB_PUBLIC_URL`; `TB_ENROL_CODE` on first start; `TB_KEYS_PUBLIC_URL` for the key page. Full list and meanings: the environments document in `Tealbrick/opt2-tealbrick-docs`. There is no `.env.example`.

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
