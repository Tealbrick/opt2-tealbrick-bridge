# Contributing to Tealbrick bridge

This file is the short version. The full engineering practice is in the Tealbrick engineering handbook (`practice/ENGINEERING-HANDBOOK.md` in the private repo `Tealbrick/opt2-tealbrick-docs`). If the two disagree, the handbook wins.

## Rules that apply to every Tealbrick repo

1. **No secrets, ever.** No keys, tokens, passwords, `.env` files with values, connection strings, webhook URLs or customer data in code, tests, fixtures, logs, issues or commit messages. Use `.env.example` with placeholders. The CI `secret-scan` step (gitleaks) fails the build. If you commit a secret, rotate it before anything else.
2. **TypeScript only.** New code is `.ts` or `.tsx`. Node 24 runs `.ts` directly (type stripping): no enums, no parameter properties, `.ts` import extensions. Do not add `.js`, `.mjs` or `.cjs` source files, scripts or tests. Allowed JavaScript: generated build output (`dist/`), files a tool requires as JS, vendored third-party code.
3. **The CI file is generated.** `.woodpecker/ci.yaml` and `.github/workflows/opt2-release.yml` are byte-identical copies of the platform template. The `setup` step fails on drift. Change `tealbrick-ci.json`, or change the template in the platform repo. Never edit the copies. Adopt or upgrade with `node ci/tb-ci.ts adopt <repo dir> --kind <kind>` from the platform repo.
3a. **Supply chain.** Install with `--frozen-lockfile --ignore-scripts`. Every GitHub-release tarball dependency carries `integrity` in the lockfile (`node ci/tb-ci.ts pin-tarballs <repo dir>` from the platform repo, after each dependency change). Package manager versions are hash-pinned (`packageManager`). A Dockerfile never uses `VOLUME` (Railway refuses it).
4. **Changes go through a pull request.** `main` is the only long-lived branch. Work on short branches named `<type>/<id>-<slug>` (types: feat, fix, chore, docs, ci, sec, hotfix). PR title `<area>: <summary>`, body with a `Refs:` line, green required checks, no unrelated changes. Squash merge only; linear history; delete the branch after merge. CODEOWNERS routes reviews; while there is one human maintainer the review is an agent review recorded in the PR. Branch protection and CODEOWNERS are not set yet (GitHub Team, decision D1): until then the rule holds by convention. No force push, no history rewrite (C39).
5. **Traceability.** Every commit carries an id in a `Refs:` trailer or the subject: a decision (`C202`), an item (`BRG-13`, `SEC-01`, `QA R-1`) or an incident. Every release has notes (a `CHANGELOG.md` section per version is the target, enforced later).
6. **Tags are immutable and CI-only.** Tag only on a green pipeline. Never move or delete a tag. If a tag is wrong, cut the next version (L38). Release assets are uploaded only by the CI release Action, never by hand (L10, C76). Build before pack: a package whose `exports` target is missing fails the pack (C75).
7. **One mechanism per concern.** Shared vocabularies, constants, version thresholds and crypto come from `@opt2-tealbrick/spec` and `@opt2-tealbrick/manifest`. Never write a second copy (L1). A version threshold names the release that contains the rule (L26).
8. **Test the real path.** Every cross-component path needs one real-to-real test (L2). A fake comes from the shared rule, never from the side under test (L1). Silent failure is a bug: surface it as an error, a health signal or a monitor report (L3). Never change a product surface to make a test pass (L4). Assert the exact outcome, not the absence of the bad one (L27).
9. **Readers tolerate, writers stay strict.** A verifier ignores unknown values that cannot widen access. It refuses unknown values only where it would act on them (L24).
10. **Interfaces change through the spec.** If a contract is wrong or missing, change `specs` first (additive within a minor, breaking only in a major with a deprecation window). Do not fix it locally.
11. **Disk hygiene.** Delete your own clones, build output, `node_modules` and test copies when the work lands. `rm -rf` only on absolute paths inside your own scratch folder, with a guarded variable (`${VAR:?}`). Never `pkill` or kill by name on a shared machine (L16, L20, L37).
12. **UI work.** Render it in a real browser and check contrast before anyone reviews it (L35). Use the design kit (`@opt2-tealbrick/ui`) tokens only. The design guard (`check-system`) fails raw colours, fonts, radii and shadows.
13. **Docs.** Update this repo's `README.md` and `ARCHITECTURE.md` when behaviour changes. Canonical long-lived docs live in Forge (`projects/tealbrick`).

## Rules specific to this repo

- A new refuse code or claim goes in the spec first (L24).
- The bridge never decides a hold and never stores holds, receipts or app data.
- Logs carry ids, codes and digests only. Never an input, an output, a token, a ticket, a code or a key value. Never `req.url`, a path or a query: `/v/<product>/tbv_…`, `/tb/v1/views/…` and `/a/<product>/_p/…`, `_d/…` carry a secret. `packages/bridge/test/no-tokens-in-logs.test.ts` plants tokens and fails on any log line that holds one.
- Public repo code may not import this repo (the CLI repo has a gate that enforces the other direction). This repo imports the agent side only through `@opt2-tealbrick/relay` and never carries a copy of it: `scripts/agent-side-gate.ts` (one owner per module, L1) fails `pnpm lint` and `pnpm test` if a relay or MCP-client symbol or module comes back. The agent-side code (relay, MCP client, CLI, harnesses) is changed in `Tealbrick/opt2-tealbrick-cli`, then this repo bumps the pinned relay tarball (dist URL, integrity in the lockfile).

## Checks before you push

```sh
pnpm typecheck
pnpm lint          # biome + check-literals + agent-side-gate
pnpm test          # agent-side-gate, builds, then node --test over packages/*/test and scripts/test
pnpm conformance   # tb-conformance bridge against the real build; waivers: none
```

Recorded at last check (bridge 0.2.5, conformance 0.1.27): 409 tests pass, 0 fail, 0 skipped; conformance bridge target 252 pass, 2 not applicable, 0 fail, 0 waivers (B5.gate_scoped_above_grant runs because the bridge reports `owner_rows`; the relay target runs in the CLI repo).

## Releasing

1. Green pipeline on `main`.
2. Tag `v<x.y.z>` (image) and `bridge-v<x.y.z>` (library tarball) on the same commit. The version equals `packages/bridge/package.json` and `bridge-server`.
3. The release Action builds and pushes; `registry-sync` verifies labels and digest and signs the index entry. Dispatch `registry-sync` by hand after a release; the schedule is slow.
4. Core offers the new version; each workspace owner updates. A bridge state reseal is one-way: the release record carries a rollback floor (`minRollback`), and apps may require a minimum bridge (`requires.bridge`).
5. qa1 is rolled by Lane C, one update at a quiet point (L46: no recent tool call by anyone but the Lane C test agents), not by the release itself.
