# Tealbrick bridge: architecture

State: verified against the repo on 2026-10-16. Claims cite paths in this repo. Anything not verified is marked UNVERIFIED. For the whole system see the system `ARCHITECTURE.md` and `SYSTEM-OVERVIEW.md`.

## 1. Listeners

- **Public** (`PORT`, default 8080). Max 2000 connections, 50 per client, request timeout 30 s, headers timeout 15 s. HSTS when `TB_PUBLIC_URL` is https. Two host names: the main origin and the keys origin (`TB_KEYS_PUBLIC_URL`, a different host name, startup throws otherwise). The keys origin serves only `GET/POST /keys`, `/healthz`, `/readyz`. On the main origin `/keys` is 404 (or a 503 "key page not configured" page when the keys origin is unset).
- **Internal** (`TB_INTERNAL_PORT`, default 8788). Private network only. Host: `TB_INTERNAL_HOST`, else `::` in the deployed form.

Public routes: `/healthz`, `/readyz`, `/mcp` (POST, GET SSE, DELETE), `/.well-known/oauth-protected-resource[/mcp]`, `/.well-known/oauth-authorization-server`, `/oauth/{register,authorize,pair/callback,token,revoke}`, `/agent/connection/revoke`, `/a/<product>/*` (person launch, app UI proxy, WebSocket for UI paths), `/p/<product>/<path>` (declared public routes only, 1 MiB cap), `/admin/v1/*` (answers only in standalone mode), `/_tb/*` (exact static allow-list). `/readyz` is 200 only when identity and a routing table exist. It does not check config age (the platform RUNBOOK says it does: mismatch).

Internal routes: `POST /tb/v1/claim`, `POST /tb/v1/status` (long-poll up to 60 s), `GET /tb/v1/keys/<name>`, `POST /tb/v1/call` (app to app; 503 with `Retry-After` while draining), `GET /metrics` (Prometheus text, no auth, so the private bind matters). Callers prove themselves with an instance assertion (`tb-instance-assert+jwt`, bound to method, path and body, 60 s, one-use `jti`, proofs issued before bridge boot refused for 90 s).

## 2. Enrolment and the Portal link (`packages/bridge/src/portal.ts`, `state.ts`)

- First start needs the one-time `TB_ENROL_CODE` (`tbe_...`, at most 24 hours). The bridge generates its Ed25519 key (K7), posts `/api/v1/bridge/enrol`, and verifies the response's key-set statement against root keys built into the bridge (`manifest.trustedPortalKeys`) BEFORE writing anything. A bad statement refuses enrolment and the refused code digest is saved so restarts do not retry it.
- **`PORTAL_ROOT_CHANNEL` is the build constant `"dev"` (`packages/bridge/src/context.ts`).** The comment says the cutover release must switch it to `"prod"`. Production root keys do not exist yet.
- Every later request to Portal carries `TB-Assert` (`tb-bridge-assert+jwt`, 60 s, bound to method, path and body). Redirects are refused.
- Config pull (`runConfigLoop`): `GET <configPath>?after=<rev>&wait=60`, 75 s per-request timeout, 5 s minimum spacing, error backoff 5 s doubling to 240 s, `Retry-After` clamped 30 to 900 s, 4 MiB cap. `verifyConfig` checks `v`, workspace, subject and audience, strictly increasing `rev`, expiry, and that the signing key is `active` or `pending` in the pinned statement. The table is built off to the side and swapped as one pointer. The last good config is kept in `<TB_DATA_DIR>/bridge/config.jws` and re-verified at boot with only the age check waived.
- **Fail closed:** a config older than its `exp` (12 hours) makes agent and app-to-app calls answer `config_expired`. Person surfaces stay up so the owner can act.
- Status report: after each applied revision (2 s debounce), at least every 5 minutes, retry 15 s to 300 s. Content is names, ids, counts and presence booleans only. Since 0.1.30 it also passes `schemaVersion {app, sdk}`, `minCompatibleCode` and `failure` from the app status through (shape-checked, malformed values dropped). Since 0.1.31 it passes `preUpdateSnapshot` too: `null`, or a ref with well-formed `file`, `sha256`, `createdAt`, `from`, `to` (one bad member drops the whole ref; spec 0.1.39 types the member on AppStatus but not yet on the report entry) and sends an extra health event when they change, so Core's update gate wakes at once.
- Update candidate (since 0.1.33, spec 0.1.51): while Core runs a health-gated update of an app, its `apps[]` entry carries `candidateManifestDigest` + `candidateVersion` (both or neither) next to the serving `manifestDigest`. The table build (and its previous-manifest cache), the manifest retry and the claim accept a manifest whose digest equals either value. The bridge uses the manifest the service serves and reports that digest in `StatusReport.apps[]`; any other digest is `manifest_mismatch` as before.
- App manifests are fetched from `<internalUrl>/tb/v1/manifest` (10 s), must match `manifestDigest`, and a failed app is marked `down` and retried (backoff 2 to 60 s). `internalUrl` must be `http://<name>.railway.internal:<port>`, or, only for entries with `ownInfra: true`, an exact origin in `TB_OWN_INFRA_ORIGINS` (BSD-07).

## 3. Call pipeline (`calls.ts`, `table.ts`)

Order per call: resolve target (dynamic ops resolve through the app, with CRUD and effect ceilings and a hold family for outward and money), select grant, validate input, derive or require the idempotency key, `gate()`, `requireListedHooks`, before hooks, context hooks, config age, re-gate on the current table, re-check listed hooks, forward, after hooks (only on `ok`). The decision functions live in `@opt2-tealbrick/manifest` (`gate`, `verifyGrant`, `reduceBeforeChain`).

- Hook order is one total order: phase, `order`, product id, hook id, by code unit. Timeout is `min(max(timeoutMs, 100), 2000)` ms. A before or context hook that errors, times out, answers a bad shape or whose app is down: `hook_failed` (fail closed). A context hook may not write outside its own `<product>.` namespace or any `tb.*` key. A failing after hook withholds the output and marks the receipt `after_failed`.
- A hold verdict from a before hook becomes the `hv` claim in the op call proof. The first hold is kept; a later refuse wins. The app decides the hold.
- Forward: `POST <internalUrl>/tb/v1/ops/<op>` with grant and `TB-Call` proof (60 s, `gjti`, `in`, `ctx`, optional `hv`). Timeout 30 s, one retry only on a pre-connect error, results capped at 4 MiB. App error codes pass through only if they look like `^[a-z][a-z0-9_]{1,40}$` and are not a bridge verdict code.
- Companion calls: re-entry from inside a hook is `hook_reentry` (409), depth over 3 is `call_depth_exceeded`, app-initiated calls are limited to 120 per minute with burst 30.
- Drain (F57a): on SIGTERM new `tools/call` answer `temporarily_unavailable` with `Retry-After: 2`; in-flight calls get 25 s, then answer `app_unavailable` ("outcome unknown, check before retrying") and are never re-sent. Set `RAILWAY_DEPLOYMENT_DRAINING_SECONDS=30` (Core does).

## 4. Identity, MCP and OAuth

Only K5 agent access tokens (`tb-agent-session+jwt`, 900 s, signed by the bridge key) are accepted at `/mcp`. No person credential is ever accepted. Each request re-checks the current table. Connection methods: **key** (the agent presents a K4-signed assertion, jwt-bearer grant, 60 s, one-use `jti`; every failure answers `connection_unknown`, no oracle) and **pairing** (OAuth authorization code with PKCE S256 and a rotating refresh `tbr_`, 30 days sliding; reuse of an old refresh revokes the chain, reason `refresh_reuse`). DCR is stateless (`client_id` is `tbc_` plus a sealed registration). MCP limits: 16 sessions per connection, 10 requests per second burst 40, 8 concurrent calls per connection, 256 global, body 2 MiB. Tools are named `<product>__<op>`. Skills are served as resources plus a `<product>__tb_skills` fallback tool.

## 5. State on disk (`<TB_DATA_DIR>/bridge/`, dir 0700, files 0600)

Sealed with `TB_KEK` (AES-256-GCM): `identity.sealed.json`, `connections.sealed.json`, `claims.sealed.json`, `jtis.sealed.json`, `keys.sealed.json`, `standalone.sealed.json`, `reports.sealed.json` (persisted revocations kept until Portal has them), `enrol-refused.sealed.json`. Not sealed: `config.jws` (Portal-signed). Writes are crash-safe (temp file, fsync, rename, directory fsync). Plaintext state from bridges older than 0.1.12 makes boot fail with `state_corrupt`. `TB_KEK_PREVIOUS` reseals every record for one start. In memory only: replay sets, OAuth state, MCP sessions, key-page sessions, rate windows. Never stored: tool inputs or outputs, holds, receipts, app data, person credentials, the enrolment code itself.

## 6. Timers

Config loop (continuous), status loop (2 s debounce, 5 minutes), manifest retry (1 s tick), standalone re-mint (60 s tick, re-mint when under 6 hours remain), MCP session sweep (10 minutes), OAuth sweep (60 s), key session sweep (60 s), Docker HEALTHCHECK (30 s).

## 7. Image

`packages/bridge-server/Dockerfile`: Node 24 slim pinned by digest, `USER 1000:1000`, `EXPOSE 8080 8788`, no `VOLUME`, HEALTHCHECK on `/healthz`. When the platform starts it as root (`RAILWAY_RUN_UID=0` for a volume) the entry chowns `TB_DATA_DIR` and drops to 1000 before loading state or listening; it refuses to stay root. `bridge-runtime.json` describes ports, health paths, volume, and env sources for Core's deploy recipe.

## 8. Standalone mode

A final Portal-signed config with `standalone` freezes the bridge: it stops pulling, re-mints grants, slices and config with its own key every 6 hours, and exposes four admin operations (pause, resume, revoke a connection, tickets) authenticated by an owner assertion. One way.

## 9. Repo split status

Prepared, not released: the agent side lives in `Tealbrick/opt2-tealbrick-cli` (relay 0.1.0, cli 0.2.0, harnesses 0.2.0). `relay-v0.1.0` is tagged but its release Action is blocked by the org's Actions billing, so nothing is indexed or mirrored yet; bridge 0.2.0 needs relay 0.1.0 on the dist host first (release-order rule). Pending: remove the old CLI, harnesses and relay modules from here; depend on `@opt2-tealbrick/relay` from the dist host; ship a `-conformance` image tag outside the signed index; bridge 0.2.0; then flip this repo to private. TBD still pins an old bridge tarball and will break when this repo goes private (see `repos/tbd`).

## 10. Known gaps

- `PORTAL_ROOT_CHANNEL` is `"dev"`.
- A docker "own infrastructure" bridge runs in the `deployed` form (`bridge-server` never selects `own_infra`) and needs `TB_KEK` supplied by hand.
- In-memory replay and session sets reset on restart (90 s mitigation). One instance only (no HA).
- `/metrics` is unauthenticated (internal bind only).
- A private repo cannot run Actions until the org billing is fixed; this repo is public until then.