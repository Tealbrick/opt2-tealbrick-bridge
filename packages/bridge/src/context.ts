/**
 * Shared runtime of a deployed (full) bridge: identity, state, current table, status counters and
 * change notifications. One instance per process.
 */

import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import { EventEmitter } from "node:events";
import { readFileSync } from "node:fs";
import type { ManifestApi } from "@opt2-tealbrick/relay";
import type { AppStatus, } from "@opt2-tealbrick/spec/bridge";
import type { AgentId, Ed25519PublicJwk, InstanceId } from "@opt2-tealbrick/spec/credentials";
import type { KeySet } from "@opt2-tealbrick/spec/sdk";
import { ProofCaps } from "./proof-caps.ts";
import type { BridgeState, Identity } from "./state.ts";
import type { Rejection, Table } from "./table.ts";
import type { Logger } from "./util.ts";
import { nowS } from "./util.ts";

/** This package's version, read from its package.json (the one place; `src/` and `dist/` both sit beside it). */
export const BRIDGE_VERSION: string = (JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string }).version;
/** F57a / L21: Retry-After (seconds) on tool and companion calls refused while the bridge drains (nothing ran) */
export const DRAIN_RETRY_AFTER_S = 2;

/**
 * BSD-08 (CREDENTIALS §9.5): the root channel this build pins. A build constant, never env (Portal sets env at
 * deploy). 0.1.x bridges are dev-channel builds; the cutover release switches to "prod".
 */
export const PORTAL_ROOT_CHANNEL: "dev" | "prod" = "dev";

export interface BridgeOptions {
  api: ManifestApi;
  state: BridgeState;
  logger: Logger;
  portalUrl: string;
  publicUrl: string;
  /** separate origin that serves ONLY the key page (C59): app UIs on the main origin can never script it */
  keysUrl?: string | undefined;
  /** internal listener origin as apps reach it (e.g. http://bridge.railway.internal:8788) */
  internalUrl: string;
  form: "deployed" | "own_infra";
  /** BSD-07 (BRIDGE §5.7): owner-set allow-list of own-infrastructure app origins (TB_OWN_INFRA_ORIGINS) */
  ownInfraOrigins?: string[];
  /** LA-1 (TB_VIEWS_KEY): the Core-generated key tb-views presents to the private views route; never logged, never reported */
  viewsKey?: string | undefined;
  /** LA-1 key rotation (TB_VIEWS_KEY_PREVIOUS): the key being retired; accepted by the private views route only while set; never logged, never reported */
  viewsKeyPrevious?: string | undefined;
  /** LA-1 (TB_VIEWS_PUBLIC_URL): the tb-views origin; set → the bridge probes its /readyz and reports `StatusReport.views` */
  viewsUrl?: string | undefined;
  /** BSD-08: Portal Root Keys; default = this build's channel. Only a test harness replaces them (start option). */
  portalRoots?: Ed25519PublicJwk[];
  fetch?: typeof fetch;
}

export interface AppHealth {
  status: AppStatus;
  lastSeen: number;
}

export class BridgeContext extends EventEmitter {
  readonly api: ManifestApi;
  readonly state: BridgeState;
  readonly log: Logger;
  readonly portalUrl: string;
  readonly publicUrl: string;
  readonly keysUrl: string | undefined;
  readonly internalUrl: string;
  readonly form: "deployed" | "own_infra";
  readonly ownInfraOrigins: string[];
  /** tb-views origin (TB_VIEWS_PUBLIC_URL) or undefined: the workspace has no views service */
  readonly viewsUrl: string | undefined;
  /** the last probe of tb-views `/readyz` (undefined until the first probe, and always when there is no views service) */
  views: { ok: boolean; lastCheckAt: string } | undefined;
  readonly #viewsKey: string | undefined;
  readonly #viewsKeyPrevious: string | undefined;
  readonly portalRoots: Ed25519PublicJwk[];
  readonly fetch: typeof fetch;
  readonly boot = randomUUID();
  /** F57a / L21: set on SIGTERM. New calls get `temporarily_unavailable` + Retry-After; in-flight calls finish. */
  draining = false;
  /** epoch s of this process start: proofs signed before it are refused for one proof lifetime (BSD-12) */
  readonly bootS = Math.floor(Date.now() / 1000);
  identity: Identity | undefined;
  table: Table | undefined;
  /** last successful config pull (epoch s) */
  lastPull = 0;
  readonly health = new Map<InstanceId, AppHealth>();
  /** C268c: which hook apps accept `bd` in the call proof (proof-caps.ts) */
  readonly proofCaps = new ProofCaps();
  readonly scopeSummaries = new Map<string, { agt: AgentId; ins: InstanceId; label: string }>();
  /** when each app instance was last asked for its scope summary (ms), and the request in flight (scope-summary.ts) */
  readonly scopeSummaryAt = new Map<InstanceId, number>();
  readonly scopeSummaryRuns = new Map<InstanceId, Promise<void>>();
  /**
   * C283 A1 (spec 0.1.50): `ScopeSummaryResult.admittedOps` per `<agt>|<ins>` as the app last answered it: the STATIC scoped
   * ops an owner-set primary row admits, possibly above the Portal grant. DISPLAY only (tools/list); the SDK authorizes every
   * call. Never part of the StatusReport. A change emits `scopes` (tool index and catalog caches are dropped).
   */
  readonly admittedOps = new Map<string, ReadonlySet<string>>();
  readonly rejected = new Map<string, number>();
  /** v0.1.14: connection → last authentication (ms) since the previous accepted status report (insertion = recency) */
  readonly connectionsSeen = new Map<string, number>();
  /** record an authenticated connection (most recent last; capped) */
  sawConnection(con: string, nowMs = Date.now()): void {
    this.connectionsSeen.delete(con);
    this.connectionsSeen.set(con, nowMs);
    if (this.connectionsSeen.size > 500) this.connectionsSeen.delete(this.connectionsSeen.keys().next().value as string);
  }
  readonly toolsOmitted = new Map<string, { ins: InstanceId; name: string; code: "tool_name_too_long" | "name_collision" | "ceiling" | "catalog_failed" }>();

  constructor(o: BridgeOptions) {
    super();
    this.setMaxListeners(0);
    this.api = o.api;
    this.state = o.state;
    this.log = o.logger;
    this.portalUrl = o.portalUrl;
    this.publicUrl = o.publicUrl;
    this.keysUrl = o.keysUrl;
    this.internalUrl = o.internalUrl;
    this.form = o.form;
    this.ownInfraOrigins = o.ownInfraOrigins ?? [];
    this.viewsUrl = o.viewsUrl;
    this.#viewsKey = o.viewsKey;
    this.#viewsKeyPrevious = o.viewsKeyPrevious;
    this.portalRoots = o.portalRoots ?? o.api.portalRootKeys(PORTAL_ROOT_CHANNEL);
    this.fetch = o.fetch ?? fetch;
  }

  /**
   * LA-1: does `got` equal the views key (TB_VIEWS_KEY) or, during a rotation, the previous one (TB_VIEWS_KEY_PREVIOUS,
   * only while set)? Constant time (digests of equal length); false when no key is configured, so a bridge without
   * TB_VIEWS_KEY answers every views request 404.
   */
  viewsKeyMatches(got: string | undefined): boolean {
    if (!got) return false;
    const b = createHash("sha256").update(got).digest();
    // both keys are always compared (no early exit), each in constant time over equal-length digests
    let ok = false;
    for (const key of [this.#viewsKey, this.#viewsKeyPrevious]) {
      if (!key) continue;
      if (timingSafeEqual(createHash("sha256").update(key).digest(), b)) ok = true;
    }
    return ok;
  }

  get bridgeRef(): `tb:brg:brg_${string}` {
    if (!this.identity) throw new Error("not enrolled");
    return `tb:brg:${this.identity.bridgeId}`;
  }

  ownKeySet(): KeySet {
    if (!this.identity) throw new Error("not enrolled");
    return this.api.keySetFrom({ keys: [this.identity.key.publicJwk] }, this.bridgeRef);
  }

  reject(r: Rejection): void {
    const k = r.ins ? `${r.kind}|${r.code}|${r.ins}` : `${r.kind}|${r.code}`;
    this.rejected.set(k, (this.rejected.get(k) ?? 0) + 1);
    this.log.warn("bridge.rejected", { kind: r.kind, code: r.code, ...(r.ins ? { ins: r.ins } : {}), ...(r.detail ? { detail: r.detail } : {}) });
  }

  /** Config older than 12 h → agent and app→app calls fail closed (C9). Standalone documents are re-minted. */
  configExpired(now = nowS()): boolean {
    return !this.table || now > this.table.exp;
  }

  /**
   * BSD-12: replay sets live in memory, so right after a restart a proof captured before it could be replayed once.
   * For one proof lifetime (+ leeway) after boot, proofs issued before the boot are refused; clients re-sign.
   */
  proofBeforeBoot(iat: number, now = nowS()): boolean {
    return now < this.bootS + 90 && iat < this.bootS;
  }

  portalReachable(now = nowS()): boolean {
    return now - this.lastPull < 120;
  }

  swapTable(next: Table): void {
    const prev = this.table;
    this.table = next;
    // C268c: a config change of an app's digest, version or update candidate drops its hook proof capabilities, before any call uses the new table
    this.proofCaps.onTable(next, prev);
    this.emit("table", next, prev);
  }
}
