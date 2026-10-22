/**
 * Agent sessions (K5) and caller verification at the bridge (BRIDGE §6, CREDENTIALS §8, §10).
 * Only K5 access tokens are accepted at /mcp; no person credential is ever accepted (R-P1).
 */

import { isRefusal } from "@opt2-tealbrick/relay";
import type { PairingConnectionRecord } from "@opt2-tealbrick/spec/bridge";
import { type AgentId, type AgentSessionClaims, type ConnectionId, LIFETIME_S, TYP } from "@opt2-tealbrick/spec/credentials";
import type { BridgeContext } from "./context.ts";
import { BridgeError, nowS } from "./util.ts";

export interface AgentPrincipal {
  agt: AgentId;
  con: ConnectionId;
  /** the K5's connection generation and expiry (epoch s): open event streams are re-checked against them (bridge 0.2.7) */
  gen: number;
  exp: number;
}

/** Current connection state: config entry, else a locally created pairing record not yet listed (BRIDGE §6). */
export function connectionState(ctx: BridgeContext, con: ConnectionId): { agt: AgentId; gen: number; active: boolean; method: "key" | "pairing" } | undefined {
  const t = ctx.table;
  const listed = t?.connections.get(con);
  const overlayRevoked =
    (ctx.state.standalone?.revokedConnections.includes(con) ?? false) || revokedLocally.has(con) || ctx.state.reports.revoked.some((r) => r.con === con);
  if (listed) {
    const local = ctx.state.connections.get(con);
    // pairing connections rotate `gen` locally on refresh; the bridge's own record is authoritative for gen
    const gen = listed.method === "pairing" && local ? local.gen : listed.gen;
    return { agt: listed.agt, gen, active: listed.status === "active" && !overlayRevoked, method: listed.method };
  }
  const rec = ctx.state.connections.get(con);
  if (rec && !rec.reported && !overlayRevoked) return { agt: rec.agt, gen: rec.gen, active: true, method: "pairing" };
  return undefined;
}

export async function issueAccess(ctx: BridgeContext, agt: AgentId, con: ConnectionId, gen: number): Promise<string> {
  // v0.1.14: an issued K5 (key assertion, pairing code exchange, refresh) counts as the connection being seen
  ctx.sawConnection(con);
  const id = ctx.identity;
  const t = ctx.table;
  if (!id || !t) throw new BridgeError("temporarily_unavailable", 503);
  const now = nowS();
  const claims: AgentSessionClaims = {
    iss: ctx.bridgeRef,
    sub: `tb:agt:${agt}`,
    aud: ctx.bridgeRef,
    iat: now,
    exp: now + LIFETIME_S.agentAccess,
    jti: ctx.api.ulid(),
    ws: t.ws,
    con,
    gen,
  };
  return ctx.api.signJws(TYP.agentSession, claims, id.key);
}

/** Verifies `Authorization: Bearer <K5>` and re-checks the current table on every request. */
export function authenticateAgent(ctx: BridgeContext, authorization: string | undefined): AgentPrincipal {
  const t = ctx.table;
  if (!t || !ctx.identity) throw new BridgeError("unauthenticated", 401);
  const m = /^Bearer ([A-Za-z0-9_\-.]+)$/.exec(authorization ?? "");
  if (!m?.[1]) throw new BridgeError("unauthenticated", 401);
  const v = ctx.api.verifyJws<AgentSessionClaims>(m[1], ctx.ownKeySet(), {
    typ: TYP.agentSession,
    aud: ctx.bridgeRef,
    iss: [ctx.bridgeRef],
    now: nowS(),
    maxLifetimeS: LIFETIME_S.agentAccess,
  });
  if (isRefusal(v)) {
    ctx.reject({ kind: "assertion", code: "invalid_token" });
    throw new BridgeError("unauthenticated", 401);
  }
  const c = v.claims;
  const agt = c.sub.startsWith("tb:agt:") ? (c.sub.slice(7) as AgentId) : undefined;
  const st = connectionState(ctx, c.con);
  if (!agt || !st?.active || st.gen !== c.gen || st.agt !== agt || c.ws !== t.ws) throw new BridgeError("unauthenticated", 401);
  if (!t.agents.has(agt)) throw new BridgeError("unauthenticated", 401);
  ctx.sawConnection(c.con);
  return { agt, con: c.con, gen: c.gen, exp: c.exp };
}

/** Refresh-token rotation with one 30 s retry grace (CORE I12, BRIDGE §6.2). */
export function rotateRefresh(ctx: BridgeContext, presented: string): { rec: PairingConnectionRecord; refresh: string } {
  const d = ctx.api.opaqueDigest(presented);
  const now = nowS();
  for (const rec of ctx.state.connections.values()) {
    const current = ctx.api.digestEqual(rec.refreshDigest, d);
    const previous = !!rec.previousDigest && ctx.api.digestEqual(rec.previousDigest, d);
    if (!current && !previous) continue;
    const st = connectionState(ctx, rec.con);
    if (!st?.active) throw new BridgeError("invalid_grant", 400);
    if (current && rec.expiresAt <= now) throw new BridgeError("invalid_grant", 400);
    if (previous) {
      const graceOk = !rec.previousUsed && rec.previousUntil !== null && now <= rec.previousUntil;
      if (!graceOk) {
        revokeLocal(ctx, rec.con, "refresh_reuse");
        throw new BridgeError("invalid_grant", 400);
      }
      rec.previousUsed = true;
    } else {
      rec.previousDigest = rec.refreshDigest;
      rec.previousUntil = now + LIFETIME_S.agentRefreshReuseGrace;
      rec.previousUsed = false;
    }
    const refresh = ctx.api.opaqueValue("tbr_");
    rec.refreshDigest = ctx.api.opaqueDigest(refresh);
    rec.gen += 1;
    rec.expiresAt = now + LIFETIME_S.agentRefreshSliding;
    ctx.state.saveConnections();
    return { rec, refresh };
  }
  throw new BridgeError("invalid_grant", 400);
}

export function revokeLocal(ctx: BridgeContext, con: ConnectionId, reason: "refresh_reuse" | "client_revoke"): void {
  if (ctx.state.connections.delete(con)) ctx.state.saveConnections();
  if (ctx.state.standalone && !ctx.state.standalone.revokedConnections.includes(con)) {
    ctx.state.standalone.revokedConnections.push(con);
    ctx.state.saveStandalone();
  }
  // persisted until a status report reaches Portal (BSD-11), and refused locally from now on
  if (!ctx.state.reports.revoked.some((r) => r.con === con)) ctx.state.reports.revoked.push({ con, reason });
  ctx.state.saveReports();
  revokedLocally.add(con);
  ctx.log.warn("bridge.connection.revoked", { con, code: reason });
  ctx.emit("connection-revoked", con);
}

/** Connections revoked here stay refused even if a stale config still lists them active. */
export const revokedLocally = new Set<string>();
