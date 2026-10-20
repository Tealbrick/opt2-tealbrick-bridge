/**
 * Standalone mode after leaving Portal (BRIDGE §11, CREDENTIALS §17, C16 B7). The final Portal-signed
 * config is frozen (S2, never edited). From it the bridge re-mints grants and slices with its own key
 * (K7) at half-life and applies the owner's admin overlay (S9). Admin = exactly 4 ops.
 */
import type { IncomingMessage, ServerResponse } from "node:http";
import { isRefusal } from "@opt2-tealbrick/relay";
import type { AdminTicketResult, InstanceSlice, WorkspaceConfig } from "@opt2-tealbrick/spec/bridge";
import { type AgentId, type ConnectionId, type GrantClaims, LIFETIME_S, type OwnerAssertionClaims, TYP } from "@opt2-tealbrick/spec/credentials";
import { BRIDGE_CAPS_DECLARED } from "./caps.ts";
import type { BridgeContext } from "./context.ts";
import { revokeLocal } from "./identity.ts";
import { buildTable, internalUrlAllowed, peekClaims, portalKeySet } from "./table.ts";
import { BridgeError, envelope, headerValue, isRecord, nowS, parseJson, readBody, sendError, sendJson } from "./util.ts";

/** Builds and swaps the self-issued table from the frozen final config + overlay. */
export async function remintStandalone(ctx: BridgeContext): Promise<void> {
  const id = ctx.identity;
  const frozenJws = ctx.state.loadConfigJws();
  if (!id || !frozenJws) return;
  const peeked = peekClaims<WorkspaceConfig>(frozenJws);
  if (!peeked?.standalone) return;
  // BSD-03: the frozen final config is re-verified with the last trusted Portal key set before anything is
  // re-minted from it (only its age is waived: the bridge is the issuer now); a planted file is refused.
  const fv = ctx.api.verifyConfig(frozenJws, { now: Math.min(nowS(), peeked.exp - 1), self: ctx.bridgeRef, issuers: portalKeySet(ctx.api, id.portalKeys) });
  if (isRefusal(fv)) {
    ctx.reject({ kind: "config", code: fv.code, detail: `${fv.reason}; frozen standalone config refused` });
    return;
  }
  const frozen = fv.body as WorkspaceConfig;
  // L3 (C116, QA J2-15): a final document that lists agents and apps but carries NO agent grants leaves every agent
  // without app tools for good (nothing is pulled after Leave Portal). Still applied (fail closed), never silent.
  if (frozen.agents.length && frozen.apps.length && !frozen.grants.some((g) => peekClaims<GrantClaims>(g)?.sub?.startsWith("tb:agt:"))) {
    ctx.reject({ kind: "config", code: "standalone_without_grants", detail: `final config rev ${frozen.rev}: ${frozen.agents.length} agents, ${frozen.apps.length} apps, 0 agent grants` });
  }
  if (!ctx.state.standalone) ctx.state.standalone = { pausedWorkspace: frozen.pause.workspace, pausedAgents: [...frozen.pause.agents], revokedConnections: [], rev: frozen.rev };
  const overlay = ctx.state.standalone;
  overlay.rev += 1;
  ctx.state.saveStandalone();
  const now = nowS();
  const exp = now + LIFETIME_S.configOrSlice;
  const ref = ctx.bridgeRef;
  const pause = { workspace: overlay.pausedWorkspace, agents: overlay.pausedAgents, instances: frozen.pause.instances };
  const grants: string[] = [];
  for (const g of frozen.grants) {
    const c = peekClaims<GrantClaims>(g);
    if (!c) continue;
    if (c.sub.startsWith("tb:agt:") && overlay.pausedAgents.includes(c.sub.slice(7) as AgentId)) continue;
    if (overlay.pausedWorkspace) continue;
    grants.push(await ctx.api.signJws(TYP.grant, { ...c, iss: ref, iat: now, exp }, id.key));
  }
  const apps = [];
  for (const a of frozen.apps) {
    const s = peekClaims<InstanceSlice>(a.slice);
    if (!s) continue;
    const companion: string[] = [];
    // a slice without grants/agents (older or minimal) must not abort the whole re-mint (no silent dead end)
    for (const g of s.grants ?? []) {
      const c = peekClaims<GrantClaims>(g);
      if (c) companion.push(await ctx.api.signJws(TYP.grant, { ...c, iss: ref, iat: now, exp }, id.key));
    }
    const slice: InstanceSlice = {
      ...s,
      iss: ref,
      iat: now,
      exp,
      jti: ctx.api.ulid(),
      rev: overlay.rev,
      portalKeys: [],
      // BRIDGE §11: a re-minted slice always names the standalone issuer (the SDK trusts only it from now on)
      ...(s.standalone ?? frozen.standalone ? { standalone: s.standalone ?? frozen.standalone } : {}),
      pause,
      // spec 0.1.54 (C292): a standalone bridge has no Core to copy its caps, so it sets `slice.bridge.caps` itself
      ...(s.bridge ? { bridge: { ...s.bridge, caps: [...BRIDGE_CAPS_DECLARED] } } : {}),
      grants: overlay.pausedWorkspace ? [] : companion,
      agents: (s.agents ?? []).map((ag) => ({ ...ag, status: overlay.pausedAgents.includes(ag.id) ? "paused" : ag.status })),
    };
    apps.push({ ...a, slice: await ctx.api.signJws(TYP.slice, slice, id.key) });
  }
  const config: WorkspaceConfig = {
    ...frozen,
    iss: ref,
    iat: now,
    exp,
    jti: ctx.api.ulid(),
    rev: overlay.rev,
    portalKeys: [],
    pause,
    connections: frozen.connections.map((c) => (overlay.revokedConnections.includes(c.con) ? { ...c, status: "revoked" as const } : c)),
    grants,
    apps,
  };
  const jws = await ctx.api.signJws(TYP.config, config, id.key);
  const own = ctx.ownKeySet();
  const table = await buildTable({ api: ctx.api, config, jws, bridgeId: id.bridgeId, ownKeys: own, issuers: own, previous: ctx.table, fetchManifest: async () => { throw new Error("manifest from previous table only"); }, internalUrlAllowed: (e) => internalUrlAllowed(ctx.api, e.internalUrl, e.ownInfra === true, ctx.ownInfraOrigins), now, reject: (r) => ctx.reject(r) });
  // manifests are reused from the previous table (same digests); refetch any that are missing
  for (const [ins, app] of table.apps) {
    const prev = ctx.table?.apps.get(ins);
    if (!app.manifest && prev?.manifest) table.apps.set(ins, { ...prev, entry: app.entry });
  }
  for (const app of table.apps.values()) table.appsByProduct.set(app.entry.product, app);
  ctx.swapTable(table);
  ctx.log.info("bridge.standalone.reminted", { rev: overlay.rev });
}

/** Re-mints at half-life (6 h) while running standalone. */
export function startStandaloneLoop(ctx: BridgeContext, signal: AbortSignal): void {
  const tick = setInterval(() => {
    const t = ctx.table;
    if (t?.standalone && t.exp - nowS() < LIFETIME_S.grantRemintBelow) void remintStandalone(ctx);
  }, 60_000);
  signal.addEventListener("abort", () => clearInterval(tick));
}

export class StandaloneAdmin {
  private readonly ctx: BridgeContext;
  private readonly seen = new Map<string, number>();

  constructor(ctx: BridgeContext) {
    this.ctx = ctx;
  }

  async handle(req: IncomingMessage, res: ServerResponse, requestId: string): Promise<void> {
    const t = this.ctx.table;
    const frozen = t?.standalone ? peekClaims<WorkspaceConfig>(this.ctx.state.loadConfigJws() ?? "") : undefined;
    if (!t?.standalone || !frozen?.standalone || req.method !== "POST") return sendJson(res, 404, envelope("not_found", "not found", requestId));
    try {
      const raw = await readBody(req, 8 * 1024);
      const token = headerValue(req, "tb-assert") ?? "";
      const iss = peekClaims<OwnerAssertionClaims>(token)?.iss;
      if (!iss?.startsWith("tb:per:")) throw new BridgeError("unauthenticated", 401);
      const keys = this.ctx.api.keySetFrom({ keys: frozen.standalone.ownerKeys }, iss as never);
      const now = nowS();
      const v = this.ctx.api.verifyAssertion<OwnerAssertionClaims>(token, keys, {
        typ: TYP.ownerAssertion,
        aud: this.ctx.bridgeRef,
        iss: [iss],
        now,
        maxLifetimeS: LIFETIME_S.proof,
        request: { method: "POST", pathAndQuery: req.url ?? "/", ...(raw.length ? { body: raw } : {}) },
      });
      if (isRefusal(v)) throw new BridgeError("unauthenticated", 401);
      for (const [k, e] of this.seen) if (e <= now) this.seen.delete(k);
      const replayKey = `${v.header.kid}|${v.claims.jti}`;
      if (this.seen.has(replayKey) || this.ctx.proofBeforeBoot(v.claims.iat, now)) throw new BridgeError("unauthenticated", 401);
      this.seen.set(replayKey, v.claims.exp + 30);
      const body = (parseJson(raw) ?? {}) as Record<string, unknown>;
      if (!isRecord(body)) throw new BridgeError("input_invalid", 400);
      const overlay = this.ctx.state.standalone;
      if (!overlay) throw new BridgeError("app_unavailable", 503);
      const path = new URL(req.url ?? "/", "http://x").pathname;
      if (path === "/admin/v1/pause" || path === "/admin/v1/resume") {
        const pause = path.endsWith("/pause");
        const agt = typeof body.agt === "string" ? (body.agt as AgentId) : undefined;
        if (agt && !t.agents.has(agt)) throw new BridgeError("not_found", 404);
        if (agt) overlay.pausedAgents = pause ? [...new Set([...overlay.pausedAgents, agt])] : overlay.pausedAgents.filter((a) => a !== agt);
        else overlay.pausedWorkspace = pause;
        this.ctx.state.saveStandalone();
        await remintStandalone(this.ctx);
        return sendJson(res, 200, { ok: true });
      }
      if (path === "/admin/v1/revoke-connection") {
        const con = typeof body.con === "string" ? (body.con as ConnectionId) : undefined;
        if (!con) throw new BridgeError("input_invalid", 400);
        revokeLocal(this.ctx, con, "client_revoke");
        await remintStandalone(this.ctx);
        return sendJson(res, 200, { ok: true });
      }
      if (path === "/admin/v1/ticket") {
        const id = this.ctx.identity;
        if (!id) throw new BridgeError("app_unavailable", 503);
        const ref = this.ctx.bridgeRef;
        if (body.pur === "keys") {
          const ticket = await this.ctx.api.signJws(TYP.personTicket, { iss: ref, sub: iss, aud: ref, iat: now, exp: now + LIFETIME_S.ticketKeys, jti: this.ctx.api.ulid(), ws: t.ws, pur: "keys" }, id.key);
          const out: AdminTicketResult = { ticket, url: `${this.ctx.keysUrl ?? this.ctx.publicUrl}/keys` };
          return sendJson(res, 200, out);
        }
        if (body.pur === "launch" && typeof body.product === "string") {
          const app = t.appsByProduct.get(body.product);
          if (!app) throw new BridgeError("not_found", 404);
          const ticket = await this.ctx.api.signJws(
            TYP.personTicket,
            { iss: ref, sub: iss, aud: `tb:ins:${app.entry.ins}`, iat: now, exp: now + LIFETIME_S.ticketLaunch, jti: this.ctx.api.ulid(), ws: t.ws, pur: "launch", ...(typeof body.path === "string" ? { path: body.path } : {}) },
            id.key,
          );
          const out: AdminTicketResult = { ticket, url: `${this.ctx.publicUrl}/a/${app.entry.product}/tb/launch` };
          return sendJson(res, 200, out);
        }
        throw new BridgeError("input_invalid", 400);
      }
      sendJson(res, 404, envelope("not_found", "not found", requestId));
    } catch (e) {
      sendError(res, e, requestId);
    }
  }
}
