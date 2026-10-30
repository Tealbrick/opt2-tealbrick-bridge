/**
 * Acting agents (spec 0.1.88, C378, BRIDGE §8.7, cap `acting_agents`): the K15 ticket and the merge rule of `tb.acting`.
 * Only this bridge signs and reads a K15: an app stores it and presents it, so the claim rules live here. A ticket is a FACT for
 * hooks: it never changes a grant, the gate or a held family, and every reader of `tb.acting` may only narrow on it.
 */
import { signCompact, verifySignedCompact } from "@opt2-tealbrick/manifest";
import type { AgentId, CallId, InstanceId } from "@opt2-tealbrick/spec/credentials";
import type { BridgeContext } from "./context.ts";
import { insRef, type Table } from "./table.ts";
import { BridgeError, isRecord, nowS } from "./util.ts";

// LOCAL COPY of spec 0.1.88 (bridge.ts, credentials.ts). The bridge pins spec 0.1.78 like the manifest it pins; move the pin and drop this
// block when the manifest package pins spec >= 0.1.88 (a spec jump alone breaks the manifest's types). K15 is signed and read only here.
export const ACTING_AGENTS_MAX = 4;
const ACTING_JOB_PATTERN = "^[A-Za-z0-9_.:-]{1,128}$";
export const ACTING_TICKET_TYP = "tb-act+jwt";
export const ACTING_TICKET_LIFETIME_S = 30 * 86400;
export const ACTING_TICKETS_PATH = "/tb/v1/acting-tickets";
export const POLICY_RECHECK_PATH = "/tb/v1/policy-recheck";
export const ACTING_AGENTS_CAP = "acting_agents";
export interface ActingAgent {
  id: AgentId;
  via: "parent_call" | "ticket";
  job?: string;
}
export interface ActingEnvelope {
  job: string;
  tickets: string[];
}
export interface ActingTicketRequest {
  call: CallId;
  job: string;
}
export interface ActingTicketResponse {
  tickets: string[];
}
export interface PolicyRecheckRequest {
  op: string;
  input: unknown;
  caller: { type: "agent"; id: string } | { type: "app"; id: string };
}
export type PolicyRecheckResponse = { decision: "allow" } | { decision: "hold"; family: string; reason: string; by: string };
interface ActingTicketClaims {
  iss: string;
  sub: string;
  aud: string;
  iat: number;
  exp: number;
  jti: string;
  call: CallId;
  op: string;
  job: string;
}
/** the manifest's MAX_JWS_BYTES (not exported) */
const MAX_JWS_BYTES = 8192;

const JOB_RE = new RegExp(ACTING_JOB_PATTERN);
const AGENT_REF_RE = /^tb:agt:(agt_[0-9A-HJKMNP-TV-Z]{26})$/;
const CLAIMS = new Set(["iss", "sub", "aud", "iat", "exp", "jti", "call", "op", "job"]);

export const validJob = (job: unknown): job is string => typeof job === "string" && JOB_RE.test(job);

const invalid = (reason: string): BridgeError => new BridgeError("acting_ticket_invalid", 403, "an acting ticket was refused", { reason });

/** One K15 per agent of the open call. The caller has checked that the call is open and was delivered to `ins` as target. */
export async function mintActingTickets(ctx: BridgeContext, ins: InstanceId, agents: readonly AgentId[], call: CallId, op: string, job: string): Promise<string[]> {
  const id = ctx.identity;
  if (!id) throw new BridgeError("app_unavailable", 503);
  const iat = nowS();
  return Promise.all(
    agents.map((agt) => {
      const claims: ActingTicketClaims = { iss: ctx.bridgeRef, sub: `tb:agt:${agt}`, aud: insRef(ins), iat, exp: iat + ACTING_TICKET_LIFETIME_S, jti: ctx.api.ulid(), call, op, job } ;
      return signCompact(ACTING_TICKET_TYP, claims, id.key, MAX_JWS_BYTES);
    }),
  );
}

/**
 * `CallEnvelope.acting` of a companion call from `ins`, every check of BRIDGE §8.7 rule 5. Any failure refuses the whole call: there
 * is no fallback to "no agent". `details.reason` names the check, never a value.
 */
export function verifyActing(ctx: BridgeContext, t: Table, ins: InstanceId, acting: unknown): ActingAgent[] {
  const env = acting as ActingEnvelope;
  if (!isRecord(acting) || !validJob(env.job) || !Array.isArray(env.tickets) || env.tickets.length < 1 || Object.keys(acting).some((k) => k !== "job" && k !== "tickets")) throw new BridgeError("input_invalid", 400, "acting needs a job and 1 to 4 tickets", { pointer: "/acting" });
  if (env.tickets.length > ACTING_AGENTS_MAX) throw invalid("too_many");
  const now = nowS();
  const seen = new Set<string>();
  return env.tickets.map((ticket) => {
    if (typeof ticket !== "string") throw invalid("not_a_ticket");
    const v = verifySignedCompact(ticket, ctx.ownKeySet(), ACTING_TICKET_TYP, MAX_JWS_BYTES);
    if (!v.ok) throw invalid("signature");
    const c = v.payload as Partial<ActingTicketClaims> | undefined;
    if (!isRecord(c) || Object.keys(c).some((k) => !CLAIMS.has(k))) throw invalid("claims");
    if (c.iss !== ctx.bridgeRef) throw invalid("issuer");
    if (c.aud !== insRef(ins)) throw invalid("audience");
    if (typeof c.iat !== "number" || typeof c.exp !== "number" || c.exp - c.iat <= 0 || c.exp - c.iat > ACTING_TICKET_LIFETIME_S) throw invalid("lifetime");
    if (now >= c.exp) throw invalid("expired");
    if (c.job !== env.job) throw invalid("job");
    const agt = typeof c.sub === "string" ? AGENT_REF_RE.exec(c.sub)?.[1] : undefined;
    if (!agt) throw invalid("subject");
    if (!t.agents.has(agt as AgentId)) throw invalid("agent_removed");
    if (seen.has(agt)) throw invalid("duplicate");
    seen.add(agt);
    return { id: agt as AgentId, via: "ticket" as const, job: env.job };
  });
}

/** Tickets and the parent chain, distinct, tickets first. More than ACTING_AGENTS_MAX refuses the call. */
export function mergeActing(tickets: readonly ActingAgent[], inherited: readonly ActingAgent[]): ActingAgent[] {
  const out = [...tickets];
  for (const a of inherited) if (!out.some((x) => x.id === a.id)) out.push(a);
  if (out.length > ACTING_AGENTS_MAX) throw invalid("too_many");
  return out;
}
