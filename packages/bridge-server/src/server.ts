#!/usr/bin/env node
/**
 * Deployed bridge entry (Docker image on the workspace private network). Process wiring only:
 * env, signals, graceful shutdown. All behaviour lives in @opt2-tealbrick/bridge.
 *
 * Two roles, one image (BRIDGE §9.2, LA-1): `TB_ROLE` unset or `bridge` = the workspace bridge; `TB_ROLE=views` = the
 * workspace views service (tb-views): no volume, no Portal, no enrolment, no keys. Env of the views role: `TB_VIEWS_UPSTREAM`
 * (the bridge private origin), `TB_VIEWS_KEY`, `PORT`. It refuses to start when TB_ENROL_CODE, TB_KEK or TB_PORTAL_URL is set.
 *
 * Env of the bridge role (BRIDGE §4.1, §3; LA-1: TB_VIEWS_KEY, TB_VIEWS_KEY_PREVIOUS (rotation only) and TB_VIEWS_PUBLIC_URL when the workspace has a views service): TB_PORTAL_URL, TB_ENROL_CODE, TB_KEK, TB_PUBLIC_URL, TB_DATA_DIR,
 * PORT (public listener), TB_INTERNAL_PORT (private listener, default 8788), TB_INTERNAL_HOST (an IP address: private listener
 * address, default `::` as before, the Railway private network, BRG-29; a host name: the stable host the bridge advertises, S1, not bound),
 * TB_OWN_INFRA_ORIGINS (own-infrastructure app origins, read at boot: a change needs a restart), TB_PUBLIC_HOST (public listener address,
 * default: no host as before; C171). KEK rotation (BRG-05): set the new key
 * as TB_KEK and the old one as TB_KEK_PREVIOUS for ONE start (every sealed record moves to TB_KEK), then drop it.
 */
import { lchownSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { dropPrivileges, jsonLogger, loadManifestApi, onStopSignals, RUN_UID, startBridge, startViews, ViewsRoleError } from "@opt2-tealbrick/bridge";

/** Process calls the drop needs (tests pass fakes). */
export interface PrivilegeProcess {
  getuid?: () => number;
  getgid?: () => number;
  setuid?: (id: number) => void;
  setgid?: (id: number) => void;
  setgroups?: (groups: number[]) => void;
  chown?: (path: string, uid: number, gid: number) => void;
}

/**
 * BSD-04: Railway runs volume services as root (RAILWAY_RUN_UID=0). Before any state load or listen: chown the
 * data dir to 1000:1000 and drop to uid/gid 1000 via the SDK helper; never keep running as root.
 */
export function dropRoot(env: NodeJS.ProcessEnv, proc: PrivilegeProcess = { getuid: process.getuid, getgid: process.getgid, setuid: process.setuid, setgid: process.setgid, setgroups: process.setgroups, chown: lchownSync }): boolean {
  const dataDir = env.TB_DATA_DIR;
  if (!dataDir) throw new Error("TB_DATA_DIR is required");
  const dropped = dropPrivileges({ dataDir, backupDir: dataDir }, proc);
  const uid = proc.getuid?.();
  if (uid === 0) throw new Error("refusing to run as root");
  if (dropped && uid !== RUN_UID) throw new Error("privilege drop did not reach uid 1000");
  return dropped;
}

/** The role this process runs (`TB_ROLE`): the bridge by default, or the views service. Anything else is a refusal. */
export function roleOf(env: NodeJS.ProcessEnv): "bridge" | "views" {
  const role = (env.TB_ROLE ?? "").trim();
  if (role === "" || role === "bridge") return "bridge";
  if (role === "views") return "views";
  throw new ViewsRoleError('TB_ROLE must be "bridge" or "views"');
}

/**
 * The views service has no volume, so it has no data dir to hand over; it must still never keep running as root. The image
 * runs as uid 1000 already; started as root anyway, it drops with the SDK's one drop (`dropPrivileges`) over a fresh EMPTY
 * scratch dir (the drop chowns its dir arguments; nothing of the workspace is touched), then removes that dir.
 */
export function dropViewsRoot(proc: PrivilegeProcess = { getuid: process.getuid, getgid: process.getgid, setuid: process.setuid, setgid: process.setgid, setgroups: process.setgroups, chown: lchownSync }): boolean {
  if (proc.getuid?.() !== 0) return false;
  const scratch = mkdtempSync(join(tmpdir(), "tb-views-"));
  const dropped = dropPrivileges({ dataDir: scratch, backupDir: scratch }, proc);
  if (proc.getuid?.() === 0) throw new Error("refusing to run as root");
  rmSync(scratch, { recursive: true, force: true });
  return dropped;
}

export async function main(): Promise<void> {
  const logger = jsonLogger();
  if (roleOf(process.env) === "views") {
    if (dropViewsRoot()) logger.info("views.privileges_dropped", { uid: process.getuid?.() ?? null });
    onStopSignals(await startViews({ logger }), logger);
    return;
  }
  if (dropRoot(process.env)) logger.info("bridge.privileges_dropped", { uid: process.getuid?.() ?? null });
  const api = await loadManifestApi();
  // F57a / L21: SIGTERM drains (in-flight calls finish, new ones are refused retryably), then the process exits
  onStopSignals(await startBridge({ api, logger }), logger);
}

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith("/server.js")) {
  main().catch((e: unknown) => {
    process.stderr.write(`${JSON.stringify({ ts: new Date().toISOString(), level: "error", event: "bridge.boot_failed", code: e instanceof Error ? e.message.slice(0, 200) : "error" })}\n`);
    process.exit(1);
  });
}
