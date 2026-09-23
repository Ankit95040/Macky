/**
 * Shared M3 fixtures. Tests use real OS temp dirs (cleaned up after
 * each test) — the ONLY place side effects belong in M3.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { createLog } from "../src/kernel/audit.js";
import { createConfirmationStore } from "../src/kernel/confirm.js";
import {
  createKillSwitch,
  engageKillSwitch,
  type KillSwitchState,
} from "../src/kernel/kill-switch.js";
import { issueGrant } from "../src/kernel/task-grants.js";
import type { ExecutionContext } from "../src/executor/executor.js";
import type { SleepState } from "../src/kernel/types.js";

export interface Sandbox {
  /** Realpath-resolved root (macOS /var → /private/var). */
  readonly root: string;
  readonly cleanup: () => void;
}

export function makeSandbox(files?: Record<string, string>): Sandbox {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "macky-m3-"));
  const root = fs.realpathSync(tmp);
  if (files !== undefined) {
    for (const [rel, content] of Object.entries(files)) {
      const full = path.join(root, rel);
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, content);
    }
  }
  return {
    root,
    cleanup: () => {
      fs.rmSync(tmp, { recursive: true, force: true });
    },
  };
}

export function makeExecCtx(
  root: string,
  opts?: {
    sleep?: SleepState;
    taskId?: string;
    kill?: KillSwitchState;
  },
): { ctx: ExecutionContext; killState: KillSwitchState } {
  const taskId = opts?.taskId ?? "task-M3";
  const ks = createKillSwitch();
  const killState = opts?.kill ?? ks.state;
  return {
    killState,
    ctx: {
      sleep: opts?.sleep ?? "AWAKE",
      grants: [
        issueGrant({
          grantId: "g-m3-fs",
          taskId,
          capability: "filesystem.read",
          scope: root,
        }),
        issueGrant({
          grantId: "g-m3-git",
          taskId,
          capability: "git.read",
          scope: root,
        }),
        issueGrant({
          grantId: "g-m3-sys",
          taskId,
          capability: "system.info",
          scope: "",
        }),
      ],
      confirmations: createConfirmationStore(),
      killSwitch: killState,
      log: createLog(),
    },
  };
}

export function readReq(
  resource: string,
  taskId = "task-M3",
): Record<string, string> {
  return {
    capability: "filesystem.read",
    operation: "read",
    resource,
    taskId,
  };
}

/**
 * True when the log shows the request was dispatched to an adapter
 * (past authorization). Adapter-level refusals (symlink escape,
 * sensitive path, limits, missing files) legitimately show `started`
 * followed by rejection — the invariant is that they never `completed`.
 */
export function reachedOs(log: { events: ReadonlyArray<{ type: string }> }): boolean {
  return log.events.some((e) => e.type === "execution.started");
}

/** True when an adapter returned data (the actual OS-read boundary). */
export function completedOs(
  log: { events: ReadonlyArray<{ type: string }> },
): boolean {
  return log.events.some((e) => e.type === "execution.completed");
}

export { engageKillSwitch };
