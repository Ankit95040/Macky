/**
 * Shared M2 test fixtures. Trusted setup helpers only — these simulate
 * the TRUSTED layer (grant issuance, confirmation recording). The
 * planner side is always raw `unknown` payloads.
 */
import { createLog, type AuditLog } from "../src/kernel/audit.js";
import {
  createConfirmationStore,
  type ConfirmationStore,
} from "../src/kernel/confirm.js";
import { issueGrant, type TrustedTaskGrant } from "../src/kernel/task-grants.js";
import type { AuthorizationContext } from "../src/kernel/authorize.js";
import type { SleepState } from "../src/kernel/types.js";

export interface Fixture {
  ctx: AuthorizationContext;
}

export function baseGrants(): Array<TrustedTaskGrant> {
  return [
    issueGrant({
      grantId: "g-fs-read",
      taskId: "task-A",
      capability: "filesystem.read",
      scope: "/project",
    }),
    issueGrant({
      grantId: "g-git-read",
      taskId: "task-A",
      capability: "git.read",
      scope: "/project",
    }),
    issueGrant({
      grantId: "g-net",
      taskId: "task-A",
      capability: "network.request",
      scope: "example.com",
    }),
    issueGrant({
      grantId: "g-del",
      taskId: "task-A",
      capability: "filesystem.delete",
      scope: "/project",
    }),
  ];
}

export function makeCtx(overrides?: {
  sleep?: SleepState;
  grants?: ReadonlyArray<TrustedTaskGrant>;
  confirmations?: ConfirmationStore;
  log?: AuditLog;
}): Fixture {
  return {
    ctx: {
      sleep: overrides?.sleep ?? "AWAKE",
      grants: overrides?.grants ?? baseGrants(),
      confirmations: overrides?.confirmations ?? createConfirmationStore(),
      log: overrides?.log ?? createLog(),
    },
  };
}
