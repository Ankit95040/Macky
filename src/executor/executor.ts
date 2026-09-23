/**
 * Trusted executor (M3 sections 1/2/9/10/11/13/14).
 *
 * THE single path from authorization to macOS. Entry point `run()`
 * takes an UNTRUSTED request plus the TRUSTED context and authorizes
 * INTERNALLY via M2 `authorize()` — there is deliberately NO
 * `execute(decision)` API, because accepting an external decision
 * object would admit forged ALLOWs. Authorization and execution are
 * bound structurally: the same request object is authorized and
 * executed in one call, so post-approval mutation is impossible.
 *
 * Pre-OS checks, in order: kill switch → internal authorize (must be
 * ALLOW with all checks passed) → sleep re-check immediately before
 * OS access (closes any authorize→execute gap) → operation allowlist
 * → grant-root rebinding (execution re-derives the authorized root
 * from live grants) → adapter.
 *
 * Failures are structured outcomes. There is no fallback executor,
 * no shell fallback, no generic path. Nothing here writes, mutates,
 * or touches the network.
 */
import {
  appendSecurityEvent,
  type AuditLog,
  type SecurityEventType,
} from "../kernel/audit.js";
import {
  authorize,
  type AuthorizationContext,
} from "../kernel/authorize.js";
import {
  getCapabilityDefinition,
  isWithinScope,
} from "../kernel/capability-model.js";
import {
  isEngaged,
  type KillSwitchState,
} from "../kernel/kill-switch.js";
import { grantsForTask, type TrustedTaskGrant } from "../kernel/task-grants.js";
import type { ConfirmationStore } from "../kernel/confirm.js";
import type { SleepState } from "../kernel/types.js";
import { listDirectory, readFile } from "./adapters/fs-read.js";
import { runGitRead, type GitOperation } from "./adapters/git-read.js";
import { readSystemInfo } from "./adapters/system-info.js";

export interface ExecutionContext {
  readonly sleep: SleepState;
  readonly grants: ReadonlyArray<TrustedTaskGrant>;
  readonly confirmations: ConfirmationStore;
  readonly killSwitch: KillSwitchState;
  readonly log: AuditLog;
}

export type ExecutionOutcome =
  | {
      readonly status: "completed";
      readonly operation: string;
      readonly result: unknown;
      readonly redacted: boolean;
    }
  | { readonly status: "refused"; readonly stage: string; readonly reason: string }
  | { readonly status: "failed"; readonly stage: "adapter"; readonly reason: string };

export interface ExecutionResult {
  readonly outcome: ExecutionOutcome;
  readonly log: AuditLog;
}

/** Exact (capability, operation) pairs the executor will run. Nothing else. */
export const EXECUTABLE_OPERATIONS: ReadonlyArray<{
  readonly capability: string;
  readonly operation: string;
}> = Object.freeze([
  Object.freeze({ capability: "system.info", operation: "info" }),
  Object.freeze({ capability: "filesystem.read", operation: "read" }),
  Object.freeze({ capability: "filesystem.read", operation: "list" }),
  Object.freeze({ capability: "git.read", operation: "status" }),
  Object.freeze({ capability: "git.read", operation: "log" }),
  Object.freeze({ capability: "git.read", operation: "diff" }),
]);

function isExecutable(capability: string, operation: string): boolean {
  return EXECUTABLE_OPERATIONS.some(
    (e) => e.capability === capability && e.operation === operation,
  );
}

function withEvent(
  log: AuditLog,
  type: SecurityEventType,
  detail: string,
  sleep: SleepState,
): AuditLog {
  return appendSecurityEvent(log, type, detail, sleep);
}

function refuse(
  ctx: ExecutionContext,
  log: AuditLog,
  stage: string,
  reason: string,
  event: SecurityEventType,
): ExecutionResult {
  return {
    outcome: { status: "refused", stage, reason },
    log: withEvent(log, event, `${stage}: ${reason}`, ctx.sleep),
  };
}

/**
 * Re-derive the authorized root from LIVE grants (binding, M3 §10).
 * Returns the first live grant scope containing the resource.
 */
function boundRoot(
  ctx: ExecutionContext,
  taskId: string,
  capability: string,
  resource: string,
): string | undefined {
  const definition = getCapabilityDefinition(capability);
  if (definition === undefined) {
    return undefined;
  }
  for (const grant of grantsForTask(ctx.grants, taskId)) {
    if (grant.capability !== capability || grant.revoked) {
      continue;
    }
    if (isWithinScope(definition, grant.scope, resource)) {
      return grant.scope;
    }
  }
  return undefined;
}

/**
 * Authorize-then-execute one untrusted request. Pure orchestration
 * around real reads: the only side effects in M3 are the read-only
 * adapter calls below, reachable solely after an ALLOW.
 */
export function run(request: unknown, ctx: ExecutionContext): ExecutionResult {
  // -- kill switch first: engaged blocks new operations entirely ---------
  if (isEngaged(ctx.killSwitch)) {
    return refuse(
      ctx,
      ctx.log,
      "kill-switch",
      "kill switch engaged: new operations denied",
      "execution.rejected",
    );
  }

  // -- internal authorization: the ONLY decision the executor trusts -----
  const authCtx: AuthorizationContext = {
    sleep: ctx.sleep,
    grants: ctx.grants,
    confirmations: ctx.confirmations,
    log: ctx.log,
  };
  const authorized = authorize(request, authCtx);
  let log = authorized.log;
  const decision = authorized.decision;

  if (decision.verdict !== "allow") {
    return refuse(
      ctx,
      log,
      "authorization",
      `authorization did not allow (got ${decision.verdict})`,
      "execution.rejected",
    );
  }
  // Decision well-formedness: authorize() is trusted internal code, so
  // the verdict is authoritative. This guards the shape only — note that
  // informational checks legitimately carry passed:false (e.g.
  // "confirmation.required" is false when no confirmation is needed),
  // so the checks array is never treated as a conjunction here.
  if (decision.capability === "unknown" || decision.operation === "unknown") {
    return refuse(
      ctx,
      log,
      "decision",
      "malformed authorization decision",
      "execution.rejected",
    );
  }

  // -- sleep re-check immediately before OS access (§11) -------------------
  // Same trusted value, checked at the OS boundary so that sleep stops
  // execution even if an earlier authorization existed.
  if (ctx.sleep !== "AWAKE") {
    return refuse(
      ctx,
      log,
      "sleep",
      "system is asleep: execution denied",
      "execution.rejected",
    );
  }

  // -- operation allowlist: no adapter, no execution ------------------------
  if (!isExecutable(decision.capability, decision.operation)) {
    return refuse(
      ctx,
      log,
      "adapter",
      `no execution adapter for "${decision.capability}:${decision.operation}"`,
      "execution.rejected",
    );
  }

  const opName = `${decision.capability}:${decision.operation}`;
  log = withEvent(log, "execution.started", `started ${opName}`, ctx.sleep);

  try {
    if (
      decision.capability === "system.info" &&
      decision.operation === "info"
    ) {
      const info = readSystemInfo();
      log = withEvent(
        log,
        "execution.completed",
        `completed ${opName}`,
        ctx.sleep,
      );
      return {
        outcome: { status: "completed", operation: opName, result: info, redacted: false },
        log,
      };
    }

    // -- filesystem / git: rebind to the exact authorized root -------------
    if (decision.taskId === undefined) {
      return refuse(ctx, log, "binding", "missing task binding", "execution.rejected");
    }
    const resource =
      typeof request === "object" && request !== null
        ? (request as { resource?: unknown }).resource
        : undefined;
    if (typeof resource !== "string") {
      return refuse(ctx, log, "binding", "missing resource", "execution.rejected");
    }
    const root = boundRoot(ctx, decision.taskId, decision.capability, resource);
    if (root === undefined) {
      return refuse(
        ctx,
        log,
        "binding",
        "no live grant scope binds this resource",
        "execution.rejected",
      );
    }

    if (decision.capability === "filesystem.read") {
      const adapter =
        decision.operation === "list" ? listDirectory(root, resource) : readFile(root, resource);
      return finishAdapter(ctx, log, opName, adapter);
    }

    if (decision.capability === "git.read") {
      const adapter = runGitRead(
        root,
        resource,
        decision.operation as GitOperation,
      );
      return finishAdapter(ctx, log, opName, adapter);
    }

    return refuse(ctx, log, "adapter", `unreachable operation ${opName}`, "execution.rejected");
  } catch {
    return {
      outcome: { status: "failed", stage: "adapter", reason: "adapter error" },
      log: withEvent(log, "execution.failed", `failed ${opName}: adapter error`, ctx.sleep),
    };
  }
}

function finishAdapter(
  ctx: ExecutionContext,
  log: AuditLog,
  opName: string,
  adapter:
    | { readonly ok: true; readonly value: unknown; readonly redacted: boolean }
    | { readonly ok: false; readonly reason: string },
): ExecutionResult {
  if (!adapter.ok) {
    const limit = adapter.reason.includes("limit");
    return {
      outcome: { status: "refused", stage: "adapter", reason: adapter.reason },
      log: withEvent(
        log,
        limit ? "limit.exceeded" : "execution.rejected",
        `${opName}: ${adapter.reason}`,
        ctx.sleep,
      ),
    };
  }
  let next = log;
  if (adapter.redacted) {
    next = withEvent(next, "result.redacted", `${opName}: secrets redacted`, ctx.sleep);
  }
  return {
    outcome: {
      status: "completed",
      operation: opName,
      result: adapter.value,
      redacted: adapter.redacted,
    },
    log: withEvent(next, "execution.completed", `completed ${opName}`, ctx.sleep),
  };
}
