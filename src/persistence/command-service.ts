/**
 * Trusted command service (M8 flow). Strict proposal validation →
 * workspace binding + reverify → classifier (Tier3/unknown die here,
 * BEFORE authorization, so no confirmation can ever revive them) →
 * cwd resolution → argv validation → kill/sleep prechecks → M2
 * authorize() (the SOLE authorization authority; Tier2 confirmations
 * resolve through the trusted M2 store) → bounded spawn → audit.
 *
 * Relationship to M5: command proposals cannot ride the M5
 * family/operation translation (that table cannot express per-command
 * capabilities without a forbidden generic terminal entry), so this
 * service applies the IDENTICAL trust disciplines (strict schema,
 * trusted task binding, zero planner authority) and routes the actual
 * allow/deny DECISION through M2 authorize(). No parallel
 * authorization exists. M3 run() structurally cannot execute commands
 * (argv is unrepresentable in M2 requests) — commands run only here.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { authorize } from "../kernel/authorize.js";
import { isEngaged } from "../kernel/kill-switch.js";
import { appendAuditEvent } from "./audit-store.js";
import { resolveWithinRoot } from "../executor/paths.js";
import { reverifyWorkspace, type WorkspaceRegistry } from "../workspace/registry.js";
import { classify, validateArgv } from "../commands/classifier.js";
import { CommandProposalSchema } from "../commands/proposal.js";
import { CommandResultSchema, type CommandResult } from "../commands/result.js";
import {
  releaseCommandSlot,
  runSpawned,
  tryAcquireCommandSlot,
} from "../commands/runner.js";
import {
  persistLogDelta,
  type DurableResult,
  type SecureSession,
} from "./session.js";

export interface CommandTaskContext {
  readonly taskId: string;
  readonly workspaceIds: ReadonlyArray<string>;
}

function commandRefusal(
  session: SecureSession,
  reason: string,
  auditPersisted: boolean,
): DurableResult {
  return {
    outcome: { status: "refused", stage: "command", reason },
    auditPersisted,
    log: session.log,
  };
}

function persistOne(
  session: SecureSession,
  type: string,
  detail: string,
): boolean {
  const r = appendAuditEvent(session.sink, {
    type,
    detail,
    epoch: session.epoch,
    sleep: session.sleep,
  });
  if (!r.ok) {
    session.auditHealthy = false;
    return false;
  }
  return true;
}

/** Relative, no `..`, no backslash, no absolute. Reused for cwd. */
function isCleanRelative(value: string): boolean {
  if (value.length === 0 || value.startsWith("/") || value.includes("\\") || value.includes("\0")) {
    return false;
  }
  return !value.split("/").includes("..");
}

export interface CommandRouter {
  tryRoute(output: unknown, taskId: string): DurableResult | Promise<DurableResult> | undefined;
}

/**
 * Router for the conversation composite: claims ONLY outputs shaped
 * `{operation: "command-exec", ...}`. Everything else falls through
 * (workspace router, then M5). Async: execution takes real time.
 */
export function createCommandRouter(
  session: SecureSession,
  wsRegistry: WorkspaceRegistry,
  workspaceIds: ReadonlyArray<string>,
): CommandRouter {
  return {
    tryRoute(output: unknown, taskId: string): Promise<DurableResult> | undefined {
      if (
        typeof output !== "object" ||
        output === null ||
        (output as { operation?: unknown }).operation !== "command-exec"
      ) {
        return undefined;
      }
      return handleCommandProposal(session, { taskId, workspaceIds }, wsRegistry, output);
    },
  };
}

export async function handleCommandProposal(
  session: SecureSession,
  taskCtx: CommandTaskContext,
  wsRegistry: WorkspaceRegistry,
  output: unknown,
): Promise<DurableResult> {
  if (!session.auditHealthy) {
    return commandRefusal(session, "audit persistence unhealthy", false);
  }
  const parsed = CommandProposalSchema.safeParse(output);
  if (!parsed.success) {
    const ok = persistOne(session, "request.validation-failed", "command proposal failed strict validation");
    return commandRefusal(session, "command proposal failed strict validation", ok);
  }
  const proposal = parsed.data;
  if (!taskCtx.workspaceIds.includes(proposal.workspaceId)) {
    const ok = persistOne(session, "request.validation-failed", "command workspace not bound to task");
    return commandRefusal(session, "workspace not bound to task", ok);
  }
  const reverified = reverifyWorkspace(wsRegistry, proposal.workspaceId);
  if (!reverified.ok) {
    const ok = persistOne(session, "request.validation-failed", `command workspace unsafe: ${reverified.reason}`);
    return commandRefusal(session, `workspace unsafe: ${reverified.reason}`, ok);
  }
  const root = reverified.root;

  // Tier3/unknown die at the classifier — before M2, before any
  // confirmation lookup. Forged approvals cannot revive them.
  const classification = classify(proposal.commandId);
  if (classification.kind !== "allowed") {
    const ok = persistOne(
      session,
      "authorization.denied",
      classification.kind === "tier3" ? classification.reason : `unknown command "${proposal.commandId}"`,
    );
    return commandRefusal(
      session,
      classification.kind === "tier3" ? classification.reason : `unknown command "${proposal.commandId}": default deny`,
      ok,
    );
  }
  const def = classification.definition;

  const cwdRel = proposal.cwd ?? ".";
  if (!isCleanRelative(cwdRel)) {
    const ok = persistOne(session, "request.validation-failed", "command cwd rejected");
    return commandRefusal(session, "invalid cwd", ok);
  }
  const cwdResolved = resolveWithinRoot(root, path.join(root, cwdRel));
  if (!cwdResolved.ok) {
    const ok = persistOne(session, "request.validation-failed", `command cwd refused: ${cwdResolved.reason}`);
    return commandRefusal(session, `cwd refused: ${cwdResolved.reason}`, ok);
  }
  try {
    if (!fs.statSync(cwdResolved.resolved.real).isDirectory()) {
      const ok = persistOne(session, "request.validation-failed", "command cwd is not a directory");
      return commandRefusal(session, "cwd is not a directory", ok);
    }
  } catch {
    const ok = persistOne(session, "request.validation-failed", "command cwd not accessible");
    return commandRefusal(session, "cwd not accessible", ok);
  }

  const argvChecked = validateArgv(def, proposal.argv ?? []);
  if (!argvChecked.ok) {
    const ok = persistOne(session, "request.validation-failed", `command argv refused: ${argvChecked.reason}`);
    return commandRefusal(session, `argv refused: ${argvChecked.reason}`, ok);
  }

  if (isEngaged(session.killSwitch)) {
    const ok = persistOne(session, "execution.rejected", "command refused: kill switch engaged");
    return commandRefusal(session, "kill switch engaged", ok);
  }
  if (session.sleep !== "AWAKE") {
    const ok = persistOne(session, "sleep.denied", "command refused while asleep");
    return commandRefusal(session, "system is asleep", ok);
  }
  if (!tryAcquireCommandSlot()) {
    const ok = persistOne(session, "execution.rejected", "command refused: another command in flight");
    return commandRefusal(session, "another command is already running", ok);
  }
  try {
    // THE authorization decision — M2, sole authority. Tier2 records
    // in the trusted store satisfy it here; Tier3 never arrives.
    const before = session.log.events.length;
    const authorized = authorize(
      { capability: def.capability, operation: "run", resource: root, taskId: taskCtx.taskId },
      { sleep: session.sleep, grants: session.grants, confirmations: session.confirmations, log: session.log },
    );
    session.log = authorized.log;
    const persistedAuth = persistLogDelta(session, before);
    if (authorized.decision.verdict !== "allow") {
      return commandRefusal(session, `authorization did not allow (got ${authorized.decision.verdict})`, persistedAuth);
    }
    // Re-check at the OS boundary (mirrors M3): nothing cached across
    // a security change, even within this call.
    if (isEngaged(session.killSwitch) || session.sleep !== "AWAKE") {
      const ok = persistOne(session, "execution.rejected", "command stopped at execution boundary");
      return commandRefusal(session, "stopped at execution boundary", ok);
    }
    const startedOk = persistOne(
      session,
      "execution.started",
      `started ${def.id} task=${taskCtx.taskId} ws=${proposal.workspaceId} cwd=${cwdRel} tier=${def.riskTier} argv=${argvChecked.argv.length}`,
    );
    if (!startedOk) {
      return commandRefusal(session, "audit unhealthy: execution refused before spawn", false);
    }
    const raw = await runSpawned(def, argvChecked.argv, cwdResolved.resolved.real);
    const validated = CommandResultSchema.safeParse(raw);
    const result: CommandResult = validated.success
      ? validated.data
      : { v: 1, status: "failed", stdout: "", stderr: "", stdoutTruncated: false, stderrTruncated: false, durationMs: 0 };
    if (result.status === "timed-out") {
      persistOne(
        session,
        "command.timed-out",
        `${def.id} timed out signal=${result.signal ?? "?"} out=${result.stdout.length}B`,
      );
      return {
        outcome: { status: "failed", stage: "adapter", reason: "command timed out" },
        auditPersisted: session.auditHealthy,
        log: session.log,
      };
    }
    if (result.status === "failed") {
      persistOne(session, "execution.failed", `${def.id} adapter failure`);
      return {
        outcome: { status: "failed", stage: "adapter", reason: "command adapter failure" },
        auditPersisted: session.auditHealthy,
        log: session.log,
      };
    }
    persistOne(
      session,
      "execution.completed",
      `${def.id} exit=${result.exitCode ?? "?"} out=${result.stdout.length}B err=${result.stderr.length}B ms=${result.durationMs}`,
    );
    return {
      outcome: { status: "completed", operation: `${def.capability}:run`, result, redacted: false },
      auditPersisted: session.auditHealthy,
      log: session.log,
    };
  } finally {
    releaseCommandSlot();
  }
}
