/**
 * Trusted speech service (M13 flow). Strict proposal validation →
 * text validation (length, shared shell-char set, leading dash,
 * secret screen) → kill/sleep prechecks → single-flight slot → M2
 * authorize() (SOLE authority; Tier2 speech.announce against live
 * task grants) → TEXT-BOUND confirmation (SHA-256 digest of the exact
 * validated text must match a trusted record — a generic confirmation
 * is never sufficient) → spawn-boundary re-check → fixed
 * /usr/bin/say with argv [text] → bounded contract → metadata audit.
 *
 * M8 isolation (§4 HARD GATE): this service never touches M8's
 * registry, classifier, or command vocabulary. The M8-typed constant
 * below exists ONLY to reuse runSpawned's spawn mechanics (timeout,
 * caps, unicode); M8's service can never resolve 'speech.announce'
 * (absent from its registry → unknown → refused), and this service
 * can never resolve M8 commandIds (it takes none). One execution
 * path: this function → runSpawned → say. No workspace coupling:
 * speech has no cwd semantics (process.cwd() passed, ignored).
 */
import { createHash } from "node:crypto";
import { authorize } from "../kernel/authorize.js";
import { hasDigestConfirmation } from "../kernel/confirm.js";
import { isEngaged } from "../kernel/kill-switch.js";
import { appendAuditEvent } from "../persistence/audit-store.js";
import {
  persistLogDelta,
  type DurableResult,
  type SecureSession,
} from "../persistence/session.js";
import { containsForbiddenShellChar } from "../commands/proposal.js";
import { containsSecretLike } from "../memory/service.js";
import {
  releaseCommandSlot,
  runSpawned,
  tryAcquireCommandSlot,
  type SpawnFn,
} from "../commands/runner.js";
import type { CommandDefinition } from "../commands/registry.js";
import { SPEECH_LIMITS } from "./limits.js";
import { SpeechProposalSchema } from "./proposal.js";
import { SpeechResultSchema } from "./results.js";

export const SPEECH_EXECUTABLE = "/usr/bin/say" as const;

/**
 * Spawn-mechanics-only definition for runSpawned reuse. NOT
 * registered anywhere M8 can see; carries no authority by itself —
 * authority comes from M2 + digest confirmation checked below.
 */
const SPEECH_SPAWN_DEF: CommandDefinition = Object.freeze({
  id: "speech.announce",
  executable: SPEECH_EXECUTABLE,
  argStyle: "text",
  capability: "speech.announce",
  riskTier: 2,
  requiresConfirmation: true,
  description: "Fixed say with one validated text operand (M13 mechanics-only).",
});

export interface SpeechTaskContext {
  readonly taskId: string;
}

export interface SpeechServiceOptions {
  readonly spawnImpl?: SpawnFn;
  readonly timeoutMs?: number;
}

/** Trusted SHA-256 hex digest of exact validated text. Never planner-supplied. */
export function speechTextDigest(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function speechRefusal(
  session: SecureSession,
  reason: string,
  auditPersisted: boolean,
): DurableResult {
  return {
    outcome: { status: "refused", stage: "speech", reason },
    auditPersisted,
    log: session.log,
  };
}

function persistOne(session: SecureSession, type: string, detail: string): boolean {
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

export interface SpeechRouter {
  tryRoute(output: unknown, taskId: string): Promise<DurableResult> | undefined;
}

/** Claims ONLY speech-announce outputs; all else falls through. */
export function createSpeechRouter(
  session: SecureSession,
  opts?: SpeechServiceOptions,
): SpeechRouter {
  return {
    tryRoute(output: unknown, taskId: string): Promise<DurableResult> | undefined {
      if (typeof output !== "object" || output === null) {
        return undefined;
      }
      if ((output as { operation?: unknown }).operation !== "speech-announce") {
        return undefined;
      }
      return handleSpeechProposal(session, { taskId }, output, opts);
    },
  };
}

export async function handleSpeechProposal(
  session: SecureSession,
  taskCtx: SpeechTaskContext,
  output: unknown,
  opts?: SpeechServiceOptions,
): Promise<DurableResult> {
  if (!session.auditHealthy) {
    return speechRefusal(session, "audit persistence unhealthy", false);
  }
  const parsed = SpeechProposalSchema.safeParse(output);
  if (!parsed.success) {
    const ok = persistOne(session, "request.validation-failed", "speech proposal failed strict validation");
    return speechRefusal(session, "speech proposal failed strict validation", ok);
  }
  const text = parsed.data.text;
  // Text validation BEFORE authorization/execution. Full M8 shell-char
  // set (conservative: '/' has no path meaning here but stays refused
  // so the surface cannot drift weaker), leading dash (option
  // injection into say: "-f file" would read a file), secret screen.
  if (containsForbiddenShellChar(text)) {
    const ok = persistOne(session, "request.validation-failed", "speech text rejected: unsafe characters");
    return speechRefusal(session, "text rejected: unsafe characters", ok);
  }
  if (text.startsWith("-")) {
    const ok = persistOne(session, "request.validation-failed", "speech text rejected: option shape");
    return speechRefusal(session, "text rejected: option shape", ok);
  }
  if (containsSecretLike(text)) {
    const ok = persistOne(session, "request.validation-failed", "speech text refused: secret-like content");
    return speechRefusal(session, "secret-like content refused", ok);
  }
  if (isEngaged(session.killSwitch)) {
    const ok = persistOne(session, "execution.rejected", "speech refused: kill switch engaged");
    return speechRefusal(session, "kill switch engaged", ok);
  }
  if (session.sleep !== "AWAKE") {
    const ok = persistOne(session, "sleep.denied", "speech refused while asleep");
    return speechRefusal(session, "system is asleep", ok);
  }
  // Shared single-flight discipline with command execution: at most
  // one spawned child per process across M8/M13 (documented).
  if (!tryAcquireCommandSlot()) {
    const ok = persistOne(session, "execution.rejected", "speech refused: another operation in flight");
    return speechRefusal(session, "another operation is already running", ok);
  }
  try {
    // THE authorization decision — M2, sole authority. Tier2 flag
    // yields allow (generic confirmation present) or
    // require-confirmation; BOTH still need the digest check below.
    const before = session.log.events.length;
    const authorized = authorize(
      { capability: "speech.announce", operation: "announce", taskId: taskCtx.taskId },
      { sleep: session.sleep, grants: session.grants, confirmations: session.confirmations, log: session.log },
    );
    session.log = authorized.log;
    const persistedAuth = persistLogDelta(session, before);
    if (authorized.decision.verdict === "deny") {
      return speechRefusal(session, "authorization denied", persistedAuth);
    }
    // TEXT-BOUND confirmation (§6): the digest of the EXACT validated
    // text must match a trusted record for this task+capability+op.
    // A generic (digest-less) confirmation that satisfied M2 above is
    // NOT sufficient — without this, approval of text A would authorize
    // speaking text B. One changed byte requires a new confirmation.
    const digest = speechTextDigest(text);
    const confirmed = hasDigestConfirmation(session.confirmations, {
      taskId: taskCtx.taskId,
      capability: "speech.announce",
      operation: "announce",
      resource: "",
      digest,
    });
    if (!confirmed) {
      const ok = persistOne(session, "confirmation.required", "speech needs exact text confirmation");
      void ok;
      return speechRefusal(session, "explicit text-bound confirmation required", persistedAuth);
    }
    if (isEngaged(session.killSwitch) || session.sleep !== "AWAKE") {
      const ok = persistOne(session, "execution.rejected", "speech stopped at spawn boundary");
      return speechRefusal(session, "stopped at spawn boundary", ok);
    }
    const startedOk = persistOne(
      session,
      "execution.started",
      `started speech.announce tier=2 digest=${digest} chars=${Array.from(text).length}`,
    );
    if (!startedOk) {
      return speechRefusal(session, "audit unhealthy: refused before spawn", false);
    }
    // Exactly ONE argv element. No voice, volume, file, URL, or other
    // flags can exist — argv shape is code, not data.
    const runOpts = opts?.spawnImpl !== undefined || opts?.timeoutMs !== undefined
      ? {
          ...(opts.spawnImpl !== undefined ? { spawnImpl: opts.spawnImpl } : {}),
          ...(opts.timeoutMs !== undefined ? { timeoutMs: opts.timeoutMs } : {}),
        }
      : undefined;
    const raw = await runSpawned(SPEECH_SPAWN_DEF, [text], process.cwd(), runOpts);
    if (raw.status === "timed-out") {
      persistOne(session, "command.timed-out", `speech.announce timeout digest=${digest}`);
      return {
        outcome: { status: "failed", stage: "adapter", reason: "speech timeout" },
        auditPersisted: session.auditHealthy,
        log: session.log,
      };
    }
    if (raw.status !== "completed") {
      persistOne(session, "execution.failed", `speech.announce adapter failure digest=${digest}`);
      return {
        outcome: { status: "failed", stage: "adapter", reason: "speech adapter failure" },
        auditPersisted: session.auditHealthy,
        log: session.log,
      };
    }
    const contract = SpeechResultSchema.safeParse({
      v: 1, operation: "speech-announce", status: "announced", truncated: false,
    });
    if (!contract.success) {
      persistOne(session, "execution.failed", "speech result contract failed");
      return {
        outcome: { status: "failed", stage: "adapter", reason: "result contract failed" },
        auditPersisted: session.auditHealthy,
        log: session.log,
      };
    }
    persistOne(
      session,
      "execution.completed",
      `speech.announce ok digest=${digest} chars=${Array.from(text).length} ms=${raw.durationMs}`,
    );
    return {
      outcome: { status: "completed", operation: "speech.announce:announce", result: contract.data, redacted: false },
      auditPersisted: session.auditHealthy,
      log: session.log,
    };
  } finally {
    releaseCommandSlot();
  }
}
