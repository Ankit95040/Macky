/**
 * The single trust boundary between planner output and execution
 * (M5 section 3). Exactly one path exists:
 *
 *   planner output (unknown)
 *     → strict proposal validation (forbidden fields rejected, never stripped)
 *     → trusted translation to an M2 ActionRequest
 *        (planner rationale/metadata DROPPED here — data, never instructions;
 *         taskId taken from the trusted envelope, never the proposal)
 *     → existing M2 authorization (no second system, no registry copy)
 *     → existing M3 executor via M4 runDurable (epoch-bound, audited)
 *
 * The kernel derives every security property itself: risk tier from
 * the M2 registry, grants from the trusted session, confirmation from
 * the trusted store, sleep/kill/epoch from the session. Planner
 * metadata cannot influence any of it — translation forwards ONLY
 * (capability, operation, resource, taskId, requestId).
 */
import { z } from "zod";
import { appendAuditEvent } from "../persistence/audit-store.js";
import {
  runDurable,
  type DurableResult,
  type SecureSession,
} from "../persistence/session.js";
import {
  UntrustedProposalSchema,
  type UntrustedProposal,
} from "./proposal.js";

/** Trusted translation: (family, operation) → M2 capability. Closed map. */
const TRANSLATION: Record<string, Record<string, string>> = {
  // M7 workspace intelligence maps onto read-only filesystem
  // capabilities (documented in M7_WORKSPACE.md §13). No new trust:
  // the same M2 registry + M3 adapters authorize and enforce.
  filesystem: {
    read: "filesystem.read",
    list: "filesystem.read",
    find: "filesystem.find",
    search: "filesystem.search",
    tree: "filesystem.tree",
  },
  git: { status: "git.read", log: "git.read", diff: "git.read" },
  system: { info: "system.info" },
};

const ProposalEnvelopeSchema = z
  .object({
    epoch: z.number().int().min(1),
    /** Trusted task binding: assigned by the app, never by the planner. */
    taskId: z.string().min(1).max(128).regex(/^[a-z0-9][a-z0-9._-]{0,127}$/i),
    output: z.unknown(),
  })
  .strict();

export interface ProposalEnvelope {
  readonly epoch: number;
  readonly taskId: string;
  readonly output: unknown;
}

function boundaryRefusal(
  session: SecureSession,
  reason: string,
): DurableResult {
  const persisted = appendAuditEvent(session.sink, {
    type: "request.validation-failed",
    detail: `planner proposal rejected at boundary: ${reason}`,
    epoch: session.epoch,
    sleep: session.sleep,
  });
  if (!persisted.ok) {
    session.auditHealthy = false;
  }
  return {
    outcome: { status: "refused", stage: "proposal", reason },
    auditPersisted: persisted.ok,
    log: session.log,
  };
}

/**
 * Handle one untrusted planner output inside a live session.
 * Always returns a refusal unless the full M2→M3→M4 chain allows.
 */
export function handleProposal(
  session: SecureSession,
  envelope: unknown,
): DurableResult {
  const envParsed = ProposalEnvelopeSchema.safeParse(envelope);
  if (!envParsed.success) {
    return boundaryRefusal(session, "malformed proposal envelope");
  }
  const proposalParsed = UntrustedProposalSchema.safeParse(envParsed.data.output);
  if (!proposalParsed.success) {
    return boundaryRefusal(session, "proposal failed strict validation");
  }
  const proposal: UntrustedProposal = proposalParsed.data;
  // Trusted task binding: the planner's claimed taskId must equal the
  // app-assigned envelope taskId. A mismatch (e.g. claiming another
  // task's authority) is refused — the planner never chooses context.
  if (proposal.taskId !== envParsed.data.taskId) {
    return boundaryRefusal(session, "task binding mismatch");
  }
  const capability = TRANSLATION[proposal.family]?.[proposal.operation];
  if (capability === undefined) {
    return boundaryRefusal(
      session,
      `untranslatable family/operation "${proposal.family}:${proposal.operation}"`,
    );
  }
  // Rationale is intentionally NOT forwarded: prompt-injection text in
  // metadata dies here and can never reach authorization or audit.
  // taskId comes from the trusted envelope, never the proposal.
  // params (M7) pass through opaquely; M2 schemas bound them and each
  // adapter accepts exactly its own keys.
  const request = {
    capability,
    operation: proposal.operation,
    ...(proposal.resource !== undefined ? { resource: proposal.resource } : {}),
    taskId: envParsed.data.taskId,
    ...(proposal.requestId !== undefined ? { requestId: proposal.requestId } : {}),
    ...(proposal.params !== undefined ? { params: proposal.params } : {}),
  };
  return runDurable(session, { epoch: envParsed.data.epoch, request });
}
