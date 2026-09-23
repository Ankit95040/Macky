/**
 * Trusted workspace service (M7 sections 1/3/4/5/14/15). Contextual
 * NARROWING, never permission escalation: the planner names a
 * registered workspaceId + relative target, this layer resolves to an
 * absolute path, then delegates to the EXISTING M5 boundary (hence
 * M2 authorization of the absolute resource against live grants, M3
 * final enforcement, M4 durable audit). Completed filesystem results
 * are wrapped into versioned contracts with workspace-relative paths.
 */
import * as path from "node:path";
import { appendAuditEvent } from "../persistence/audit-store.js";
import {
  type DurableResult,
  type SecureSession,
} from "../persistence/session.js";
import { handleProposal } from "../planner/boundary.js";
import { PLANNER_CONTRACT_VERSION } from "../planner/proposal.js";
import {
  ContentSearchResultSchema,
  DirectoryListingResultSchema,
  FileReadResultSchema,
  FileSearchResultSchema,
  TreeResultSchema,
} from "./results.js";
import {
  validateRelativePath,
  WorkspaceProposalSchema,
  type WorkspaceOperation,
} from "./proposals.js";
import { reverifyWorkspace, type WorkspaceRegistry } from "./registry.js";

export interface TaskWorkspaceContext {
  readonly taskId: string;
  readonly workspaceIds: ReadonlyArray<string>;
}

export interface WorkspaceProposalRouter {
  tryRoute(output: unknown, taskId: string): DurableResult | undefined;
}

/**
 * Router for the M6 orchestrator's `proposalRouter` hook. Claims ONLY
 * outputs matching the M7 workspace shape (bound to one of the trusted
 * workspaceIds); everything else returns undefined so the exact M5
 * path runs. The taskId comes from the orchestrator's trusted call —
 * never from the proposal.
 */
export function createWorkspaceRouter(
  session: SecureSession,
  registry: WorkspaceRegistry,
  workspaceIds: ReadonlyArray<string>,
): WorkspaceProposalRouter {
  return {
    tryRoute(output: unknown, taskId: string): DurableResult | undefined {
      if (
        typeof output !== "object" ||
        output === null ||
        (output as { workspaceId?: unknown }).workspaceId === undefined
      ) {
        return undefined;
      }
      return handleWorkspaceProposal(session, { taskId, workspaceIds }, registry, output);
    },
  };
}

const OP_MAP: Record<WorkspaceOperation, { family: string; operation: string }> = {
  "file-read": { family: "filesystem", operation: "read" },
  "dir-list": { family: "filesystem", operation: "list" },
  "file-find": { family: "filesystem", operation: "find" },
  "content-search": { family: "filesystem", operation: "search" },
  tree: { family: "filesystem", operation: "tree" },
  "git-status": { family: "git", operation: "status" },
  "git-log": { family: "git", operation: "log" },
  "git-diff": { family: "git", operation: "diff" },
};

function workspaceRefusal(session: SecureSession, reason: string): DurableResult {
  const persisted = appendAuditEvent(session.sink, {
    type: "request.validation-failed",
    detail: `workspace proposal rejected: ${reason}`,
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

/** Absolute → workspace-relative. Undefined on any escape (defensive). */
function toRelative(root: string, absolute: string): string | undefined {
  const rel = path.relative(root, absolute);
  if (rel === "" ) {
    return ".";
  }
  if (rel.startsWith("..") || path.isAbsolute(rel)) {
    return undefined;
  }
  return rel;
}

export function handleWorkspaceProposal(
  session: SecureSession,
  taskCtx: TaskWorkspaceContext,
  registry: WorkspaceRegistry,
  output: unknown,
): DurableResult {
  const parsed = WorkspaceProposalSchema.safeParse(output);
  if (!parsed.success) {
    return workspaceRefusal(session, "proposal failed strict validation");
  }
  const proposal = parsed.data;
  // Binding: the id must be BOTH registered AND in the trusted task
  // context. A planner-claimed id outside the binding dies here.
  if (!taskCtx.workspaceIds.includes(proposal.workspaceId)) {
    return workspaceRefusal(session, "workspace not bound to task");
  }
  const reverified = reverifyWorkspace(registry, proposal.workspaceId);
  if (!reverified.ok) {
    return workspaceRefusal(session, `workspace unsafe: ${reverified.reason}`);
  }
  const root = reverified.root;
  const rel = validateRelativePath(proposal.path);
  if (rel === undefined) {
    return workspaceRefusal(session, "invalid relative path");
  }
  // Op-appropriate fields only: pattern/query are refused anywhere
  // they do not belong (no smuggled parameters).
  const wantsPattern = proposal.op === "file-find";
  const wantsQuery = proposal.op === "content-search";
  if (wantsPattern !== (proposal.pattern !== undefined)) {
    return workspaceRefusal(session, "pattern field mismatch for operation");
  }
  if (wantsQuery !== (proposal.query !== undefined)) {
    return workspaceRefusal(session, "query field mismatch for operation");
  }
  const mapped = OP_MAP[proposal.op];
  const absolute = path.join(root, rel);
  const m5proposal: Record<string, unknown> = {
    plannerVersion: PLANNER_CONTRACT_VERSION,
    taskId: taskCtx.taskId,
    family: mapped.family,
    operation: mapped.operation,
    resource: absolute,
  };
  if (proposal.pattern !== undefined) {
    m5proposal["params"] = { pattern: proposal.pattern };
  }
  if (proposal.query !== undefined) {
    m5proposal["params"] = { query: proposal.query };
  }
  const result = handleProposal(
    session,
    { epoch: session.epoch, taskId: taskCtx.taskId, output: m5proposal },
  );
  if (result.outcome.status !== "completed") {
    return result;
  }
  return wrapCompleted(proposal.workspaceId, rel, proposal.op, root, proposal.pattern, result);
}

function wrapCompleted(
  workspaceId: string,
  rel: string,
  op: WorkspaceOperation,
  root: string,
  pattern: string | undefined,
  result: DurableResult,
): DurableResult {
  const outcome = result.outcome;
  if (outcome.status !== "completed") {
    return result;
  }
  const contract = buildContract(workspaceId, rel, op, outcome.result, outcome.redacted, root, pattern);
  if (contract === undefined) {
    return {
      outcome: { status: "refused", stage: "adapter", reason: "result contract failed" },
      auditPersisted: result.auditPersisted,
      log: result.log,
    };
  }
  return {
    outcome: { status: "completed", operation: outcome.operation, result: contract, redacted: outcome.redacted },
    auditPersisted: result.auditPersisted,
    log: result.log,
  };
}

function buildContract(
  workspaceId: string,
  rel: string,
  op: WorkspaceOperation,
  value: unknown,
  redacted: boolean,
  root: string,
  pattern: string | undefined,
): unknown {
  const v = 1 as const;
  if (op === "dir-list" && Array.isArray(value)) {
    const parsed = DirectoryListingResultSchema.safeParse({
      v, workspaceId, path: rel, entries: value, truncated: false,
    });
    return parsed.success ? parsed.data : undefined;
  }
  if (op === "file-read" && typeof value === "string") {
    const parsed = FileReadResultSchema.safeParse({
      v, workspaceId, path: rel, content: value, redacted, truncated: false,
    });
    return parsed.success ? parsed.data : undefined;
  }
  if (op === "file-find" && typeof value === "object" && value !== null) {
    const raw = value as { entries?: Array<{ path: string; kind: string }>; pruned?: number; truncated?: boolean };
    const entries: Array<{ path: string; kind: string }> = [];
    for (const e of raw.entries ?? []) {
      const mapped = toRelative(root, e.path);
      if (mapped !== undefined) {
        entries.push({ path: mapped, kind: e.kind });
      }
    }
    const parsed = FileSearchResultSchema.safeParse({
      v, workspaceId, path: rel, pattern: pattern ?? "", entries, pruned: raw.pruned ?? 0, truncated: raw.truncated ?? false,
    });
    return parsed.success ? parsed.data : undefined;
  }
  if (op === "content-search" && typeof value === "object" && value !== null) {
    const raw = value as { matches?: Array<{ path: string; line: number; context: string }>; pruned?: number; truncated?: boolean };
    const matches: Array<{ path: string; line: number; context: string }> = [];
    for (const m of raw.matches ?? []) {
      const mapped = toRelative(root, m.path);
      if (mapped !== undefined) {
        matches.push({ path: mapped, line: m.line, context: m.context });
      }
    }
    const parsed = ContentSearchResultSchema.safeParse({
      v, workspaceId, path: rel, matches, pruned: raw.pruned ?? 0, truncated: raw.truncated ?? false,
    });
    return parsed.success ? parsed.data : undefined;
  }
  if (op === "tree" && typeof value === "object" && value !== null) {
    const raw = value as { nodes?: unknown; pruned?: number; truncated?: boolean };
    const parsed = TreeResultSchema.safeParse({
      v, workspaceId, path: rel, nodes: raw.nodes ?? [], pruned: raw.pruned ?? 0, truncated: raw.truncated ?? false,
    });
    return parsed.success ? parsed.data : undefined;
  }
  // Git operations pass through with existing M3 shapes (bounded upstream).
  if (op === "git-status" || op === "git-log" || op === "git-diff") {
    return value;
  }
  return undefined;
}
