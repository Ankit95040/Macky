/**
 * Trusted memory service (M10 flow). Strict proposal validation →
 * trusted registry classification (Tier1 only) → kill/sleep
 * prechecks → single-flight slot → M2 authorize() (SOLE authority;
 * unscoped memory caps against live task grants) → operation with
 * trusted metadata → atomic durable commit → bounded contract →
 * metadata-only audit.
 *
 * Memory is INFORMATION ONLY. Records, queries, and retrieved text
 * never enter authorization, grants, policy, or state. Writes are
 * create-only (no overwrite, no dedup, no inference); content stored
 * exactly as supplied once validated. The service exposes no
 * execute(decision) equivalent — authorization is re-checked inside
 * this call immediately before every mutation.
 */
import { authorize } from "../kernel/authorize.js";
import { isEngaged } from "../kernel/kill-switch.js";
import { appendAuditEvent } from "../persistence/audit-store.js";
import {
  persistLogDelta,
  type DurableResult,
  type SecureSession,
} from "../persistence/session.js";
import { MEMORY_LIMITS } from "./limits.js";
import {
  MemoryDeleteProposalSchema,
  MemoryReadProposalSchema,
  MemoryWriteProposalSchema,
} from "./proposal.js";
import { classifyMemoryOperation } from "./registry.js";
import {
  MemoryDeleteResultSchema,
  MemoryReadResultSchema,
  MemoryWriteResultSchema,
} from "./results.js";
import {
  mintMemoryId,
  saveMemoryStore,
  trustedNow,
  type MemoryRecord,
  type MemoryStore,
} from "./store.js";

export interface MemoryTaskContext {
  readonly taskId: string;
}

let memoryInFlight = 0;

export function tryAcquireMemorySlot(): boolean {
  if (memoryInFlight >= 1) {
    return false;
  }
  memoryInFlight += 1;
  return true;
}

export function releaseMemorySlot(): void {
  memoryInFlight = Math.max(0, memoryInFlight - 1);
}

/**
 * Heuristic secret screen (defense ONLY — documented as imperfect).
 * The real boundary is that content never becomes authority, even
 * when this check misses. Same pattern families as audit redaction.
 */
export function containsSecretLike(content: string): boolean {
  if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(content)) {
    return true;
  }
  return /(api[_-]?key|secret|token|private[_-]?key|auth[_-]?token|password|passwd)\s*[:=]\s*\S+/i.test(content);
}

function memoryRefusal(
  session: SecureSession,
  reason: string,
  auditPersisted: boolean,
): DurableResult {
  return {
    outcome: { status: "refused", stage: "memory", reason },
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

export interface MemoryRouter {
  tryRoute(output: unknown, taskId: string): DurableResult | undefined;
}

/** Claims ONLY memory-read/write/delete outputs; all else falls through. */
export function createMemoryRouter(
  session: SecureSession,
  store: MemoryStore,
): MemoryRouter {
  return {
    tryRoute(output: unknown, taskId: string): DurableResult | undefined {
      if (typeof output !== "object" || output === null) {
        return undefined;
      }
      const op = (output as { operation?: unknown }).operation;
      if (op !== "memory-read" && op !== "memory-write" && op !== "memory-delete") {
        return undefined;
      }
      return handleMemoryProposal(session, { taskId }, store, output);
    },
  };
}

function normalizeForSearch(text: string): string {
  return text.toLowerCase().replace(/\s+/g, " ");
}

export function handleMemoryProposal(
  session: SecureSession,
  taskCtx: MemoryTaskContext,
  store: MemoryStore,
  output: unknown,
): DurableResult {
  if (!session.auditHealthy) {
    return memoryRefusal(session, "audit persistence unhealthy", false);
  }
  const asRead = MemoryReadProposalSchema.safeParse(output);
  if (asRead.success) {
    const readInput: { query: string; maxResults?: number } =
      asRead.data.maxResults === undefined
        ? { query: asRead.data.query }
        : { query: asRead.data.query, maxResults: asRead.data.maxResults };
    return dispatchMemory(session, taskCtx, store, "memory-read", { read: readInput });
  }
  const asWrite = MemoryWriteProposalSchema.safeParse(output);
  if (asWrite.success) {
    return dispatchMemory(session, taskCtx, store, "memory-write", { write: asWrite.data });
  }
  const asDelete = MemoryDeleteProposalSchema.safeParse(output);
  if (!asDelete.success) {
    const ok = persistOne(session, "request.validation-failed", "memory proposal failed strict validation");
    return memoryRefusal(session, "memory proposal failed strict validation", ok);
  }
  return dispatchMemory(session, taskCtx, store, "memory-delete", { delete: asDelete.data });
}

function dispatchMemory(
  session: SecureSession,
  taskCtx: MemoryTaskContext,
  store: MemoryStore,
  operation: "memory-read" | "memory-write" | "memory-delete",
  proposal: {
    read?: { query: string; maxResults?: number };
    write?: { content: string; kind: "fact" | "preference" | "project" | "instruction" };
    delete?: { memoryId: string };
  },
): DurableResult {
  const def = classifyMemoryOperation(operation);
  if (def === undefined) {
    const ok = persistOne(session, "request.validation-failed", "unknown memory operation");
    return memoryRefusal(session, "unknown memory operation", ok);
  }
  if (isEngaged(session.killSwitch)) {
    const ok = persistOne(session, "execution.rejected", "memory refused: kill switch engaged");
    return memoryRefusal(session, "kill switch engaged", ok);
  }
  if (session.sleep !== "AWAKE") {
    const ok = persistOne(session, "sleep.denied", "memory refused while asleep");
    return memoryRefusal(session, "system is asleep", ok);
  }
  if (!tryAcquireMemorySlot()) {
    const ok = persistOne(session, "execution.rejected", "memory refused: another operation in flight");
    return memoryRefusal(session, "another memory operation is already running", ok);
  }
  try {
    // THE authorization decision — M2, sole authority. M2 operations
    // are "read"/"write"/"delete" (registry-declared); the "memory-"
    // prefixed names are M10 proposal vocabulary only.
    const m2Operation = operation === "memory-read" ? "read" : operation === "memory-write" ? "write" : "delete";
    const before = session.log.events.length;
    const authorized = authorize(
      { capability: def.capability, operation: m2Operation, taskId: taskCtx.taskId },
      { sleep: session.sleep, grants: session.grants, confirmations: session.confirmations, log: session.log },
    );
    session.log = authorized.log;
    const persistedAuth = persistLogDelta(session, before);
    if (authorized.decision.verdict !== "allow") {
      return memoryRefusal(session, `authorization did not allow (got ${authorized.decision.verdict})`, persistedAuth);
    }
    if (isEngaged(session.killSwitch) || session.sleep !== "AWAKE") {
      const ok = persistOne(session, "execution.rejected", "memory stopped at operation boundary");
      return memoryRefusal(session, "stopped at operation boundary", ok);
    }
    // M2 operations coincide with the dispatched handlers below.
    if (proposal.read !== undefined) {
      return runRead(session, store, proposal.read.query, proposal.read.maxResults ?? MEMORY_LIMITS.MAX_RESULTS);
    }
    if (proposal.write !== undefined) {
      return runWrite(session, taskCtx, store, proposal.write.content, proposal.write.kind);
    }
    const memoryId = proposal.delete?.memoryId;
    if (memoryId === undefined) {
      const ok = persistOne(session, "request.validation-failed", "memory-delete unparseable");
      return memoryRefusal(session, "memory-delete unparseable", ok);
    }
    return runDelete(session, store, memoryId);
  } finally {
    releaseMemorySlot();
  }
}

function toView(record: MemoryRecord): {
  id: string;
  kind: "fact" | "preference" | "project" | "instruction";
  content: string;
  createdAt: string;
  taskId: string;
} {
  return {
    id: record.id,
    kind: record.kind,
    content: record.content,
    createdAt: record.createdAt,
    taskId: record.taskId,
  };
}

function runRead(
  session: SecureSession,
  store: MemoryStore,
  query: string,
  maxResults: number,
): DurableResult {
  const startedOk = persistOne(session, "execution.started", "started memory.read tier=1");
  if (!startedOk) {
    return memoryRefusal(session, "audit unhealthy: refused before read", false);
  }
  const needle = normalizeForSearch(query);
  const matched = store.records.filter((r) => normalizeForSearch(r.content).includes(needle));
  let truncated = matched.length > maxResults;
  let views = matched.slice(0, maxResults).map(toView);
  for (;;) {
    if (Buffer.byteLength(JSON.stringify(views), "utf8") <= MEMORY_LIMITS.MAX_RESULT_PAYLOAD_BYTES || views.length === 0) {
      break;
    }
    truncated = true;
    views = views.slice(0, views.length - 1);
  }
  const parsed = MemoryReadResultSchema.safeParse({ v: 1, records: views, truncated });
  if (!parsed.success) {
    persistOne(session, "execution.failed", "memory.read result contract failed");
    return {
      outcome: { status: "failed", stage: "adapter", reason: "result contract failed" },
      auditPersisted: session.auditHealthy,
      log: session.log,
    };
  }
  persistOne(session, "execution.completed", `memory.read ok count=${parsed.data.records.length} truncated=${truncated}`);
  return {
    outcome: { status: "completed", operation: "memory.read:read", result: parsed.data, redacted: false },
    auditPersisted: session.auditHealthy,
    log: session.log,
  };
}

function runWrite(
  session: SecureSession,
  taskCtx: MemoryTaskContext,
  store: MemoryStore,
  content: string,
  kind: "fact" | "preference" | "project" | "instruction",
): DurableResult {
  // Heuristic secret screen (defense only): obviously unsafe storage
  // classes are refused outright.
  if (containsSecretLike(content)) {
    const refused = persistOne(session, "request.validation-failed", "memory-write refused: secret-like content");
    return memoryRefusal(session, "secret-like content refused", refused);
  }
  const startedOk = persistOne(session, "execution.started", "started memory.write tier=1");
  if (!startedOk) {
    return memoryRefusal(session, "audit unhealthy: refused before write", false);
  }
  const now = trustedNow();
  const record: MemoryRecord = {
    v: 1,
    id: mintMemoryId(),
    content,
    kind,
    createdAt: now,
    updatedAt: now,
    source: "m10-proposal",
    taskId: taskCtx.taskId,
    epoch: session.epoch,
  };
  // Create-only: no overwrite path exists. Limits enforced inside
  // saveMemoryStore BEFORE disk is touched; in-memory state swaps
  // only on success, so failed writes mutate nothing.
  const saved = saveMemoryStore(store, [...store.records, record]);
  if (!saved.ok) {
    persistOne(session, "execution.failed", `memory.write failed: ${saved.reason}`);
    return {
      outcome: { status: "failed", stage: "adapter", reason: saved.reason },
      auditPersisted: session.auditHealthy,
      log: session.log,
    };
  }
  const parsed = MemoryWriteResultSchema.safeParse({ v: 1, id: record.id, kind: record.kind });
  if (!parsed.success) {
    persistOne(session, "execution.failed", "memory.write result contract failed");
    return {
      outcome: { status: "failed", stage: "adapter", reason: "result contract failed" },
      auditPersisted: session.auditHealthy,
      log: session.log,
    };
  }
  const bytes = Buffer.byteLength(content, "utf8");
  persistOne(session, "execution.completed", `memory.write ok id=${record.id} bytes=${bytes}`);
  return {
    outcome: { status: "completed", operation: "memory.write:write", result: parsed.data, redacted: false },
    auditPersisted: session.auditHealthy,
    log: session.log,
  };
}

function runDelete(session: SecureSession, store: MemoryStore, memoryId: string): DurableResult {
  const startedOk = persistOne(session, "execution.started", "started memory.delete tier=1");
  if (!startedOk) {
    return memoryRefusal(session, "audit unhealthy: refused before delete", false);
  }
  const index = store.records.findIndex((r) => r.id === memoryId);
  if (index === -1) {
    persistOne(session, "execution.rejected", "memory.delete unknown id");
    return memoryRefusal(session, "unknown memory id", session.auditHealthy);
  }
  const next = store.records.filter((r) => r.id !== memoryId);
  const saved = saveMemoryStore(store, next);
  if (!saved.ok) {
    persistOne(session, "execution.failed", `memory.delete failed: ${saved.reason}`);
    return {
      outcome: { status: "failed", stage: "adapter", reason: saved.reason },
      auditPersisted: session.auditHealthy,
      log: session.log,
    };
  }
  persistOne(session, "execution.completed", `memory.delete ok id=${memoryId}`);
  return {
    outcome: {
      status: "completed",
      operation: "memory.delete:delete",
      result: { v: 1, id: memoryId, deleted: true as const },
      redacted: false,
    },
    auditPersisted: session.auditHealthy,
    log: session.log,
  };
}
