/**
 * Durable secure session + epoch-bound execution (M4 sections 2/3/15).
 *
 * The session is the process-lifetime trusted context: epoch, sleep,
 * kill-switch, grants, confirmations, audit cursor + health, in-memory
 * log mirror. Grants/confirmations live ONLY here — never persisted —
 * so a restart inherently voids them; the epoch envelope makes
 * staleness explicit and testable.
 *
 * runDurable() is the only M4 execution entry: envelope epoch must
 * equal the live epoch, the sink is probed BEFORE dispatch (no OS
 * touch on audit failure), M3 run() executes, then delta events are
 * persisted. Persistence failure degrades the session: subsequent
 * calls refuse until a fresh boot with a healthy sink. This is the
 * documented §6 policy — decision, persistence success, and
 * persistence failure are always distinguishable in the result.
 */
import { z } from "zod";
import * as fs from "node:fs";
import { createLog, type AuditLog } from "../kernel/audit.js";
import {
  createConfirmationStore,
  recordConfirmation,
  type ConfirmationStore,
  type TrustedConfirmationRecord,
} from "../kernel/confirm.js";
import {
  createKillSwitch,
  disengageKillSwitch,
  engageKillSwitch,
  type KillSwitchKey,
  type KillSwitchState,
} from "../kernel/kill-switch.js";
import {
  issueGrant,
  revokeGrant,
  type GrantIssuance,
  type TrustedTaskGrant,
} from "../kernel/task-grants.js";
import { enterSleep, requestWake } from "../kernel/sleep.js";
import type { SleepState } from "../kernel/types.js";
import { run, type ExecutionContext, type ExecutionOutcome } from "../executor/executor.js";
import type { MackyConfig } from "../bootstrap/config.js";
import {
  appendAuditEvent,
  AUDIT_LIMITS,
  type AuditSink,
} from "./audit-store.js";

export interface SecureSession {
  readonly config: MackyConfig;
  readonly epoch: number;
  sleep: SleepState;
  killSwitch: KillSwitchState;
  readonly controlKey: KillSwitchKey;
  grants: Array<TrustedTaskGrant>;
  confirmations: ConfirmationStore;
  log: AuditLog;
  readonly sink: AuditSink;
  auditHealthy: boolean;
}

export function createSession(
  config: MackyConfig,
  epoch: number,
  sink: AuditSink,
): SecureSession {
  const ks = createKillSwitch();
  return {
    config,
    epoch,
    sleep: "SLEEP",
    killSwitch: ks.state,
    controlKey: ks.key,
    grants: [],
    confirmations: createConfirmationStore(),
    log: createLog(),
    sink,
    auditHealthy: true,
  };
}

const DurableEnvelopeSchema = z
  .object({
    epoch: z.number().int().min(1),
    request: z.unknown(),
  })
  .strict();

export interface DurableEnvelope {
  readonly epoch: number;
  readonly request: unknown;
}

export interface DurableResult {
  readonly outcome: ExecutionOutcome;
  /** False when events could NOT be persisted (session now degraded). */
  readonly auditPersisted: boolean;
  readonly log: AuditLog;
}

function persistInternal(  session: SecureSession,
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

/**
 * Persist in-memory log events appended since `fromLength` to the
 * durable sink. Shared by runDurable (M4) and command execution (M8)
 * so both report decision/persistence separately. Degrades the
 * session on any failure.
 */
export function persistLogDelta(session: SecureSession, fromLength: number): boolean {
  let ok = true;
  for (const event of session.log.events.slice(fromLength)) {
    const r = appendAuditEvent(session.sink, {
      type: event.type,
      detail: event.detail,
      epoch: session.epoch,
      sleep: event.sleepState,
    });
    if (!r.ok) {
      ok = false;
    }
  }
  if (!ok) {
    session.auditHealthy = false;
  }
  return ok;
}

/** Trusted grant issuance into the live session (audited). */
export function grantToSession(
  session: SecureSession,
  issuance: GrantIssuance,
): { readonly ok: true } | { readonly ok: false; readonly reason: string } {
  let grant: TrustedTaskGrant;
  try {
    grant = issueGrant(issuance);
  } catch {
    return { ok: false, reason: "invalid issuance" };
  }
  session.grants.push(grant);
  if (!persistInternal(session, "capability.issued", `issued ${grant.grantId} for ${grant.taskId}`)) {
    session.grants = session.grants.filter((g) => g.grantId !== grant.grantId);
    return { ok: false, reason: "audit persistence failed; issuance rolled back" };
  }
  return { ok: true };
}

/** Trusted revocation (audited). */
export function revokeSessionGrant(session: SecureSession, grantId: string): void {
  session.grants = [...revokeGrant(session.grants, grantId)];
  persistInternal(session, "capability.revoked", `revoked ${grantId}`);
}

/** Trusted confirmation recording (audited). */
export function confirmInSession(
  session: SecureSession,
  record: TrustedConfirmationRecord,
): void {
  session.confirmations = recordConfirmation(session.confirmations, record);
  persistInternal(
    session,
    "confirmation.recorded",
    `confirmation recorded for ${record.taskId} ${record.capability}`,
  );
}

export function sleepSession(session: SecureSession): void {
  session.sleep = enterSleep(session.sleep);
  persistInternal(session, "sleep.entered", "entered SLEEP");
}

/** Trusted local wake only. Returns true on SLEEP→AWAKE transition. */
export function wakeSession(session: SecureSession, action: unknown): boolean {
  const next = requestWake(session.sleep, action);
  if (next === "AWAKE" && session.sleep !== "AWAKE") {
    session.sleep = next;
    persistInternal(session, "sleep.woken", "explicit trusted wake");
    return true;
  }
  return false;
}

export function engageSessionKill(session: SecureSession): void {
  session.killSwitch = engageKillSwitch(session.killSwitch);
  persistInternal(session, "kill.engaged", "kill switch engaged");
}

export function disengageSessionKill(session: SecureSession, key: unknown): boolean {
  const next = disengageKillSwitch(session.killSwitch, key, session.controlKey);
  const changed = next.engaged === false && session.killSwitch.engaged === true;
  session.killSwitch = next;
  return changed;
}

/** Sink writability + space probe. No throw, no side effects. */
function probeSink(session: SecureSession): boolean {
  const st = auditFileSize(session.sink.path);
  return st.writable && st.bytes < AUDIT_LIMITS.MAX_AUDIT_FILE_BYTES;
}

function auditFileSize(filePath: string): { writable: boolean; bytes: number } {
  try {
    const dir = filePath.slice(0, filePath.lastIndexOf("/"));
    if (fs.existsSync(filePath)) {
      fs.accessSync(filePath, fs.constants.W_OK);
      return { writable: true, bytes: fs.statSync(filePath).size };
    }
    fs.accessSync(dir, fs.constants.W_OK);
    return { writable: true, bytes: 0 };
  } catch {
    return { writable: false, bytes: 0 };
  }
}

/**
 * Epoch-bound durable execution. Refuses (in order): degraded session,
 * malformed envelope, stale epoch, unwritable audit sink — all BEFORE
 * any OS touch. Then delegates to M3 run() and persists the delta.
 */
export function runDurable(
  session: SecureSession,
  envelope: unknown,
): DurableResult {
  if (!session.auditHealthy) {
    return {
      outcome: { status: "refused", stage: "audit", reason: "audit persistence unhealthy: refuse until fresh boot" },
      auditPersisted: false,
      log: session.log,
    };
  }
  const parsed = DurableEnvelopeSchema.safeParse(envelope);
  if (!parsed.success) {
    persistInternal(session, "request.validation-failed", "malformed durable envelope rejected");
    return {
      outcome: { status: "refused", stage: "envelope", reason: "malformed envelope" },
      auditPersisted: session.auditHealthy,
      log: session.log,
    };
  }
  const env: DurableEnvelope = { epoch: parsed.data.epoch, request: parsed.data.request };
  if (env.epoch !== session.epoch) {
    const persisted = persistInternal(
      session,
      "authorization.denied",
      `stale epoch ${env.epoch} presented to epoch ${session.epoch}`,
    );
    return {
      outcome: { status: "refused", stage: "epoch", reason: `stale epoch: want ${session.epoch}` },
      auditPersisted: persisted,
      log: session.log,
    };
  }
  if (!probeSink(session)) {
    session.auditHealthy = false;
    return {
      outcome: { status: "refused", stage: "audit", reason: "audit sink not writable: execution refused before OS touch" },
      auditPersisted: false,
      log: session.log,
    };
  }
  const execCtx: ExecutionContext = {
    sleep: session.sleep,
    grants: session.grants,
    confirmations: session.confirmations,
    killSwitch: session.killSwitch,
    log: session.log,
  };
  const before = session.log.events.length;
  const result = run(env.request, execCtx);
  session.log = result.log;
  let persisted = true;
  for (const event of result.log.events.slice(before)) {
    const r = appendAuditEvent(session.sink, {
      type: event.type,
      detail: event.detail,
      epoch: session.epoch,
      sleep: event.sleepState,
    });
    if (!r.ok) {
      persisted = false;
    }
  }
  if (!persisted) {
    session.auditHealthy = false;
  }
  return { outcome: result.outcome, auditPersisted: persisted, log: result.log };
}
