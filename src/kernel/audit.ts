/**
 * Append-only audit log (normative: SECURITY_SPEC.md S9).
 * Persistent immutable structure: every append returns a NEW log.
 * No disable, pause, clear, rewrite, or reorder API exists anywhere
 * in this module — by design, so none can be reached by Macky.
 */
import type { SleepState } from "./types.js";

export interface AuditEventInput {
  type: string;
  detail: string;
  sleepState: SleepState;
}

export interface AuditEvent extends AuditEventInput {
  seq: number;
}

export interface AuditLog {
  readonly events: ReadonlyArray<AuditEvent>;
}

const EMPTY: AuditLog = Object.freeze({ events: Object.freeze([]) });

export function createLog(): AuditLog {
  return EMPTY;
}

/** Append returns a new frozen log; the input log is never mutated. */
export function appendEvent(log: AuditLog, input: AuditEventInput): AuditLog {
  const seq = log.events.length + 1;
  const event: AuditEvent = Object.freeze({
    seq,
    type: input.type,
    detail: input.detail,
    sleepState: input.sleepState,
  });
  return Object.freeze({ events: Object.freeze([...log.events, event]) });
}

// ---------------------------------------------------------------------------
// M2: security-event vocabulary + secret redaction (M2 section 14).
//
// Every authorize() call appends exactly one event naming its terminal
// outcome. Trusted lifecycle transitions (grant issued/revoked,
// sleep/wake) are appended by the trusted caller via
// appendSecurityEvent. Secrets must NEVER enter the log: all details
// pass through redactSecrets first.
// ---------------------------------------------------------------------------

export const SECURITY_EVENT_TYPES = [
  "request.validation-failed",
  "capability.lookup-failed",
  "authorization.no-grant",
  "authorization.unknown-task",
  "sleep.denied",
  "operation.denied",
  "scope.denied",
  "authorization.denied",
  "confirmation.required",
  "confirmation.satisfied",
  "authorization.allowed",
  "capability.issued",
  "capability.revoked",
  "sleep.entered",
  "sleep.woken",
  "execution.rejected",
  "execution.started",
  "execution.completed",
  "execution.failed",
  "result.redacted",
  "limit.exceeded",
] as const;

export type SecurityEventType = (typeof SECURITY_EVENT_TYPES)[number];

/**
 * Redact credential-shaped content before it can reach the audit log.
 * Conservative: any key=value / key:"value" pair whose key looks like
 * a secret, plus PEM blocks and long bearer-style tokens.
 */
export function redactSecrets(text: string): string {
  return text
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, "[REDACTED-PEM]")
    .replace(
      /((?:password|passwd|api[_-]?key|secret|token|private[_-]?key|auth[_-]?token|bearer)\s*[:=]\s*)("[^"]*"|'[^']*'|\S+)/gi,
      "$1[REDACTED]",
    )
    .replace(/\b(sk-(?:live|test)-[A-Za-z0-9_-]{8,})\b/g, "[REDACTED]")
    .replace(/\b(ghp_[A-Za-z0-9]{20,})\b/g, "[REDACTED]")
    .replace(/\b(xox[bap]-[A-Za-z0-9-]{8,})\b/g, "[REDACTED]");
}

/** Append a security event with secrets redacted. Returns a new log. */
export function appendSecurityEvent(
  log: AuditLog,
  type: SecurityEventType,
  detail: string,
  sleepState: SleepState,
): AuditLog {
  return appendEvent(log, {
    type,
    detail: redactSecrets(detail),
    sleepState,
  });
}
