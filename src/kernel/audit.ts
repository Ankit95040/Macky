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
