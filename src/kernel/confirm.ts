/**
 * High-risk confirmation gate (normative: SECURITY_SPEC.md S12).
 * Pure functions. Planner self-approval is never valid.
 */
import type { Decision, RiskLevel } from "./types.js";

const RISKS: ReadonlySet<string> = new Set<string>([
  "low",
  "medium",
  "high",
]);

export interface HumanResponse {
  approved: boolean;
  responder: string;
}

/** High risk — and anything unclassifiable — needs human approval. */
export function needsConfirmation(risk: unknown): boolean {
  if (risk === "high") {
    return true;
  }
  if (risk === "medium") {
    return true;
  }
  if (risk === "low") {
    return false;
  }
  return true;
}

/**
 * Resolve a human confirmation round. Only `{ responder: "human" }`
 * counts. Planner/model self-approval, missing fields, or wrong
 * types fail closed to deny.
 */
export function resolveConfirmation(
  pending: Decision,
  response: unknown,
): Decision {
  if (pending.verdict !== "require-confirmation") {
    return pending;
  }
  if (
    typeof response !== "object" ||
    response === null ||
    (response as HumanResponse).responder !== "human" ||
    typeof (response as HumanResponse).approved !== "boolean"
  ) {
    return {
      verdict: "deny",
      reason: "confirmation invalid: explicit human approval required",
    };
  }
  const human = response as HumanResponse;
  if (human.approved === true) {
    return { verdict: "allow", reason: "explicit human approval recorded" };
  }
  return { verdict: "deny", reason: "human declined" };
}

export function riskOf(value: unknown): RiskLevel | undefined {
  if (typeof value === "string" && RISKS.has(value)) {
    return value as RiskLevel;
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// M2: trusted confirmation store (M2 section 7).
//
// The policy engine returns REQUIRE_CONFIRMATION; only the TRUSTED
// confirmation layer produces authorization state. This in-memory store
// is the deterministic/mock provider sufficient for M2 testing — no
// Touch ID, no voice authentication. Planner fields such as
// `approved: true` or `confirmedBy: "user"` never reach this store:
// the strict request schema rejects them at the boundary.
// ---------------------------------------------------------------------------

/** A confirmation recorded by trusted code (human/UI path), never by the planner. */
export interface TrustedConfirmationRecord {
  readonly taskId: string;
  readonly capability: string;
  readonly operation: string;
  /** Redacted resource string; "" for unscoped capabilities. */
  readonly resource: string;
  /**
   * M13: optional SHA-256 hex digest binding the confirmation to an
   * exact payload (speech text). hasConfirmation below never reads
   * this field, so existing capabilities behave bit-identically
   * whether or not any record carries one. Digest enforcement lives
   * ONLY in hasDigestConfirmation.
   */
  readonly digest?: string;
}

export type ConfirmationStore = ReadonlyArray<TrustedConfirmationRecord>;

const EMPTY_STORE: ConfirmationStore = Object.freeze([]);

export function createConfirmationStore(): ConfirmationStore {
  return EMPTY_STORE;
}

/** Record a trusted confirmation. Returns a NEW frozen store. */
export function recordConfirmation(
  store: ConfirmationStore,
  record: TrustedConfirmationRecord,
): ConfirmationStore {
  const entry: TrustedConfirmationRecord = Object.freeze({ ...record });
  return Object.freeze([...store, entry]);
}

/** Exact-match lookup: task + capability + operation + resource. */
export function hasConfirmation(
  store: ConfirmationStore,
  key: TrustedConfirmationRecord,
): boolean {
  return store.some(
    (r: TrustedConfirmationRecord): boolean =>
      r.taskId === key.taskId &&
      r.capability === key.capability &&
      r.operation === key.operation &&
      r.resource === key.resource,
  );
}

/**
 * M13 strict digest-bound lookup: all four identity fields PLUS an
 * exact digest match. A record without a digest NEVER satisfies this
 * (digests cannot be inherited or defaulted); a wrong digest NEVER
 * satisfies it. Used by payload-bound capabilities (speech) whose
 * authorization must cover exact content, not just identity.
 */
export function hasDigestConfirmation(
  store: ConfirmationStore,
  key: Required<Pick<TrustedConfirmationRecord, "taskId" | "capability" | "operation" | "resource" | "digest">>,
): boolean {
  return store.some(
    (r: TrustedConfirmationRecord): boolean =>
      r.taskId === key.taskId &&
      r.capability === key.capability &&
      r.operation === key.operation &&
      r.resource === key.resource &&
      r.digest !== undefined &&
      r.digest === key.digest,
  );
}
