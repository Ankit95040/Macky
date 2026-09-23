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
