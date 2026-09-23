/**
 * Policy engine (normative: SECURITY_SPEC.md S1/S2/S4/S5/S14).
 * Default-deny, fail-closed, pure functions. The policy object is
 * frozen and this module exports NO mutation API on any
 * planner/model/memory/external-reachable path (S8).
 */
import { z } from "zod";
import { getCapability } from "./capabilities.js";
import { needsConfirmation } from "./confirm.js";
import { isCategoryAllowed } from "./sleep.js";
import {
  SLEEP_GATED_CATEGORIES,
  type Decision,
  type SleepGatedCategory,
  type SleepState,
} from "./types.js";

/** Untrusted planner proposals MUST pass this schema (S4/S5). */
export const PlannerProposalSchema = z
  .object({
    action: z.string().min(1).max(256),
    capability: z.string().min(1).max(128),
    category: z.enum(SLEEP_GATED_CATEGORIES).optional(),
    risk: z.enum(["low", "medium", "high"]).optional(),
  })
  .strict();

export type PlannerProposal = z.infer<typeof PlannerProposalSchema>;

export interface PolicyContext {
  sleep: SleepState;
}

export const POLICY_VERSION = "m1-foundation" as const;

/**
 * Evaluate one planner proposal. Order is load-bearing:
 * 1. schema validation (untrusted input) → deny on failure
 * 2. SLEEP gate → deny gated categories while asleep
 * 3. capability must be declared → deny unknown
 * 4. risk/confirmation → require-confirmation where needed
 * 5. default deny (S1): no allowlist grants in M1 beyond audit/sleep
 */
export function evaluateProposal(
  proposal: unknown,
  ctx: PolicyContext,
): Decision {
  const parsed = PlannerProposalSchema.safeParse(proposal);
  if (!parsed.success) {
    return {
      verdict: "deny",
      reason: "proposal failed validation: untrusted planner output rejected",
    };
  }
  const p: PlannerProposal = parsed.data;

  if (p.category !== undefined) {
    const category: SleepGatedCategory = p.category;
    if (!isCategoryAllowed(ctx.sleep, category)) {
      return {
        verdict: "deny",
        reason: `sleep gate: category "${category}" not allowed while ${ctx.sleep}`,
      };
    }
  }

  const capability = getCapability(p.capability);
  if (capability === undefined) {
    return {
      verdict: "deny",
      reason: `unknown capability "${p.capability}": default deny`,
    };
  }

  const risk = p.risk ?? capability.risk;
  if (needsConfirmation(risk) || capability.requiresConfirmation) {
    return {
      verdict: "require-confirmation",
      reason: `capability "${capability.id}" requires explicit human approval`,
    };
  }

  if (ctx.sleep === "SLEEP" && capability.sleepGated) {
    return {
      verdict: "deny",
      reason: `capability "${capability.id}" is sleep-gated`,
    };
  }

  if (capability.id === "system.sleep" || capability.id === "audit.append") {
    return {
      verdict: "allow",
      reason: `capability "${capability.id}" granted at low risk`,
    };
  }

  return {
    verdict: "deny",
    reason: `default deny: no grant rule for "${capability.id}"`,
  };
}
