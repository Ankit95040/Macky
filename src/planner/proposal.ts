/**
 * Untrusted planner contract (M5 section 1). Versioned, strict.
 *
 * The planner returns ONLY proposal data: who (taskId), what family,
 * what operation, what target, plus inert rationale. It MUST NOT
 * supply trusted authorization state — risk tier, decisions,
 * approvals, grants, kill-switch/sleep/policy material. The schema is
 * `.strict()`, so any forbidden field fails validation and the
 * proposal is rejected outright. Forbidden fields are NEVER silently
 * stripped: adversarial input is denied, not repaired.
 */
import { z } from "zod";

export const PLANNER_CONTRACT_VERSION = 1 as const;

const TASK_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{0,127}$/i;

export const UntrustedProposalSchema = z
  .object({
    plannerVersion: z.literal(PLANNER_CONTRACT_VERSION),
    taskId: z.string().min(1).max(128).regex(TASK_ID_PATTERN),
    family: z.enum(["filesystem", "git", "system"]),
    operation: z.string().min(1).max(64),
    resource: z.string().min(1).max(512).optional(),
    requestId: z.string().min(1).max(128).optional(),
    /** Inert free text. Dropped at the trust boundary, never forwarded. */
    rationale: z.string().max(512).optional(),
  })
  .strict();

export type UntrustedProposal = z.infer<typeof UntrustedProposalSchema>;

/** Application-level input the (trusted) app hands to the planner. */
export interface PlannerInput {
  readonly taskId: string;
  readonly family: "filesystem" | "git" | "system";
  readonly operation: string;
  readonly resource?: string;
  readonly rationale?: string;
}
