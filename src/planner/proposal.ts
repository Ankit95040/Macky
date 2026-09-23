/**
 * Untrusted planner contract (M5 section 1, M12 trusted task binding).
 * Versioned, strict.
 *
 * The planner returns ONLY proposal data: what family, what
 * operation, what target, plus inert rationale. It MUST NOT supply
 * trusted authorization state — risk tier, decisions, approvals,
 * grants, kill-switch/sleep/policy material. The schema is
 * `.strict()`, so any forbidden field fails validation and the
 * proposal is rejected outright. Forbidden fields are NEVER silently
 * stripped: adversarial input is denied, not repaired.
 *
 * taskId is OPTIONAL in untrusted output (M12 corrective fix). When
 * absent, the trusted envelope.taskId is authoritative. When present,
 * it must equal the trusted envelope.taskId or the proposal is
 * refused. Either way the planner never selects task identity: the
 * M2 request is always built from the envelope value.
 */
import { z } from "zod";

export const PLANNER_CONTRACT_VERSION = 1 as const;

const TASK_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{0,127}$/i;

export const UntrustedProposalSchema = z
  .object({
    plannerVersion: z.literal(PLANNER_CONTRACT_VERSION),
    // Optional (M12 corrective fix): absent binds the trusted
    // envelope taskId; present must equal it (checked in boundary.ts).
    taskId: z.string().min(1).max(128).regex(TASK_ID_PATTERN).optional(),
    family: z.enum(["filesystem", "git", "system"]),
    operation: z.string().min(1).max(64),
    resource: z.string().min(1).max(512).optional(),
    requestId: z.string().min(1).max(128).optional(),
    /** Inert free text. Dropped at the trust boundary, never forwarded. */
    rationale: z.string().max(512).optional(),
    // M7: bounded opaque per-operation parameters (find pattern, search
    // query). Forwarded to M2/M3 untouched; each adapter validates
    // exactly the keys it understands and refuses anything else.
    params: z.record(z.string().min(1).max(32), z.string().max(256)).optional(),
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
