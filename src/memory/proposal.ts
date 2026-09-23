/**
 * Strict versioned M10 proposal schemas. The planner controls ONLY
 * the listed fields per operation. Every trusted field (capability,
 * risk, confirmation, taskId, epoch, sessionId, memoryId-on-write,
 * timestamps, source, storage path, retention, policy, grants,
 * provider, filesystem paths) is absent — supplying any of it fails
 * validation. Never stripped, repaired, or coerced.
 */
import { z } from "zod";
import { MEMORY_LIMITS } from "./limits.js";

export const MEMORY_PROPOSAL_VERSION = 1 as const;

const CONTROL_CHARS = /[\0-\x1f\x7f]/;

function cleanText(value: string, maxCodePoints: number): boolean {
  const points = Array.from(value);
  if (points.length === 0 || points.length > maxCodePoints) {
    return false;
  }
  return !CONTROL_CHARS.test(value);
}

export const MemoryReadProposalSchema = z
  .object({
    v: z.literal(MEMORY_PROPOSAL_VERSION),
    operation: z.literal("memory-read"),
    // Shape bound in UTF-16 units with headroom: the refine below
    // enforces the real code-point limit (astral chars take 2 units).
    query: z.string().min(1).max(MEMORY_LIMITS.MAX_QUERY_CHARS * 2 + 64),
    maxResults: z.number().int().min(1).max(MEMORY_LIMITS.MAX_RESULTS).optional(),
  })
  .strict()
  .superRefine((p, ctx) => {
    if (!cleanText(p.query, MEMORY_LIMITS.MAX_QUERY_CHARS)) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "query rejected" });
    }
  });

export const MemoryKindSchema = z.enum(["fact", "preference", "project", "instruction"]);

export const MemoryWriteProposalSchema = z
  .object({
    v: z.literal(MEMORY_PROPOSAL_VERSION),
    operation: z.literal("memory-write"),
    content: z.string().min(1).max(MEMORY_LIMITS.MAX_CONTENT_CHARS * 2 + 256),
    kind: MemoryKindSchema,
  })
  .strict()
  .superRefine((p, ctx) => {
    if (!cleanText(p.content, MEMORY_LIMITS.MAX_CONTENT_CHARS)) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "content rejected" });
    }
  });

const MEMORY_ID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;

export const MemoryDeleteProposalSchema = z
  .object({
    v: z.literal(MEMORY_PROPOSAL_VERSION),
    operation: z.literal("memory-delete"),
    memoryId: z.string().min(1).max(64).regex(MEMORY_ID_PATTERN),
  })
  .strict();

export type MemoryReadProposal = z.infer<typeof MemoryReadProposalSchema>;
export type MemoryWriteProposal = z.infer<typeof MemoryWriteProposalSchema>;
export type MemoryDeleteProposal = z.infer<typeof MemoryDeleteProposalSchema>;
