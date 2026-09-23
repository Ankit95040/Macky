/**
 * Strict versioned speech proposal contract (M13 section 1).
 * Untrusted fields: exactly {v, operation, text} — nothing else.
 * Strictly rejected (never repaired/stripped): capability, family,
 * tier, risk, approved, confirmation, digest, taskId, executable,
 * argv, voice, volume, output, file, path, URL, environment,
 * timeout, shell, cwd, and any unknown field. Limits: 1..500 code
 * points, non-empty, no truncation, Unicode-safe counting.
 */
import { z } from "zod";
import { SPEECH_LIMITS } from "./limits.js";

export const SPEECH_PROPOSAL_VERSION = 1 as const;

export const SpeechProposalSchema = z
  .object({
    v: z.literal(SPEECH_PROPOSAL_VERSION),
    operation: z.literal("speech-announce"),
    text: z.string().min(1).max(SPEECH_LIMITS.MAX_TEXT_CHARS + 64),
  })
  .strict()
  .superRefine((p, ctx) => {
    if (Array.from(p.text).length === 0 || Array.from(p.text).length > SPEECH_LIMITS.MAX_TEXT_CHARS) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "text rejected: length bounds" });
    }
  });

export type SpeechProposal = z.infer<typeof SpeechProposalSchema>;
