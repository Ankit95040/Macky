/**
 * Strict versioned speech result. Bounded metadata only: logical
 * outcome, duration. No stdout/stderr text (ignored), no text echo,
 * no environment, no paths. Contains no authority.
 */
import { z } from "zod";

export const SPEECH_RESULT_VERSION = 1 as const;

export const SpeechResultSchema = z
  .object({
    v: z.literal(SPEECH_RESULT_VERSION),
    operation: z.literal("speech-announce"),
    status: z.enum(["announced", "failed", "refused"]),
    truncated: z.literal(false),
  })
  .strict();

export type SpeechResult = z.infer<typeof SpeechResultSchema>;
