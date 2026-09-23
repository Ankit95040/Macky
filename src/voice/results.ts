/**
 * Versioned voice result contract. Carries the validated transcript
 * (untrusted text, handed to handleUserMessage by the caller) or a
 * typed refusal/failure. Bounded metadata only — never audio bytes,
 * never paths, never secrets.
 */
import { z } from "zod";
import { VOICE_LIMITS } from "./limits.js";

export const VOICE_RESULT_VERSION = 1 as const;

export const VoiceResultSchema = z
  .object({
    v: z.literal(VOICE_RESULT_VERSION),
    status: z.enum(["completed", "refused", "failed", "cancelled"]),
    transcript: z.string().max(VOICE_LIMITS.MAX_TRANSCRIPT_CHARS + 32).optional(),
    audioBytes: z.number().int().min(0).optional(),
    durationMs: z.number().int().min(0),
    reason: z.string().max(256).optional(),
  })
  .strict();

export type VoiceResult = z.infer<typeof VoiceResultSchema>;
