/**
 * Strict versioned command result (M8 section 22). Bounded stdout /
 * stderr with explicit truncation flags, exit/signal/duration. No
 * absolute paths, no environment, no unbounded output.
 */
import { z } from "zod";

export const COMMAND_RESULT_VERSION = 1 as const;

export const CommandResultSchema = z
  .object({
    v: z.literal(COMMAND_RESULT_VERSION),
    status: z.enum(["completed", "failed", "timed-out", "refused"]),
    exitCode: z.number().int().min(0).max(255).optional(),
    signal: z.string().max(32).optional(),
    stdout: z.string().max(70 * 1024),
    stderr: z.string().max(70 * 1024),
    stdoutTruncated: z.boolean(),
    stderrTruncated: z.boolean(),
    durationMs: z.number().int().min(0),
  })
  .strict();

export type CommandResult = z.infer<typeof CommandResultSchema>;
