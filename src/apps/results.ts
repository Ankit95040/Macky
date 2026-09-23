/**
 * Strict versioned M11 result. Bounded metadata only: logical appId,
 * outcome, duration. No stdout/stderr (ignored), no environment, no
 * executable/bundle paths, no shell text. Contains no authority.
 */
import { z } from "zod";

export const APP_RESULT_VERSION = 1 as const;

export const AppLaunchResultSchema = z
  .object({
    v: z.literal(APP_RESULT_VERSION),
    operation: z.literal("app-launch"),
    appId: z.string().max(128),
    status: z.enum(["launched", "failed", "refused"]),
    truncated: z.literal(false),
  })
  .strict();

export type AppLaunchResult = z.infer<typeof AppLaunchResultSchema>;
