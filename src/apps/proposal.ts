/**
 * Strict versioned M11 proposal schema. The planner controls ONLY
 * appId — a bounded logical identifier with no control characters.
 * Every trusted field (path, executable, bundle, args, shell, env,
 * cwd, url, file, risk, capability, confirmation, taskId, epoch,
 * policy, registry, privilege, timeout) is absent: supplying any of
 * it fails validation. Never stripped, repaired, or coerced.
 * Unicode-safe: length measured in code points.
 */
import { z } from "zod";
import { APP_LIMITS } from "./limits.js";

export const APP_PROPOSAL_VERSION = 1 as const;

const APP_ID_PATTERN = /^[A-Za-z0-9._-]{1,128}$/;

export const AppLaunchProposalSchema = z
  .object({
    v: z.literal(APP_PROPOSAL_VERSION),
    operation: z.literal("app-launch"),
    appId: z.string().min(1).max(APP_LIMITS.MAX_APP_ID_CHARS + 64),
  })
  .strict()
  .superRefine((p, ctx) => {
    if (Array.from(p.appId).length > APP_LIMITS.MAX_APP_ID_CHARS) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "appId exceeds length limit" });
      return;
    }
    if (/[\0-\x1f\x7f]/.test(p.appId)) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "appId contains control characters" });
      return;
    }
    if (!APP_ID_PATTERN.test(p.appId)) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "appId has invalid shape" });
    }
  });

export type AppLaunchProposal = z.infer<typeof AppLaunchProposalSchema>;
