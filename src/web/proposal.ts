/**
 * Strict versioned M9 proposal schemas. Planner controls ONLY the
 * listed fields. Provider, headers, cookies, auth, proxy, DNS, TLS,
 * timeout, redirects, limits, method, capability, tier, confirmation,
 * task authority, and policy are absent — supplying any of them fails
 * validation. Never stripped, repaired, or coerced.
 */
import { z } from "zod";
import { WEB_LIMITS } from "./limits.js";

export const WEB_PROPOSAL_VERSION = 1 as const;

const CONTROL_CHARS = /[\0-\x1f\x7f]/;

function cleanText(value: string, maxChars: number): boolean {
  if (Array.from(value).length === 0 || Array.from(value).length > maxChars) {
    return false;
  }
  return !CONTROL_CHARS.test(value);
}

export const WebSearchProposalSchema = z
  .object({
    v: z.literal(WEB_PROPOSAL_VERSION),
    operation: z.literal("web-search"),
    query: z.string().min(1).max(WEB_LIMITS.MAX_QUERY_CHARS + 64),
    maxResults: z.number().int().min(1).max(WEB_LIMITS.MAX_RESULTS).optional(),
  })
  .strict()
  .superRefine((p, ctx) => {
    if (!cleanText(p.query, WEB_LIMITS.MAX_QUERY_CHARS)) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "query rejected" });
    }
  });

export const WebFetchProposalSchema = z
  .object({
    v: z.literal(WEB_PROPOSAL_VERSION),
    operation: z.literal("web-fetch"),
    url: z.string().min(1).max(WEB_LIMITS.MAX_URL_CHARS),
  })
  .strict()
  .superRefine((p, ctx) => {
    if (CONTROL_CHARS.test(p.url)) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "url rejected: control characters" });
    }
  });

export type WebSearchProposal = z.infer<typeof WebSearchProposalSchema>;
export type WebFetchProposal = z.infer<typeof WebFetchProposalSchema>;
