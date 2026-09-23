/**
 * Versioned bounded web result contracts. Titles/urls/snippets/body
 * truncated Unicode-safely with explicit flags; absolute result
 * counts and byte sizes reported so callers see bounds. Web content
 * stays content — contracts carry no authority.
 */
import { z } from "zod";
import { WEB_LIMITS } from "./limits.js";

export const WEB_RESULT_VERSION = 1 as const;

export const SearchResultSchema = z
  .object({
    v: z.literal(WEB_RESULT_VERSION),
    query: z.string().max(WEB_LIMITS.MAX_QUERY_CHARS),
    results: z.array(
      z.object({
        title: z.string().max(WEB_LIMITS.MAX_TITLE_CHARS + 32),
        url: z.string().max(WEB_LIMITS.MAX_URL_CHARS),
        snippet: z.string().max(WEB_LIMITS.MAX_SNIPPET_CHARS + 32),
      }),
    ).max(WEB_LIMITS.MAX_RESULTS),
    truncated: z.boolean(),
  })
  .strict();

export const FetchResultSchema = z
  .object({
    v: z.literal(WEB_RESULT_VERSION),
    url: z.string().max(WEB_LIMITS.MAX_URL_CHARS),
    title: z.string().max(WEB_LIMITS.MAX_TITLE_CHARS + 32),
    body: z.string(),
    truncated: z.boolean(),
    redirected: z.boolean(),
  })
  .strict();

export type SearchResult = z.infer<typeof SearchResultSchema>;
export type FetchResult = z.infer<typeof FetchResultSchema>;
