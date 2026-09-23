/**
 * M9 centralized limits. Security limits, never planner-controlled:
 * oversized values are rejected, never clamped. Conservative.
 */
export const WEB_LIMITS = {
  MAX_QUERY_CHARS: 512,
  MAX_RESULTS: 10,
  MAX_URL_CHARS: 2048,
  MAX_TITLE_CHARS: 512,
  MAX_SNIPPET_CHARS: 2048,
  MAX_RESULTS_PAYLOAD_BYTES: 64 * 1024,
  MAX_FETCH_RESPONSE_BYTES: 128 * 1024,
  MAX_REDIRECTS: 3,
  REQUEST_TIMEOUT_MS: 10_000,
  MAX_CONCURRENT_REQUESTS: 1,
} as const;
