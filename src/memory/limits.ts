/**
 * M10 centralized limits. Security limits, never planner-controlled:
 * oversized values are refused, never clamped. Unicode lengths are
 * code points (Array.from), never UTF-16 units.
 */
export const MEMORY_LIMITS = {
  MAX_CONTENT_CHARS: 4096,
  MAX_RECORDS: 1000,
  MAX_QUERY_CHARS: 256,
  MAX_RESULTS: 20,
  MAX_TOTAL_STORAGE_BYTES: 4 * 1024 * 1024,
  MAX_RECORD_SERIALIZED_BYTES: 8192,
  MAX_RESULT_PAYLOAD_BYTES: 64 * 1024,
} as const;
