/**
 * Deterministic conversation bounds (M6 section 3). Conservative for
 * an 8 GB Mac. Exceeding a bound fails closed, except tool-result
 * text which truncates with an explicit marker (documented §8 policy).
 */
export const CONVERSATION_LIMITS = {
  /** Refuse any single message longer than this. */
  MAX_MESSAGE_CHARS: 4096,
  /** Refuse new messages beyond this many per session. */
  MAX_MESSAGES: 32,
  /** Hard cap on planner/tool iterations per user message. */
  MAX_TOOL_ITERATIONS: 3,
  /** Refuse planner outputs (JSON) larger than this. */
  MAX_PLANNER_OUTPUT_CHARS: 8192,
  /** Refuse growth beyond this accumulated total. */
  MAX_CONVERSATION_CHARS: 65536,
  /** Tool text kept per message; excess truncates with a marker. */
  MAX_TOOL_RESULT_CHARS: 4096,
  /** Recent messages forwarded to the planner as (untrusted) context. */
  HISTORY_TO_PLANNER: 8,
} as const;

export const TOOL_TRUNCATION_MARKER = "[truncated: result exceeded bounded size]" as const;
