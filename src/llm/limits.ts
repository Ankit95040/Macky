/**
 * M12 centralized LLM limits. Security limits, never planner- or
 * model-controlled. Code-point measured where text is bounded.
 */
export const LLM_LIMITS = {
  MAX_USER_TEXT_CHARS: 4096,
  MAX_CONTEXT_MESSAGES: 16,
  MAX_CONTEXT_MESSAGE_CHARS: 4096,
  MAX_PROMPT_CHARS: 32768,
  MAX_RESPONSE_BYTES: 65536,
  REQUEST_TIMEOUT_MS: 15000,
  MAX_OUTPUT_TOKENS: 1024,
} as const;
