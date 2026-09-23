/**
 * Deterministic resource limits (M3 section 6).
 *
 * A read-only executor must not become a resource-exhaustion primitive.
 * Values are conservative for an 8 GB MacBook. Over-limit requests are
 * DENIED with a structured limit-exceeded outcome — never silently
 * truncated and presented as complete.
 */
export const LIMITS = {
  /** Refuse any single file read larger than this. */
  MAX_FILE_BYTES: 64 * 1024,
  /** Refuse directory listings larger than this many entries. */
  MAX_DIR_ENTRIES: 200,
  /** Refuse any adapter result larger than this. */
  MAX_RESULT_BYTES: 256 * 1024,
  /** git log entry cap (adapter enforces via --max-count). */
  GIT_MAX_COMMITS: 50,
  /** Refuse git output larger than this. */
  GIT_MAX_BYTES: 128 * 1024,
  /** Adapter wall-clock budget per operation. */
  EXEC_TIMEOUT_MS: 10_000,
  /** Filesystem list is single-level only: no recursion, no depth. */
  LIST_RECURSIVE: false,
} as const;

export type LimitName = keyof typeof LIMITS;
