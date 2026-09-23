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
  // ---- M7 bounded discovery (conservative for an 8 GB Mac) ----
  /** Max recursion depth for find/search/tree walks. */
  MAX_SEARCH_DEPTH: 8,
  /** Max tree depth (stricter than search; trees fan out). */
  MAX_TREE_DEPTH: 6,
  /** Max filesystem entries visited per walk. */
  MAX_VISITED_ENTRIES: 2000,
  /** Max entries returned by find. */
  MAX_FIND_RESULTS: 200,
  /** Max matches returned by content search. */
  MAX_SEARCH_MATCHES: 100,
  /** Per-file read cap during content search. */
  SEARCH_MAX_FILE_BYTES: 32 * 1024,
  /** Max nodes in a tree result. */
  MAX_TREE_NODES: 300,
  /** Max pattern text (find) / query text (search). */
  MAX_PATTERN_CHARS: 128,
  MAX_QUERY_CHARS: 256,
} as const;

export type LimitName = keyof typeof LIMITS;
