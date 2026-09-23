/**
 * M11 centralized limits. Security limits, never planner-controlled.
 */
export const APP_LIMITS = {
  MAX_APP_ID_CHARS: 128,
  /** Launcher wall-clock budget per launch operation. */
  LAUNCH_TIMEOUT_MS: 10_000,
  /** At most one launch operation in flight per process. */
  MAX_CONCURRENT_LAUNCHES: 1,
} as const;
