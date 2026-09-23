/**
 * M8 centralized command limits (section 11). Security limits, never
 * planner-controlled: proposals carrying timeouts/sizes are rejected
 * by the schema. Conservative for an 8 GB Mac.
 */
export const COMMAND_LIMITS = {
  MAX_ARGV_COUNT: 16,
  /** Code points per argument. */
  MAX_ARG_CHARS: 1024,
  /** Total argv bytes. */
  MAX_ARGV_BYTES: 16 * 1024,
  COMMAND_TIMEOUT_MS: 10_000,
  /** Grace between SIGTERM and SIGKILL on timeout. */
  KILL_GRACE_MS: 1_000,
  MAX_STDOUT_BYTES: 64 * 1024,
  MAX_STDERR_BYTES: 64 * 1024,
  /** Derived bound: 64 KiB + 64 KiB. Enforced per stream. */
  MAX_COMBINED_BYTES: 128 * 1024,
  /** Only one M8 command in flight per process. */
  MAX_CONCURRENT_COMMANDS: 1,
} as const;
