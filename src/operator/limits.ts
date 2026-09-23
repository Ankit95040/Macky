/**
 * M16 operator limits. Security limits, never operator-input
 * controlled: oversized requests are refused, never clamped.
 */
export const OPERATOR_LIMITS = {
  MAX_ID_CHARS: 128,
  MAX_SCOPE_CHARS: 1024,
  MAX_OPERATION_CHARS: 64,
  MAX_AUDIT_TAIL: 100,
} as const;
