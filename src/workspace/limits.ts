/**
 * M7 workspace limits. Size/depth/count policy lives ONCE in the
 * executor (M3 LIMITS — no second file-size policy); this module adds
 * only workspace-layer bounds: path text, registry size, and the
 * user-facing result cap applied with explicit truncation flags.
 */
export const WORKSPACE_LIMITS = {
  /** Max workspaces registered per process. */
  MAX_WORKSPACES: 16,
  /** Max characters in a workspace-relative path or root. */
  MAX_WORKSPACE_PATH_CHARS: 1024,
} as const;
