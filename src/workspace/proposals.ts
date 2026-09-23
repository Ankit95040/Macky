/**
 * M7 workspace proposal contract (versioned, strict). The planner
 * names a REGISTERED workspaceId plus a workspace-RELATIVE target —
 * never an absolute path, never a root. Absolute paths, `..`
 * segments, backslashes, and NUL bytes are rejected here, before any
 * resolution; the trusted layer joins the relative path onto the
 * canonical root and reuses M3 containment + sensitivity enforcement.
 */
import { z } from "zod";
import { WORKSPACE_LIMITS } from "./limits.js";

export const WORKSPACE_PROPOSAL_VERSION = 1 as const;

const WORKSPACE_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{0,127}$/i;

export const WorkspaceOperationSchema = z.enum([
  "file-read",
  "dir-list",
  "file-find",
  "content-search",
  "tree",
  "git-status",
  "git-log",
  "git-diff",
]);

export type WorkspaceOperation = z.infer<typeof WorkspaceOperationSchema>;

export const WorkspaceProposalSchema = z
  .object({
    v: z.literal(WORKSPACE_PROPOSAL_VERSION),
    workspaceId: z.string().min(1).max(128).regex(WORKSPACE_ID_PATTERN),
    op: WorkspaceOperationSchema,
    /** Workspace-relative path; defaults to the root. */
    path: z.string().min(1).max(WORKSPACE_LIMITS.MAX_WORKSPACE_PATH_CHARS).optional(),
    /** file-find pattern (tiny trusted language, validated downstream). */
    pattern: z.string().min(1).max(128).optional(),
    /** content-search query. */
    query: z.string().min(1).max(256).optional(),
  })
  .strict();

export type WorkspaceProposal = z.infer<typeof WorkspaceProposalSchema>;

/**
 * Validate relative-path shape. Rejects absolute paths, `..`
 * segments (no normalization games — refused outright), backslashes,
 * and NUL bytes. Returns the cleaned relative form or undefined.
 */
export function validateRelativePath(raw: unknown): string | undefined {
  if (raw === undefined) {
    return ".";
  }
  if (typeof raw !== "string" || raw.length === 0) {
    return undefined;
  }
  if (raw.length > WORKSPACE_LIMITS.MAX_WORKSPACE_PATH_CHARS) {
    return undefined;
  }
  if (raw.includes("\0") || raw.includes("\\")) {
    return undefined;
  }
  if (raw.startsWith("/")) {
    return undefined;
  }
  const segments = raw.split("/");
  for (const segment of segments) {
    if (segment === "..") {
      return undefined;
    }
  }
  if (segments.some((s) => s.length === 0 && raw !== ".")) {
    // Tolerate "." only; empty segments elsewhere refused.
    return undefined;
  }
  return raw;
}
