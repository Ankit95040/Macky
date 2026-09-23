/**
 * Versioned workspace result contracts (M7 section 12). Bounded
 * fields, workspace-RELATIVE paths (absolute paths never surface
 * unless workspace policy permits — M7 policy does not), explicit
 * truncated flags wherever capping applies.
 */
import { z } from "zod";
import { WORKSPACE_LIMITS } from "./limits.js";

export const WORKSPACE_RESULT_VERSION = 1 as const;

const RelPath = z.string().max(WORKSPACE_LIMITS.MAX_WORKSPACE_PATH_CHARS);
const EntryKind = z.enum(["file", "dir", "symlink", "other"]);

export const DirectoryListingResultSchema = z
  .object({
    v: z.literal(WORKSPACE_RESULT_VERSION),
    workspaceId: z.string(),
    path: RelPath,
    entries: z.array(z.object({ name: z.string().max(256), kind: EntryKind, size: z.number().optional() })),
    truncated: z.literal(false),
  })
  .strict();

export const FileReadResultSchema = z
  .object({
    v: z.literal(WORKSPACE_RESULT_VERSION),
    workspaceId: z.string(),
    path: RelPath,
    content: z.string().max(64 * 1024),
    redacted: z.boolean(),
    truncated: z.literal(false),
  })
  .strict();

export const FileSearchResultSchema = z
  .object({
    v: z.literal(WORKSPACE_RESULT_VERSION),
    workspaceId: z.string(),
    path: RelPath,
    pattern: z.string(),
    entries: z.array(z.object({ path: RelPath, kind: EntryKind })),
    pruned: z.number().int().min(0),
    truncated: z.boolean(),
  })
  .strict();

export const ContentSearchResultSchema = z
  .object({
    v: z.literal(WORKSPACE_RESULT_VERSION),
    workspaceId: z.string(),
    path: RelPath,
    matches: z.array(
      z.object({ path: RelPath, line: z.number().int().min(1), context: z.string().max(512) }),
    ),
    pruned: z.number().int().min(0),
    truncated: z.boolean(),
  })
  .strict();

const TreeNodeSchema: z.ZodType<unknown> = z.object({
  name: z.string().max(256),
  kind: EntryKind,
  children: z.array(z.lazy((): z.ZodType<unknown> => TreeNodeSchema)).optional(),
});

export const TreeResultSchema = z
  .object({
    v: z.literal(WORKSPACE_RESULT_VERSION),
    workspaceId: z.string(),
    path: RelPath,
    nodes: z.array(TreeNodeSchema),
    pruned: z.number().int().min(0),
    truncated: z.boolean(),
  })
  .strict();

export type DirectoryListingResult = z.infer<typeof DirectoryListingResultSchema>;
export type FileReadResult = z.infer<typeof FileReadResultSchema>;
export type FileSearchResult = z.infer<typeof FileSearchResultSchema>;
export type ContentSearchResult = z.infer<typeof ContentSearchResultSchema>;
export type TreeResult = z.infer<typeof TreeResultSchema>;
