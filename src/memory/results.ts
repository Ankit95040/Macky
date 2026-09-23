/**
 * Versioned bounded memory result contracts. Records carry trusted
 * display metadata (id, kind, timestamps, task, epoch) alongside
 * UNTRUSTED content. Payloads bounded with explicit truncated flags.
 */
import { z } from "zod";
import { MEMORY_LIMITS } from "./limits.js";

export const MEMORY_RESULT_VERSION = 1 as const;

const RecordViewSchema = z.object({
  id: z.string().max(64),
  kind: z.enum(["fact", "preference", "project", "instruction"]),
  content: z.string().max(MEMORY_LIMITS.MAX_CONTENT_CHARS + 32),
  createdAt: z.string(),
  taskId: z.string().max(128),
});

export const MemoryReadResultSchema = z
  .object({
    v: z.literal(MEMORY_RESULT_VERSION),
    records: z.array(RecordViewSchema).max(MEMORY_LIMITS.MAX_RESULTS),
    truncated: z.boolean(),
  })
  .strict();

export const MemoryWriteResultSchema = z
  .object({
    v: z.literal(MEMORY_RESULT_VERSION),
    id: z.string().max(64),
    kind: z.enum(["fact", "preference", "project", "instruction"]),
  })
  .strict();

export const MemoryDeleteResultSchema = z
  .object({
    v: z.literal(MEMORY_RESULT_VERSION),
    id: z.string().max(64),
    deleted: z.literal(true),
  })
  .strict();

export type MemoryReadResult = z.infer<typeof MemoryReadResultSchema>;
export type MemoryWriteResult = z.infer<typeof MemoryWriteResultSchema>;
export type MemoryDeleteResult = z.infer<typeof MemoryDeleteResultSchema>;
