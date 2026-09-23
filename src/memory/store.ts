/**
 * Durable local memory store (M10 persistence). One bounded JSON file
 * with atomic replacement (tmp + fsync + rename, 0o600, 0o700 dir).
 * No database. Storage root comes from trusted configuration, never
 * planner input. Malformed storage fails closed at open; records are
 * schema-validated on every load; failed writes never partially
 * mutate in-memory state (validate + write first, swap on success).
 *
 * IDs (`mem-<uuid>`) and timestamps are generated here by trusted
 * code only. The store holds DATA; it confers zero authority.
 */
import { randomUUID } from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { z } from "zod";
import { MEMORY_LIMITS } from "./limits.js";

export const MEMORY_STORE_VERSION = 1 as const;
export const STORE_FILENAME = "memory.json" as const;

export const MemoryRecordSchema = z
  .object({
    v: z.literal(MEMORY_STORE_VERSION),
    id: z.string().min(1).max(64),
    content: z.string().max(MEMORY_LIMITS.MAX_CONTENT_CHARS + 32),
    kind: z.enum(["fact", "preference", "project", "instruction"]),
    createdAt: z.string().datetime(),
    updatedAt: z.string().datetime(),
    source: z.string().min(1).max(64),
    taskId: z.string().min(1).max(128),
    epoch: z.number().int().min(1),
  })
  .strict();

export type MemoryRecord = z.infer<typeof MemoryRecordSchema>;

const StoreFileSchema = z
  .object({
    v: z.literal(MEMORY_STORE_VERSION),
    records: z.array(MemoryRecordSchema).max(MEMORY_LIMITS.MAX_RECORDS),
  })
  .strict();

export interface MemoryStore {
  readonly path: string;
  records: Array<MemoryRecord>;
}

export type StoreOpenResult =
  | { readonly ok: true; readonly store: MemoryStore }
  | { readonly ok: false; readonly reason: string };

/** Mint a trusted unique record ID. Never planner-supplied. */
export function mintMemoryId(): string {
  return `mem-${randomUUID()}`;
}

/** Trusted timestamp. Never planner-supplied. */
export function trustedNow(): string {
  return new Date().toISOString();
}

/**
 * Open (or initialize) the store inside a trusted directory. Any
 * defect — missing version, schema failure, oversized payload —
 * refuses the open so corruption can never become trusted history.
 */
export function openMemoryStore(dir: string): StoreOpenResult {
  try {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    fs.chmodSync(dir, 0o700);
  } catch {
    return { ok: false, reason: "memory directory unavailable" };
  }
  const filePath = path.join(dir, STORE_FILENAME);
  let raw: string;
  try {
    raw = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return { ok: true, store: { path: filePath, records: [] } };
    }
    return { ok: false, reason: "memory file unreadable" };
  }
  let json: unknown;
  try {
    json = JSON.parse(raw) as unknown;
  } catch {
    return { ok: false, reason: "memory file is not valid JSON" };
  }
  const parsed = StoreFileSchema.safeParse(json);
  if (!parsed.success) {
    return { ok: false, reason: "memory file failed schema validation" };
  }
  if (Buffer.byteLength(raw, "utf8") > MEMORY_LIMITS.MAX_TOTAL_STORAGE_BYTES) {
    return { ok: false, reason: "memory file exceeds storage limit" };
  }
  return { ok: true, store: { path: filePath, records: [...parsed.data.records] } };
}

export type StoreSaveResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly reason: string };

/**
 * Atomically persist records. Validates count, per-record size, and
 * total bytes BEFORE touching disk; writes tmp + fsync + rename.
 * Returns failure explicitly — callers roll back in-memory state.
 */
export function saveMemoryStore(store: MemoryStore, records: ReadonlyArray<MemoryRecord>): StoreSaveResult {
  if (records.length > MEMORY_LIMITS.MAX_RECORDS) {
    return { ok: false, reason: "record count exceeds limit" };
  }
  for (const record of records) {
    if (Buffer.byteLength(JSON.stringify(record), "utf8") > MEMORY_LIMITS.MAX_RECORD_SERIALIZED_BYTES) {
      return { ok: false, reason: "record exceeds serialized size limit" };
    }
  }
  const payload = `${JSON.stringify({ v: MEMORY_STORE_VERSION, records: [...records] })}\n`;
  if (Buffer.byteLength(payload, "utf8") > MEMORY_LIMITS.MAX_TOTAL_STORAGE_BYTES) {
    return { ok: false, reason: "storage exceeds total size limit" };
  }
  try {
    const tmp = `${store.path}.tmp-${process.pid}`;
    const fd = fs.openSync(tmp, "w", 0o600);
    try {
      fs.writeFileSync(fd, payload);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.chmodSync(tmp, 0o600);
    fs.renameSync(tmp, store.path);
  } catch {
    return { ok: false, reason: "memory write failed" };
  }
  store.records = [...records];
  return { ok: true };
}
