/**
 * Durable append-only audit store (M4 sections 4–10).
 *
 * Format: JSON Lines, one canonical event per line, hash-chained.
 * Each event commits to the previous event's hash (tamper EVIDENCE,
 * not prevention — a privileged local attacker can still delete the
 * file; deletion is detectable by absence, not by crypto).
 *
 * Single-writer model: one Macky process owns the directory. Appends
 * use O_APPEND + fsync, so same-process sequential appends are safe;
 * concurrent multi-process writers are out of scope and documented.
 *
 * Rotation: NOT implemented in M4. A full audit file refuses new
 * persistence (`audit-full`) rather than destroying history (§10).
 * Zod validates every event before persistence; malformed input never
 * enters the stream. Secrets are redacted before write.
 */
import { createHash } from "node:crypto";
import * as fs from "node:fs";
import { z } from "zod";
import { redactSecrets } from "../kernel/audit.js";
import type { SleepState } from "../kernel/types.js";

export const AUDIT_FORMAT_VERSION = 1 as const;
export const GENESIS_PREV_HASH = "GENESIS" as const;

/** Conservative for a 13 GB-free MacBook; documented in M4 doc. */
export const AUDIT_LIMITS = {
  MAX_AUDIT_FILE_BYTES: 5 * 1024 * 1024,
  MAX_EVENT_BYTES: 4096,
  MAX_DETAIL_BYTES: 2048,
} as const;

export const DurableAuditEventSchema = z
  .object({
    v: z.literal(AUDIT_FORMAT_VERSION),
    seq: z.number().int().min(1),
    ts: z.string().datetime(),
    epoch: z.number().int().min(1),
    type: z.string().min(1).max(128),
    detail: z.string().max(AUDIT_LIMITS.MAX_DETAIL_BYTES),
    sleep: z.enum(["SLEEP", "AWAKE"]),
    prevHash: z.string().min(1),
    hash: z.string().min(1),
  })
  .strict();

export type DurableAuditEvent = z.infer<typeof DurableAuditEventSchema>;

const DurableAuditInputSchema = z
  .object({
    type: z.string().min(1).max(128),
    detail: z.string(),
    epoch: z.number().int().min(1),
    sleep: z.enum(["SLEEP", "AWAKE"]),
  })
  .strict();

export interface AuditEventInput {
  readonly type: string;
  readonly detail: string;
  readonly epoch: number;
  readonly sleep: SleepState;
}

/** Mutable single-writer cursor. Process-lifetime handle, not authority. */
export interface AuditSink {
  readonly path: string;
  nextSeq: number;
  prevHash: string;
}

function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

/** Canonical bytes the hash commits to (fixed key order, no hash field). */
function canonicalBytes(event: Omit<DurableAuditEvent, "hash">): string {
  return JSON.stringify({
    v: event.v,
    seq: event.seq,
    ts: event.ts,
    epoch: event.epoch,
    type: event.type,
    detail: event.detail,
    sleep: event.sleep,
    prevHash: event.prevHash,
  });
}

function hashFor(event: Omit<DurableAuditEvent, "hash">): string {
  return sha256Hex(canonicalBytes(event));
}

export type SinkOpenResult =
  | { readonly ok: true; readonly sink: AuditSink }
  | { readonly ok: false; readonly reason: string };

/**
 * Open (or initialize) the sink. An existing file is FULLY verified;
 * any defect refuses the open so a corrupt log can never silently
 * become the trusted stream. Missing file starts a fresh chain.
 */
export function openAuditSink(filePath: string): SinkOpenResult {
  let raw: string;
  try {
    raw = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return { ok: true, sink: { path: filePath, nextSeq: 1, prevHash: GENESIS_PREV_HASH } };
    }
    return { ok: false, reason: "audit file unreadable" };
  }
  const verification = verifyAuditContent(raw);
  if (!verification.ok) {
    return { ok: false, reason: `audit file corrupt: ${verification.errors[0] ?? "unknown"}` };
  }
  const last = verification.events[verification.events.length - 1];
  return {
    ok: true,
    sink: {
      path: filePath,
      nextSeq: verification.events.length + 1,
      prevHash: last !== undefined ? last.hash : GENESIS_PREV_HASH,
    },
  };
}

export type AuditAppendResult =
  | { readonly ok: true; readonly seq: number }
  | { readonly ok: false; readonly reason: string };

/**
 * Append one event. Validates, redacts, enforces size caps, writes with
 * O_APPEND + fsync. Never overwrites, never deletes. Returns
 * persistence failure explicitly — callers must NOT pretend success.
 */
export function appendAuditEvent(
  sink: AuditSink,
  input: AuditEventInput,
): AuditAppendResult {
  const parsed = DurableAuditInputSchema.safeParse(input);
  if (!parsed.success) {
    return { ok: false, reason: "malformed audit input rejected" };
  }
  const detail = redactSecrets(parsed.data.detail);
  if (detail.length > AUDIT_LIMITS.MAX_DETAIL_BYTES) {
    return { ok: false, reason: "audit detail exceeds size limit" };
  }
  const body = {
    v: AUDIT_FORMAT_VERSION,
    seq: sink.nextSeq,
    ts: new Date().toISOString(),
    epoch: parsed.data.epoch,
    type: parsed.data.type,
    detail,
    sleep: parsed.data.sleep,
    prevHash: sink.prevHash,
  };
  const event: DurableAuditEvent = { ...body, hash: hashFor(body) };
  const line = `${JSON.stringify(event)}\n`;
  if (Buffer.byteLength(line, "utf8") > AUDIT_LIMITS.MAX_EVENT_BYTES) {
    return { ok: false, reason: "audit event exceeds size limit" };
  }
  try {
    const current = fs.existsSync(sink.path)
      ? fs.statSync(sink.path).size
      : 0;
    if (current + Buffer.byteLength(line, "utf8") > AUDIT_LIMITS.MAX_AUDIT_FILE_BYTES) {
      return { ok: false, reason: "audit-full: refusing to destroy history" };
    }
    const fd = fs.openSync(sink.path, "a", 0o600);
    try {
      fs.writeFileSync(fd, line);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.chmodSync(sink.path, 0o600);
  } catch {
    return { ok: false, reason: "audit write failed" };
  }
  sink.nextSeq += 1;
  sink.prevHash = event.hash;
  return { ok: true, seq: event.seq };
}

export interface AuditVerification {
  readonly ok: boolean;
  readonly events: ReadonlyArray<DurableAuditEvent>;
  readonly errors: ReadonlyArray<string>;
}

/** Verify raw file content: parse, schema, chain, sequence. */
export function verifyAuditContent(raw: string): AuditVerification {
  const events: Array<DurableAuditEvent> = [];
  const errors: Array<string> = [];
  const lines = raw.split("\n");
  // A well-formed file ends with exactly one trailing newline; a missing
  // or extra trailing fragment means a partial final record.
  const hasTrailingNewline = raw.length === 0 || raw.endsWith("\n");
  const body = hasTrailingNewline ? lines.slice(0, -1) : lines;
  if (!hasTrailingNewline && raw.length > 0) {
    errors.push(`partial final record at line ${body.length}`);
  }
  let expectedPrev: string = GENESIS_PREV_HASH;
  let expectedSeq = 1;
  body.forEach((line, index) => {
    const lineNo = index + 1;
    if (line.length === 0) {
      errors.push(`empty line ${lineNo}`);
      return;
    }
    let json: unknown;
    try {
      json = JSON.parse(line) as unknown;
    } catch {
      errors.push(`malformed JSON at line ${lineNo}`);
      return;
    }
    const parsed = DurableAuditEventSchema.safeParse(json);
    if (!parsed.success) {
      errors.push(`schema-invalid event at line ${lineNo}`);
      return;
    }
    const event = parsed.data;
    if (event.seq !== expectedSeq) {
      errors.push(`sequence discontinuity at line ${lineNo}: want ${expectedSeq}, got ${event.seq}`);
    }
    if (event.prevHash !== expectedPrev) {
      errors.push(`broken chain at line ${lineNo}`);
    }
    const { hash, ...rest } = event;
    if (hashFor(rest) !== hash) {
      errors.push(`broken hash at line ${lineNo}`);
    }
    expectedPrev = event.hash;
    expectedSeq = event.seq + 1;
    events.push(event);
  });
  return { ok: errors.length === 0, events: Object.freeze(events), errors: Object.freeze(errors) };
}

/** Verify the audit file at rest. Missing file is an error (not empty). */
export function verifyAuditFile(filePath: string): AuditVerification {
  let raw: string;
  try {
    raw = fs.readFileSync(filePath, "utf8");
  } catch {
    return { ok: false, events: [], errors: ["audit file unreadable"] };
  }
  return verifyAuditContent(raw);
}

/**
 * EXPLICIT operator repair only: keep the first `keepCount` lines,
 * fsync, and return. Never called automatically — boot fails closed on
 * corruption, and recovery requires this deliberate act (tested).
 */
export function repairAuditToPrefix(filePath: string, keepCount: number): void {
  const raw = fs.readFileSync(filePath, "utf8");
  const lines = raw.split("\n");
  const body = raw.endsWith("\n") || raw.length === 0 ? lines.slice(0, -1) : lines;
  if (keepCount < 0 || keepCount > body.length) {
    throw new Error("repair count out of range");
  }
  const kept = body.slice(0, keepCount);
  const payload = kept.length > 0 ? `${kept.join("\n")}\n` : "";
  const fd = fs.openSync(filePath, "w", 0o600);
  try {
    fs.writeFileSync(fd, payload);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.chmodSync(filePath, 0o600);
}
