/**
 * Supervisor wire protocol (M18). Length-prefixed JSON, strict
 * schemas, read-only operations ONLY (status, audit). Any unknown
 * operation, unknown field, oversized frame, or malformed byte
 * fails closed. Authority-bearing fields cannot exist here by
 * construction — the schemas have nowhere to put them.
 */
import { z } from "zod";

export const SUPERVISOR_PROTOCOL_VERSION = 1 as const;

/** Max single frame (request or response) on the wire. */
export const MAX_FRAME_BYTES = 64 * 1024;
/** Max response payload. */
export const MAX_RESPONSE_BYTES = 256 * 1024;

export const SupervisorRequestSchema = z.union([
  z.object({ v: z.literal(SUPERVISOR_PROTOCOL_VERSION), op: z.literal("status") }).strict(),
  z.object({
    v: z.literal(SUPERVISOR_PROTOCOL_VERSION),
    op: z.literal("audit"),
    limit: z.number().int().min(1).max(100).optional(),
  }).strict(),
]);

export type SupervisorRequest = z.infer<typeof SupervisorRequestSchema>;

export const SupervisorResponseSchema = z
  .object({
    v: z.literal(SUPERVISOR_PROTOCOL_VERSION),
    ok: z.boolean(),
    result: z.unknown().optional(),
    error: z.string().max(256).optional(),
  })
  .strict();

export type SupervisorResponse = z.infer<typeof SupervisorResponseSchema>;

/** Encode one frame: 4-byte big-endian length + UTF-8 JSON. */
export function encodeFrame(value: unknown): Buffer {
  const body = Buffer.from(JSON.stringify(value), "utf8");
  if (body.length > MAX_FRAME_BYTES) {
    throw new Error("frame exceeds size limit");
  }
  const header = Buffer.alloc(4);
  header.writeUInt32BE(body.length, 0);
  return Buffer.concat([header, body]);
}

export interface FrameDecode {
  readonly frames: ReadonlyArray<unknown>;
  readonly rest: Buffer;
  readonly error?: string;
}

/**
 * Pull complete frames off a byte stream. Returns leftover bytes for
 * the next read. Declared lengths over the cap are an error (never
 * allocate blindly); trailing garbage is left for the caller, which
 * treats any protocol violation as connection-fatal.
 */
export function decodeFrames(buffer: Buffer): FrameDecode {
  const frames: Array<unknown> = [];
  let rest = buffer;
  for (;;) {
    if (rest.length < 4) {
      return { frames: Object.freeze(frames), rest };
    }
    const declared = rest.readUInt32BE(0);
    if (declared > MAX_FRAME_BYTES) {
      return { frames: Object.freeze(frames), rest: Buffer.alloc(0), error: "frame too large" };
    }
    if (rest.length < 4 + declared) {
      return { frames: Object.freeze(frames), rest };
    }
    const body = rest.subarray(4, 4 + declared);
    rest = rest.subarray(4 + declared);
    try {
      frames.push(JSON.parse(body.toString("utf8")) as unknown);
    } catch {
      return { frames: Object.freeze(frames), rest: Buffer.alloc(0), error: "malformed frame" };
    }
  }
}
