/**
 * Structured Action Request (M2 deliverable 1).
 *
 * The untrusted planner proposes actions using this shape and NOTHING
 * else. There is deliberately NO field for executable code, risk tier,
 * approval flags, confirmation tokens, or policy directives: the Zod
 * schema is `.strict()`, so any forged field (approved, risk,
 * confirmedBy, confirmationToken, ...) fails validation and the
 * request fails closed to DENY.
 *
 * Pure data + validation only. No I/O, no OS APIs.
 */
import { z } from "zod";

const ID_PATTERN = /^[a-z0-9][a-z0-9._-]{0,127}$/i;

/**
 * External representation of one proposed action. Minimum information
 * needed for authorization: capability id, operation, resource/scope
 * where applicable, task/request binding, inert metadata only.
 */
export const ActionRequestSchema = z
  .object({
    capability: z.string().min(1).max(128),
    operation: z.string().min(1).max(64),
    resource: z.string().min(1).max(512).optional(),
    taskId: z.string().min(1).max(128).optional(),
    requestId: z.string().min(1).max(128).optional(),
    metadata: z.record(z.string(), z.string()).optional(),
    // M7: bounded per-operation parameters (e.g. find pattern, search
    // query). Opaque to authorization — each adapter validates exactly
    // the keys it understands and refuses anything else.
    params: z.record(z.string().min(1).max(32), z.string().max(256)).optional(),
  })
  .strict()
  .superRefine((req, ctx) => {
    if (req.taskId !== undefined && !ID_PATTERN.test(req.taskId)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "taskId has invalid shape",
      });
    }
    if (req.requestId !== undefined && !ID_PATTERN.test(req.requestId)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "requestId has invalid shape",
      });
    }
    if (req.metadata !== undefined) {
      const keys = Object.keys(req.metadata);
      if (keys.length > 16) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "metadata exceeds 16 entries",
        });
      }
      for (const key of keys) {
        if (key.length > 64 || (req.metadata[key] ?? "").length > 256) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: "metadata entry exceeds size limits",
          });
          break;
        }
      }
    }
    if (req.resource !== undefined && req.resource.includes("\0")) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "resource contains NUL byte",
      });
    }
    if (req.params !== undefined && Object.keys(req.params).length > 8) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "params exceeds 8 entries",
      });
    }
  });

export type ActionRequest = z.infer<typeof ActionRequestSchema>;
