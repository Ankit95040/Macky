/**
 * Strict operator action schemas (M16). Every operator input is
 * validated here; unknown fields fail closed, nothing is stripped
 * or repaired. IDs reuse the M2/M5 shape convention
 * (documented local copies, not imports, to keep this module's
 * dependency surface minimal).
 */
import { z } from "zod";
import { OPERATOR_LIMITS } from "./limits.js";

const ID_PATTERN = /^[a-z0-9][a-z0-9._-]{0,127}$/i;
const HEX64_PATTERN = /^[0-9a-f]{64}$/i;

export const OperatorGrantSchema = z
  .object({
    taskId: z.string().min(1).max(OPERATOR_LIMITS.MAX_ID_CHARS).regex(ID_PATTERN),
    grantId: z.string().min(1).max(OPERATOR_LIMITS.MAX_ID_CHARS).regex(ID_PATTERN),
    capability: z.string().min(1).max(OPERATOR_LIMITS.MAX_ID_CHARS),
    scope: z.string().max(OPERATOR_LIMITS.MAX_SCOPE_CHARS),
  })
  .strict();

export const OperatorRevokeSchema = z
  .object({
    grantId: z.string().min(1).max(OPERATOR_LIMITS.MAX_ID_CHARS).regex(ID_PATTERN),
  })
  .strict();

export const OperatorConfirmSchema = z
  .object({
    taskId: z.string().min(1).max(OPERATOR_LIMITS.MAX_ID_CHARS).regex(ID_PATTERN),
    capability: z.string().min(1).max(OPERATOR_LIMITS.MAX_ID_CHARS),
    operation: z.string().min(1).max(OPERATOR_LIMITS.MAX_OPERATION_CHARS),
    resource: z.string().max(OPERATOR_LIMITS.MAX_SCOPE_CHARS),
    digest: z.string().regex(HEX64_PATTERN).optional(),
  })
  .strict();

export const OperatorWakeSchema = z
  .object({
    kind: z.enum(["keyboard-shortcut", "ui-action"]),
  })
  .strict();

export const OperatorAuditTailSchema = z
  .object({
    limit: z.number().int().min(1).max(OPERATOR_LIMITS.MAX_AUDIT_TAIL),
  })
  .strict();

export type OperatorGrantInput = z.infer<typeof OperatorGrantSchema>;
export type OperatorRevokeInput = z.infer<typeof OperatorRevokeSchema>;
export type OperatorConfirmInput = z.infer<typeof OperatorConfirmSchema>;
export type OperatorWakeInput = z.infer<typeof OperatorWakeSchema>;
export type OperatorAuditTailInput = z.infer<typeof OperatorAuditTailSchema>;
