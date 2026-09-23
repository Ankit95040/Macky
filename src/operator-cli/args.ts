/**
 * Strict argv parsing (M17). CLI argv is UNTRUSTED: unknown commands,
 * unknown flags, duplicates, oversized values, and malformed shapes
 * all fail closed. Nothing is stripped, repaired, or normalized into
 * an accepted command. Only three commands exist: status, audit, talk.
 */
import { z } from "zod";
import { OPERATOR_LIMITS } from "../operator/limits.js";

export const MAX_ARGV_ARGS = 8;
export const MAX_ARGV_ARG_CHARS = 256;

const AuditArgsSchema = z
  .object({
    command: z.literal("audit"),
    limit: z.number().int().min(1).max(OPERATOR_LIMITS.MAX_AUDIT_TAIL).optional(),
  })
  .strict();

export type ParsedArgs =
  | { readonly kind: "status" }
  | { readonly kind: "audit"; readonly limit: number }
  | { readonly kind: "talk" };

export type ArgvRefusal = { readonly ok: false; readonly reason: string };
function boundedArgs(argv: ReadonlyArray<string>): boolean {
  if (argv.length > MAX_ARGV_ARGS) {
    return false;
  }
  return argv.every((a) => typeof a === "string" && a.length <= MAX_ARGV_ARG_CHARS);
}

/**
 * Parse `macky <args>`: `status`, `audit [--limit N]`, `talk`.
 * `audit` defaults to 20 entries. Returns a refusal for anything else.
 */
export function parseArgv(argv: ReadonlyArray<string>): ParsedArgs | ArgvRefusal {
  if (!Array.isArray(argv) || !boundedArgs(argv)) {
    return { ok: false, reason: "argv rejected" };
  }
  const [command, ...rest] = argv as [string?, ...Array<string>];
  if (command === "status") {
    return rest.length === 0 ? { kind: "status" } : { ok: false, reason: "status takes no arguments" };
  }
  if (command === "talk") {
    return rest.length === 0 ? { kind: "talk" } : { ok: false, reason: "talk takes no arguments" };
  }
  if (command === "audit") {
    let limit = 20;
    let seenLimit = false;
    for (let i = 0; i < rest.length; i += 1) {
      const token = rest[i] as string;
      if (token === "--limit") {
        if (seenLimit) {
          return { ok: false, reason: "duplicate --limit" };
        }
        seenLimit = true;
        const raw = rest[i + 1];
        if (raw === undefined || !/^[0-9]+$/.test(raw)) {
          return { ok: false, reason: "malformed --limit value" };
        }
        limit = Number(raw);
        i += 1;
        continue;
      }
      return { ok: false, reason: `unknown audit argument: ${token.slice(0, 32)}` };
    }
    const parsed = AuditArgsSchema.safeParse({ command: "audit", limit });
    if (!parsed.success) {
      return { ok: false, reason: "audit limit out of range" };
    }
    return { kind: "audit", limit: parsed.data.limit ?? 20 };
  }
  return { ok: false, reason: "unknown command" };
}
