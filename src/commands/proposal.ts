/**
 * Versioned command proposal schema (M8 section 4). Structured data —
 * never a shell string. The planner names a registered commandId plus
 * inert argv; every trusted control (risk, approval, grants,
 * confirmation, environment, timeout, policy, executable path) is
 * absent from the schema, so supplying any of it fails validation.
 * Dangerous argv CONTENT is rejected here (shape level); arity and
 * command-specific rules live in the classifier.
 */
import { z } from "zod";
import { COMMAND_LIMITS } from "./limits.js";

export const COMMAND_PROPOSAL_VERSION = 1 as const;

const WORKSPACE_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{0,127}$/i;

/**
 * Characters with shell meaning are refused outright — no stripping,
 * no repair. `/` is refused because none of the M8 commands take
 * paths (kills absolute paths and traversal in one rule); leading
 * `-` is refused (option injection).
 */
const FORBIDDEN_ARG_CHARS = new Set(["|", "&", ";", ">", "<", "$", "`", "\n", "\r", "\0", "(", ")", "*", "?", "[", "]", "{", "}", "~", "#", "!", "\\", "/"]);

/**
 * M13 reuse: the exact shell-meaning character set, shared (not
 * duplicated) so speech text validation cannot drift weaker than the
 * terminal policy. Pure predicate, no I/O.
 */
export function containsForbiddenShellChar(text: string): boolean {
  for (const ch of text) {
    if (FORBIDDEN_ARG_CHARS.has(ch)) {
      return true;
    }
  }
  return false;
}

function argShapeOk(arg: string): boolean {
  if (Array.from(arg).length > COMMAND_LIMITS.MAX_ARG_CHARS) {
    return false;
  }
  if (arg.startsWith("-")) {
    return false;
  }
  for (const ch of arg) {
    if (FORBIDDEN_ARG_CHARS.has(ch)) {
      return false;
    }
  }
  return true;
}

export const CommandProposalSchema = z
  .object({
    v: z.literal(COMMAND_PROPOSAL_VERSION),
    operation: z.literal("command-exec"),
    commandId: z.string().min(1).max(128),
    workspaceId: z.string().min(1).max(128).regex(WORKSPACE_ID_PATTERN),
    cwd: z.string().min(1).max(1024).optional(),
    argv: z.array(z.string().max(COMMAND_LIMITS.MAX_ARG_CHARS + 16)).max(COMMAND_LIMITS.MAX_ARGV_COUNT).optional(),
  })
  .strict()
  .superRefine((p, ctx) => {
    for (const arg of p.argv ?? []) {
      if (!argShapeOk(arg)) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: "argv rejected: unsafe argument" });
        break;
      }
    }
    if (p.cwd !== undefined && p.cwd.includes("\0")) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "cwd contains NUL byte" });
    }
  });

export type CommandProposal = z.infer<typeof CommandProposalSchema>;
