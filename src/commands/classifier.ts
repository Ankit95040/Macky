/**
 * Trusted deterministic classifier (M8 section 17). Classifies from
 * the registry ONLY: id → definition (capability, tier, confirmation).
 * Unknown ids deny; denylisted ids deny as Tier3; planner-supplied
 * risk/capability/executable/confirmation/timeout never exist in the
 * proposal schema, so they cannot even reach this function.
 *
 * argv rules per command style (after the schema's global metachar
 * rejection): `none` takes nothing, `text` takes bounded innocent
 * strings, `printf` additionally constrains argv[0] to safe formats
 * (%s/%d/%% — `%n` would be a memory write and is refused).
 */
import { COMMAND_LIMITS } from "./limits.js";
import { getAllowedCommand, isDeniedCommand, type CommandDefinition } from "./registry.js";

export type Classification =
  | { readonly kind: "allowed"; readonly definition: CommandDefinition }
  | { readonly kind: "tier3"; readonly commandId: string; readonly reason: string }
  | { readonly kind: "unknown"; readonly commandId: string };

export function classify(commandId: string): Classification {
  const definition = getAllowedCommand(commandId);
  if (definition !== undefined) {
    return { kind: "allowed", definition };
  }
  if (isDeniedCommand(commandId)) {
    return { kind: "tier3", commandId, reason: `command "${commandId}" is Tier3: permanently denied` };
  }
  return { kind: "unknown", commandId };
}

const PRINTF_SAFE_FORMAT = /^([%][sd%]|[^%])*$/;

export function validateArgv(
  definition: CommandDefinition,
  argv: ReadonlyArray<string>,
): { readonly ok: true; readonly argv: ReadonlyArray<string> } | { readonly ok: false; readonly reason: string } {
  if (argv.length > COMMAND_LIMITS.MAX_ARGV_COUNT) {
    return { ok: false, reason: "too many arguments" };
  }
  let bytes = 0;
  for (const arg of argv) {
    bytes += Buffer.byteLength(arg, "utf8");
  }
  if (bytes > COMMAND_LIMITS.MAX_ARGV_BYTES) {
    return { ok: false, reason: "argv exceeds byte limit" };
  }
  switch (definition.argStyle) {
    case "none":
      return argv.length === 0
        ? { ok: true, argv }
        : { ok: false, reason: "command takes no arguments" };
    case "text":
      return argv.length >= 1 && argv.length <= COMMAND_LIMITS.MAX_ARGV_COUNT
        ? { ok: true, argv }
        : { ok: false, reason: "text command needs 1+ arguments" };
    case "printf": {
      if (argv.length < 1) {
        return { ok: false, reason: "printf needs a format argument" };
      }
      const format = argv[0] as string;
      if (!PRINTF_SAFE_FORMAT.test(format)) {
        return { ok: false, reason: "printf format restricted to %s/%d/%%" };
      }
      return { ok: true, argv };
    }
  }
}
