/**
 * M17 entry point. Argument parsing + dispatch only — all authority
 * lives in the M16 funnel and the M2 kernel. No auto-execution on
 * import: tests call runCommand(); processes call main().
 */
export * from "./args.js";
export * from "./commands.js";

import { parseArgv, type ArgvRefusal, type ParsedArgs } from "./args.js";
import { runCommand, type TalkDeps } from "./commands.js";

function isRefusal(parsed: ParsedArgs | ArgvRefusal): parsed is ArgvRefusal {
  return "ok" in parsed && parsed.ok === false;
}

export async function main(argv: ReadonlyArray<string>, stateDir?: string, deps?: TalkDeps): Promise<number> {
  const parsed = parseArgv(argv);
  if (isRefusal(parsed)) {
    console.log(`usage refused: ${parsed.reason}`);
    return 2;
  }
  const result = await runCommand(parsed, stateDir, deps);
  console.log(result.output);
  return result.exitCode;
}
