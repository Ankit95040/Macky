/**
 * Trusted command registry (M8 sections 5/17/18). Maps logical command
 * IDs (the ONLY thing a planner may name) to exact executable paths,
 * argv rules, capabilities, tiers, and confirmation requirements.
 *
 * Five allowed commands, all Tier0 except `command.id` (Tier2:
 * identity/group exposure is human-gated). Tier3 is represented by an
 * explicit denylist PLUS default-deny: denied ids can never authorize
 * because they have no M2 capability, no adapter, and the classifier
 * refuses them before authorization is even attempted.
 */
import type { RiskTier } from "../kernel/capability-model.js";

export type ArgStyle = "none" | "text" | "printf";

export interface CommandDefinition {
  readonly id: string;
  /** Exact executable. Never resolved via PATH, never from planner input. */
  readonly executable: string;
  readonly argStyle: ArgStyle;
  readonly capability: string;
  readonly riskTier: RiskTier;
  readonly requiresConfirmation: boolean;
  readonly description: string;
}

function allowed(d: CommandDefinition): CommandDefinition {
  return Object.freeze(d);
}

export const ALLOWED_COMMANDS: ReadonlyArray<CommandDefinition> = Object.freeze([
  allowed({
    id: "command.echo",
    executable: "/bin/echo",
    argStyle: "text",
    capability: "command.echo",
    riskTier: 0,
    requiresConfirmation: false,
    description: "Fixed echo: formats validated text argv to stdout. No side effects.",
  }),
  allowed({
    id: "command.printf",
    executable: "/usr/bin/printf",
    argStyle: "printf",
    capability: "command.printf",
    riskTier: 0,
    requiresConfirmation: false,
    description: "Fixed printf: first argv is a safe format (%s/%d/%% only — never %n).",
  }),
  allowed({
    id: "command.whoami",
    executable: "/usr/bin/whoami",
    argStyle: "none",
    capability: "command.whoami",
    riskTier: 0,
    requiresConfirmation: false,
    description: "Fixed whoami: no argv accepted.",
  }),
  allowed({
    id: "command.pwd",
    executable: "/bin/pwd",
    argStyle: "none",
    capability: "command.pwd",
    riskTier: 0,
    requiresConfirmation: false,
    description: "Fixed pwd: no argv accepted.",
  }),
  allowed({
    id: "command.id",
    executable: "/usr/bin/id",
    argStyle: "none",
    capability: "command.id",
    riskTier: 2,
    requiresConfirmation: true,
    description: "Fixed id: exposes uid/gid/groups — Tier2, human approval required.",
  }),
]);

/** Explicit Tier3 denylist (defense in depth over default-deny). */
export const DENIED_COMMAND_IDS: ReadonlyArray<string> = Object.freeze([
  "shell.sh",
  "shell.bash",
  "shell.zsh",
  "priv.sudo",
  "priv.su",
  "fs.rm",
  "fs.mv",
  "fs.cp",
  "fs.mkdir",
  "fs.touch",
  "fs.ln",
  "fs.chmod",
  "fs.chown",
  "net.curl",
  "net.wget",
  "net.nc",
  "net.ssh",
  "vcs.git",
  "pkg.npm",
  "pkg.npx",
  "pkg.pip",
  "lang.python",
  "lang.node",
  "lang.ruby",
  "lang.perl",
  "mac.osascript",
]);

export function getAllowedCommand(id: string): CommandDefinition | undefined {
  return ALLOWED_COMMANDS.find((d) => d.id === id);
}

export function isDeniedCommand(id: string): boolean {
  return DENIED_COMMAND_IDS.includes(id);
}
