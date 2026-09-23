/**
 * Deterministic bootstrap configuration (M4 section 16).
 *
 * Trusted local configuration only: state directory, audit path,
 * security-state path, schema versions. NEVER planner-controlled —
 * no field here is derivable from any request. A minimal override
 * (explicit function argument or MACKY_STATE_DIR) selects the directory;
 * everything inside it is derived deterministically.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

export const CONFIG_VERSION = 1 as const;
export const DEFAULT_STATE_DIRNAME = ".macky" as const;
export const AUDIT_FILENAME = "audit.jsonl" as const;
export const STATE_FILENAME = "security-state.json" as const;

export interface MackyConfig {
  readonly configVersion: number;
  readonly stateDir: string;
  readonly auditPath: string;
  readonly statePath: string;
}

/**
 * Resolve trusted configuration. Throws on invalid directory input —
 * boot fails closed rather than guessing a location.
 */
export function resolveConfig(stateDirOverride?: string): MackyConfig {
  const raw =
    stateDirOverride ?? process.env["MACKY_STATE_DIR"] ?? path.join(os.homedir(), DEFAULT_STATE_DIRNAME);
  if (typeof raw !== "string" || raw.length === 0 || raw.includes("\0")) {
    throw new Error("invalid state directory");
  }
  if (!path.isAbsolute(raw)) {
    throw new Error("state directory must be absolute");
  }
  const stateDir = path.normalize(raw);
  return {
    configVersion: CONFIG_VERSION,
    stateDir,
    auditPath: path.join(stateDir, AUDIT_FILENAME),
    statePath: path.join(stateDir, STATE_FILENAME),
  };
}

/** Create the state dir user-private (0o700). Throws on failure. */
export function ensureStateDir(config: MackyConfig): void {
  fs.mkdirSync(config.stateDir, { recursive: true, mode: 0o700 });
  fs.chmodSync(config.stateDir, 0o700);
}
