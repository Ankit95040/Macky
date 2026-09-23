/**
 * Durable trusted security state (M4 sections 1/11/12).
 *
 * Minimal by design: only what safe restart behavior requires.
 * Deliberately NOT persisted: sleep detail (boot always sleeps),
 * kill-switch engagement (key is process-local; see M4 doc §13),
 * grants/confirmations (re-issued per epoch), prompts, memory,
 * secrets, tasks. This module is file I/O for ONE small JSON file;
 * validation is strict Zod — arbitrary JSON never becomes trusted.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { z } from "zod";

export const SECURITY_STATE_VERSION = 1 as const;

export const SecurityStateSchema = z
  .object({
    schemaVersion: z.literal(SECURITY_STATE_VERSION),
    epoch: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
  })
  .strict();

export type SecurityState = z.infer<typeof SecurityStateSchema>;

/** First-boot state. Epochs start at 1 and only increase. */
export function defaultSecurityState(): SecurityState {
  return { schemaVersion: SECURITY_STATE_VERSION, epoch: 1 };
}

/** Parse untrusted persisted bytes. Undefined on ANY defect. */
export function parseSecurityState(raw: unknown): SecurityState | undefined {
  const parsed = SecurityStateSchema.safeParse(raw);
  if (!parsed.success) {
    return undefined;
  }
  return parsed.data;
}

/** Next epoch for a valid loaded state. Throws at the integer ceiling. */
export function nextEpochState(loaded: SecurityState): SecurityState {
  if (loaded.epoch >= Number.MAX_SAFE_INTEGER) {
    throw new Error("security epoch exhausted: refuse boot");
  }
  return { schemaVersion: SECURITY_STATE_VERSION, epoch: loaded.epoch + 1 };
}

export type StateLoadResult =
  | { readonly status: "missing" }
  | { readonly status: "loaded"; readonly state: SecurityState }
  | { readonly status: "invalid"; readonly reason: string };

/** Read + parse the state file. Never throws, never guesses. */
export function loadStateFile(statePath: string): StateLoadResult {
  let raw: string;
  try {
    raw = fs.readFileSync(statePath, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return { status: "missing" };
    }
    return { status: "invalid", reason: "state file unreadable" };
  }
  let json: unknown;
  try {
    json = JSON.parse(raw) as unknown;
  } catch {
    return { status: "invalid", reason: "state file is not valid JSON" };
  }
  const state = parseSecurityState(json);
  if (state === undefined) {
    return { status: "invalid", reason: "state failed schema validation" };
  }
  return { status: "loaded", state };
}

/**
 * Crash-safe save: write temp file + fsync + atomic rename + 0o600.
 * Throws on failure (caller fails closed). No merge, no partial update.
 */
export function saveStateFile(statePath: string, state: SecurityState): void {
  const dir = path.dirname(statePath);
  const tmp = `${statePath}.tmp-${process.pid}`;
  const payload = `${JSON.stringify(state)}\n`;
  const fd = fs.openSync(tmp, "w", 0o600);
  try {
    fs.writeFileSync(fd, payload);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.chmodSync(tmp, 0o600);
  fs.renameSync(tmp, statePath);
}
