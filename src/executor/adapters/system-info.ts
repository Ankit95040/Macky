/**
 * system.info adapter (M3 section 8). Explicit structured fields only.
 * Never the process environment, never arbitrary files, never shell.
 */
import * as os from "node:os";

export interface SystemInfo {
  readonly os: string;
  readonly osVersion: string;
  readonly architecture: string;
  readonly hostname: string;
  readonly runtime: string;
}

const KEYS: ReadonlyArray<keyof SystemInfo> = Object.freeze([
  "os",
  "osVersion",
  "architecture",
  "hostname",
  "runtime",
]);

export function systemInfoKeys(): ReadonlyArray<string> {
  return KEYS as ReadonlyArray<string>;
}

export function readSystemInfo(): SystemInfo {
  return Object.freeze({
    os: os.platform(),
    osVersion: os.release(),
    architecture: os.arch(),
    hostname: os.hostname(),
    runtime: process.version,
  });
}
