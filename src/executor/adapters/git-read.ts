/**
 * Git read-only adapter (M3 section 7).
 *
 * NO arbitrary command strings. The adapter builds git invocations
 * itself from a fixed operation enum; structured parameters (repo path)
 * travel via `cwd`, never via argv. No shell is ever involved.
 *
 * Gate-5 note: this module uses `execFile` (argv execution, no shell),
 * never `exec`/`spawn`/`eval` and never `shell: true`. Running the git
 * binary with fixed argv is exactly what "construct the operation
 * itself from structured parameters" requires; arbitrary commands are
 * structurally impossible — there is no string-command API here.
 *
 * Determinism hardening: fixed allowlisted binary paths (no PATH
 * lookup), GIT_* environment scrubbed, fixed output formats, byte caps,
 * wall-clock timeout. Mutating operations (commit/push/reset/clean/
 * checkout/...) have no entry point in this module.
 */
import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import { LIMITS } from "../limits.js";
import { resolveWithinRoot } from "../paths.js";
import { sanitizeText } from "../sanitize.js";

export type GitOperation = "status" | "log" | "diff";

export type GitAdapterResult =
  | { readonly ok: true; readonly value: unknown; readonly redacted: boolean }
  | { readonly ok: false; readonly reason: string };

const GIT_BINARIES = [
  "/usr/bin/git",
  "/opt/homebrew/bin/git",
  "/usr/local/bin/git",
] as const;

function resolveGitBinary(): string | undefined {
  for (const candidate of GIT_BINARIES) {
    try {
      fs.accessSync(candidate, fs.constants.X_OK);
      const stat = fs.statSync(candidate);
      if (stat.isFile()) {
        return candidate;
      }
    } catch {
      continue;
    }
  }
  return undefined;
}

/** Scrubbed environment: caller GIT_* config cannot alter behavior. */
function gitEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (value === undefined) {
      continue;
    }
    if (key.startsWith("GIT_")) {
      continue;
    }
    env[key] = value;
  }
  env["GIT_PAGER"] = "cat";
  env["PAGER"] = "cat";
  env["GIT_TERMINAL_PROMPT"] = "0";
  env["LC_ALL"] = "C";
  return env;
}

function fail(reason: string): GitAdapterResult {
  return { ok: false, reason };
}

function runGitFixed(argv: ReadonlyArray<string>, cwd: string): Buffer {
  const binary = resolveGitBinary();
  if (binary === undefined) {
    throw new Error("no allowlisted git binary available");
  }
  return execFileSync(binary, [...argv], {
    cwd,
    env: gitEnv(),
    timeout: LIMITS.EXEC_TIMEOUT_MS,
    maxBuffer: LIMITS.GIT_MAX_BYTES + 4096,
  });
}

function checkBytes(out: Buffer): string | undefined {
  if (out.byteLength > LIMITS.GIT_MAX_BYTES) {
    return `git output exceeds limit (${LIMITS.GIT_MAX_BYTES} bytes)`;
  }
  return undefined;
}

export interface GitStatusEntry {
  readonly code: string;
  readonly path: string;
}

function parseStatusZ(out: string): Array<GitStatusEntry> {
  const entries: Array<GitStatusEntry> = [];
  const parts = out.split("\0");
  for (let i = 0; i < parts.length; i += 1) {
    const head = parts[i] ?? "";
    if (head.length === 0) {
      continue;
    }
    const code = head.slice(0, 2);
    const file = head.slice(3);
    if (code.startsWith("R") || code.startsWith("C")) {
      const target = parts[i + 1] ?? "";
      i += 1;
      entries.push({ code, path: `${file} -> ${target}` });
    } else {
      entries.push({ code, path: file });
    }
  }
  return entries;
}

export interface GitLogEntry {
  readonly hash: string;
  readonly author: string;
  readonly date: string;
  readonly subject: string;
}

function parseLog(out: string): Array<GitLogEntry> {
  const entries: Array<GitLogEntry> = [];
  for (const line of out.split("\n")) {
    if (line.length === 0) {
      continue;
    }
    const fields = line.split("\x00");
    if (fields.length !== 4) {
      continue;
    }
    const [hash, author, date, subject] = fields as [
      string,
      string,
      string,
      string,
    ];
    entries.push({ hash, author, date, subject });
  }
  return entries;
}

const FIXED_ARGV: Record<GitOperation, ReadonlyArray<string>> = {
  status: ["status", "--porcelain=v1", "-z", "--untracked-files=normal", "--"],
  log: [
    "log",
    `--max-count=${LIMITS.GIT_MAX_COMMITS}`,
    "--no-color",
    "--no-decorate",
    "--date=iso",
    "--format=%H%x00%an%x00%ad%x00%s",
    "--",
  ],
  diff: ["diff", "--no-color", "--no-ext-diff", "--no-textconv", "--", "."],
};

/**
 * Run one fixed read-only git operation in an authorized repo path.
 * `root` is the authorized grant root; `repoPath` must resolve inside
 * it and contain a `.git` dir or worktree file.
 */
export function runGitRead(
  root: string,
  repoPath: unknown,
  operation: GitOperation,
): GitAdapterResult {
  const resolution = resolveWithinRoot(root, repoPath);
  if (!resolution.ok) {
    return fail(resolution.reason);
  }
  const real = resolution.resolved.real;
  try {
    const dotgit = fs.statSync(`${real}/.git`);
    if (!dotgit.isDirectory() && !dotgit.isFile()) {
      return fail("not a git repository");
    }
  } catch {
    return fail("not a git repository");
  }

  let out: Buffer;
  try {
    out = runGitFixed(FIXED_ARGV[operation], real);
  } catch {
    return fail("git operation failed");
  }
  const over = checkBytes(out);
  if (over !== undefined) {
    return fail(over);
  }
  const text = out.toString("utf8");
  if (operation === "status") {
    return { ok: true, value: Object.freeze(parseStatusZ(text)), redacted: false };
  }
  if (operation === "log") {
    return { ok: true, value: Object.freeze(parseLog(text)), redacted: false };
  }
  const sanitized = sanitizeText(text);
  if (!sanitized.ok) {
    return fail(sanitized.reason);
  }
  return { ok: true, value: sanitized.text, redacted: sanitized.redacted };
}
