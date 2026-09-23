/**
 * Filesystem read-only adapter (M3 sections 3/4/6).
 *
 * Operations: list (single level, never recursive), read (bounded).
 * No writes, no delete/rename/move/chmod/symlink manipulation — those
 * entry points do not exist in this module.
 *
 * Every path is resolved through resolveWithinRoot against the
 * caller-supplied authorized root, then size-checked BEFORE reading.
 * Over-limit reads are denied, never silently truncated.
 */
import * as fs from "node:fs";
import { LIMITS } from "../limits.js";
import { resolveWithinRoot, type ResolvedPath } from "../paths.js";
import { sanitizeText, type SanitizedResult } from "../sanitize.js";

export type FsAdapterResult =
  | { readonly ok: true; readonly value: unknown; readonly redacted: boolean }
  | { readonly ok: false; readonly reason: string };

export interface FsEntry {
  readonly name: string;
  readonly kind: "file" | "dir" | "symlink" | "other";
  readonly size: number | undefined;
}

function fail(reason: string): FsAdapterResult {
  return { ok: false, reason };
}

/** Single-level directory listing. Denies oversized directories. */
export function listDirectory(
  root: string,
  requested: unknown,
): FsAdapterResult {
  const resolution = resolveWithinRoot(root, requested);
  if (!resolution.ok) {
    return fail(resolution.reason);
  }
  const resolved: ResolvedPath = resolution.resolved;
  let stat: fs.Stats;
  try {
    stat = fs.statSync(resolved.real);
  } catch {
    return fail("path is not accessible");
  }
  if (!stat.isDirectory()) {
    return fail("not a directory");
  }
  let dirents: Array<fs.Dirent>;
  try {
    dirents = fs.readdirSync(resolved.real, { withFileTypes: true });
  } catch {
    return fail("directory is not readable");
  }
  if (dirents.length > LIMITS.MAX_DIR_ENTRIES) {
    return fail(
      `directory exceeds entry limit (${LIMITS.MAX_DIR_ENTRIES})`,
    );
  }
  const entries: Array<FsEntry> = [];
  for (const d of dirents) {
    let size: number | undefined;
    try {
      const s = fs.lstatSync(`${resolved.real}/${d.name}`);
      size = s.isFile() || s.isSymbolicLink() ? s.size : undefined;
    } catch {
      size = undefined;
    }
    entries.push({
      name: d.name,
      kind: d.isFile()
        ? "file"
        : d.isDirectory()
          ? "dir"
          : d.isSymbolicLink()
            ? "symlink"
            : "other",
      size,
    });
  }
  return { ok: true, value: Object.freeze(entries), redacted: false };
}

/** Bounded file read. Regular files only; binary refused. */
export function readFile(root: string, requested: unknown): FsAdapterResult {
  const resolution = resolveWithinRoot(root, requested);
  if (!resolution.ok) {
    return fail(resolution.reason);
  }
  const resolved: ResolvedPath = resolution.resolved;
  let stat: fs.Stats;
  try {
    stat = fs.statSync(resolved.real);
  } catch {
    return fail("path is not accessible");
  }
  if (!stat.isFile()) {
    return fail("not a regular file");
  }
  if (stat.size > LIMITS.MAX_FILE_BYTES) {
    return fail(`file exceeds size limit (${LIMITS.MAX_FILE_BYTES} bytes)`);
  }
  let raw: Buffer;
  try {
    raw = fs.readFileSync(resolved.real);
  } catch {
    return fail("file is not readable");
  }
  if (raw.byteLength > LIMITS.MAX_RESULT_BYTES) {
    return fail("result exceeds size limit");
  }
  const sanitized: SanitizedResult = sanitizeText(raw.toString("utf8"));
  if (!sanitized.ok) {
    return fail(sanitized.reason);
  }
  return { ok: true, value: sanitized.text, redacted: sanitized.redacted };
}
