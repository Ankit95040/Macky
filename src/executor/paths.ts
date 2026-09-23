/**
 * Deterministic path resolution (M3 section 4).
 *
 * The executor never trusts a path string because M2 authorized it.
 * Every filesystem/git path is re-resolved here: lexical
 * normalization, symlink resolution via realpath, containment of the
 * FINAL target inside the resolved root, plus sensitive-path screening
 * of both the requested and resolved forms.
 *
 * Symlink policy: links are resolved, never assumed. A link whose
 * final target stays inside the root and outside sensitive locations
 * is allowed; anything escaping is denied. This is deterministic for a
 * single evaluation. TOCTOU races (path swapped between check and use)
 * are a documented limitation (see M3_EXECUTION.md); M3 performs
 * single-shot reads with no privilege boundary crossed by a race.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { isSensitivePath } from "./sensitive-paths.js";

export interface ResolvedPath {
  /** Lexically normalized requested path. */
  readonly normalized: string;
  /** Fully resolved target after realpath (symlinks resolved). */
  readonly real: string;
  /** Resolved root the target was contained in. */
  readonly root: string;
}

export type PathResolution =
  | { readonly ok: true; readonly resolved: ResolvedPath }
  | { readonly ok: false; readonly reason: string };

function deny(reason: string): PathResolution {
  return { ok: false, reason };
}

/**
 * Resolve `requested` (must be absolute) inside `root`.
 * Both are resolved with realpath before the containment check.
 */
export function resolveWithinRoot(
  root: string,
  requested: unknown,
): PathResolution {
  if (typeof requested !== "string" || requested.length === 0) {
    return deny("path is not a non-empty string");
  }
  if (requested.includes("\0")) {
    return deny("path contains NUL byte");
  }
  if (!path.isAbsolute(requested)) {
    return deny("path is not absolute");
  }
  const normalized = path.normalize(requested);
  if (!path.isAbsolute(normalized)) {
    return deny("normalized path is not absolute");
  }

  let realRoot: string;
  try {
    realRoot = fs.realpathSync(root);
  } catch {
    return deny("grant root is not accessible");
  }
  let real: string;
  try {
    real = fs.realpathSync(normalized);
  } catch {
    return deny("path does not exist or is not resolvable");
  }

  if (real !== realRoot && !real.startsWith(`${realRoot}/`)) {
    return deny("resolved target escapes the authorized root");
  }

  const sensitiveReal = isSensitivePath(real);
  if (sensitiveReal.sensitive) {
    return deny(`sensitive path: ${sensitiveReal.reason}`);
  }
  const sensitiveReq = isSensitivePath(normalized);
  if (sensitiveReq.sensitive) {
    return deny(`sensitive path: ${sensitiveReq.reason}`);
  }

  return {
    ok: true,
    resolved: Object.freeze({ normalized, real, root: realRoot }),
  };
}
