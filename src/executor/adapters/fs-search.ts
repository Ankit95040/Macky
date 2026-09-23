/**
 * Read-only discovery adapter (M7 sections 5/8/9/10).
 * find / search / tree over an authorized root. No shell find/grep,
 * no child_process, no symlinked-directory descent, no unbounded walk.
 *
 * Deterministic: byte-sorted traversal, absolute realpath containment
 * per entry (reusing resolveWithinRoot), sensitive pruning with an
 * explicit pruned count (never silent), hard caps with truncated flags.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { LIMITS } from "../limits.js";
import { resolveWithinRoot } from "../paths.js";
import { sanitizeText } from "../sanitize.js";
import { isSensitivePath } from "../sensitive-paths.js";

export type DiscoveryResult =
  | { readonly ok: true; readonly value: unknown; readonly redacted: boolean }
  | { readonly ok: false; readonly reason: string };

function fail(reason: string): DiscoveryResult {
  return { ok: false, reason };
}

export interface FoundEntry {
  readonly path: string;
  readonly kind: "file" | "dir" | "symlink" | "other";
}

/**
 * Deliberately small pattern language: an exact filename, `*` (all),
 * or `*suffix` (e.g. `*.ts`). One leading star at most; nothing else.
 * Case-sensitive exact matching.
 */
export function validatePattern(pattern: unknown): string | undefined {
  if (typeof pattern !== "string" || pattern.length === 0) {
    return undefined;
  }
  if (pattern.length > LIMITS.MAX_PATTERN_CHARS) {
    return undefined;
  }
  if (pattern === "*") {
    return pattern;
  }
  if (!/^[A-Za-z0-9._*-]+$/.test(pattern)) {
    return undefined;
  }
  const stars = pattern.split("*").length - 1;
  if (stars > 1 || (stars === 1 && !pattern.startsWith("*"))) {
    return undefined;
  }
  return pattern;
}

function patternMatches(pattern: string, name: string): boolean {
  if (pattern === "*") {
    return true;
  }
  if (pattern.startsWith("*")) {
    return name.endsWith(pattern.slice(1)) && name.length > pattern.length - 1;
  }
  return name === pattern;
}

interface WalkEntry {
  real: string;
  depth: number;
}

/**
 * Shared bounded walker. Yields resolved absolute paths in
 * deterministic (byte-sorted) order. Directory symlinks are NEVER
 * descended (pruned + counted). Dangling links are pruned.
 */
function walkRoot(
  root: string,
  startReal: string,
  maxDepth: number,
): { entries: Array<{ real: string; depth: number }>; visited: number; pruned: number; truncated: boolean } {
  const entries: Array<{ real: string; depth: number }> = [];
  const stack: Array<WalkEntry> = [{ real: startReal, depth: 0 }];
  let visited = 0;
  let pruned = 0;
  let truncated = false;
  while (stack.length > 0) {
    if (visited >= LIMITS.MAX_VISITED_ENTRIES) {
      truncated = true;
      break;
    }
    const current = stack.pop() as WalkEntry;
    let dirents: Array<fs.Dirent>;
    try {
      dirents = fs.readdirSync(current.real, { withFileTypes: true });
    } catch {
      pruned += 1;
      continue;
    }
    dirents.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const d of dirents) {
      visited += 1;
      if (visited > LIMITS.MAX_VISITED_ENTRIES) {
        truncated = true;
        break;
      }
      const full = `${current.real}/${d.name}`;
      // Discovery prunes sensitive paths (defense in depth on top of
      // read-time denial): sensitive names never surface from
      // find/search/tree, with an explicit pruned count.
      if (isSensitivePath(full).sensitive) {
        pruned += 1;
        continue;
      }
      if (d.isSymbolicLink()) {
        // Resolve once: files inside containment are listable, directory
        // links are never descended, escapes/dangling links are pruned.
        let target: fs.Stats | undefined;
        try {
          const real = fs.realpathSync(full);
          const resolution = resolveWithinRoot(root, real);
          if (!resolution.ok) {
            pruned += 1;
            continue;
          }
          if (isSensitivePath(resolution.resolved.real).sensitive) {
            pruned += 1;
            continue;
          }
          target = fs.statSync(resolution.resolved.real);
        } catch {
          pruned += 1;
          continue;
        }
        if (target.isDirectory()) {
          pruned += 1;
          continue;
        }
        entries.push({ real: full, depth: current.depth + 1 });
        continue;
      }
      if (d.isDirectory()) {
        entries.push({ real: full, depth: current.depth + 1 });
        if (current.depth + 1 < maxDepth) {
          stack.push({ real: full, depth: current.depth + 1 });
        }
        continue;
      }
      entries.push({ real: full, depth: current.depth + 1 });
    }
  }
  // Deterministic global order regardless of stack discipline.
  entries.sort((a, b) => (a.real < b.real ? -1 : a.real > b.real ? 1 : 0));
  return { entries, visited, pruned, truncated };
}

function containmentOk(root: string, absoluteReal: string): boolean {
  return resolveWithinRoot(root, absoluteReal).ok;
}

function kindOf(real: string): FoundEntry["kind"] {
  try {
    const s = fs.lstatSync(real);
    if (s.isSymbolicLink()) return "symlink";
    if (s.isFile()) return "file";
    if (s.isDirectory()) return "dir";
    return "other";
  } catch {
    return "other";
  }
}

/** Bounded filename discovery inside a resolved directory. */
export function findFiles(
  root: string,
  dir: unknown,
  pattern: unknown,
): DiscoveryResult {
  const valid = validatePattern(pattern);
  if (valid === undefined) {
    return fail("invalid find pattern");
  }
  const resolution = resolveWithinRoot(root, dir);
  if (!resolution.ok) {
    return fail(resolution.reason);
  }
  const startReal = resolution.resolved.real;
  try {
    if (!fs.statSync(startReal).isDirectory()) {
      return fail("not a directory");
    }
  } catch {
    return fail("path is not accessible");
  }
  const walk = walkRoot(root, startReal, LIMITS.MAX_SEARCH_DEPTH);
  const entries: Array<FoundEntry> = [];
  let truncated = walk.truncated;
  for (const e of walk.entries) {
    if (entries.length >= LIMITS.MAX_FIND_RESULTS) {
      truncated = true;
      break;
    }
    if (!containmentOk(root, e.real)) {
      walk.pruned += 1;
      continue;
    }
    const name = e.real.slice(e.real.lastIndexOf("/") + 1);
    if (!patternMatches(valid, name)) {
      continue;
    }
    entries.push({ path: e.real, kind: kindOf(e.real) });
  }
  return {
    ok: true,
    value: Object.freeze({ entries: Object.freeze(entries), pruned: walk.pruned, truncated }),
    redacted: false,
  };
}

export interface SearchMatch {
  readonly path: string;
  readonly line: number;
  readonly context: string;
}

function validateQuery(query: unknown): string | undefined {
  if (typeof query !== "string" || query.length === 0) {
    return undefined;
  }
  if (query.length > LIMITS.MAX_QUERY_CHARS) {
    return undefined;
  }
  if (query.includes("\0")) {
    return undefined;
  }
  return query;
}

/** Bounded recursive text search. Binary/unreadable/sensitive files pruned. */
export function searchContents(
  root: string,
  dir: unknown,
  query: unknown,
): DiscoveryResult {
  const valid = validateQuery(query);
  if (valid === undefined) {
    return fail("invalid search query");
  }
  const resolution = resolveWithinRoot(root, dir);
  if (!resolution.ok) {
    return fail(resolution.reason);
  }
  const startReal = resolution.resolved.real;
  try {
    if (!fs.statSync(startReal).isDirectory()) {
      return fail("not a directory");
    }
  } catch {
    return fail("path is not accessible");
  }
  const walk = walkRoot(root, startReal, LIMITS.MAX_SEARCH_DEPTH);
  const matches: Array<SearchMatch> = [];
  let pruned = walk.pruned;
  let truncated = walk.truncated;
  let redacted = false;
  outer: for (const e of walk.entries) {
    if (matches.length >= LIMITS.MAX_SEARCH_MATCHES) {
      truncated = true;
      break;
    }
    if (!containmentOk(root, e.real)) {
      pruned += 1;
      continue;
    }
    let stat: fs.Stats;
    try {
      stat = fs.statSync(e.real);
    } catch {
      pruned += 1;
      continue;
    }
    if (!stat.isFile() || stat.size > LIMITS.SEARCH_MAX_FILE_BYTES) {
      if (stat.isFile()) {
        pruned += 1;
      }
      continue;
    }
    let raw: Buffer;
    try {
      raw = fs.readFileSync(e.real);
    } catch {
      pruned += 1;
      continue;
    }
    const text = raw.toString("utf8");
    if (text.includes("\0")) {
      pruned += 1;
      continue;
    }
    const lines = text.split("\n");
    for (let i = 0; i < lines.length; i += 1) {
      if (matches.length >= LIMITS.MAX_SEARCH_MATCHES) {
        truncated = true;
        break outer;
      }
      const line = lines[i] ?? "";
      if (!line.includes(valid)) {
        continue;
      }
      const sanitized = sanitizeText(line);
      if (!sanitized.ok) {
        pruned += 1;
        continue;
      }
      if (sanitized.redacted) {
        redacted = true;
      }
      const context =
        sanitized.text.length > 256 ? `${sanitized.text.slice(0, 256)}[…]` : sanitized.text;
      matches.push({ path: e.real, line: i + 1, context });
    }
  }
  return {
    ok: true,
    value: Object.freeze({ matches: Object.freeze(matches), pruned, truncated }),
    redacted,
  };
}

export interface TreeNode {
  readonly name: string;
  readonly kind: "file" | "dir" | "symlink" | "other";
  readonly children?: ReadonlyArray<TreeNode>;
}

/** Bounded structure listing. Never descends symlinked directories. */
export function readTree(root: string, dir: unknown): DiscoveryResult {
  const resolution = resolveWithinRoot(root, dir);
  if (!resolution.ok) {
    return fail(resolution.reason);
  }
  const startReal = resolution.resolved.real;
  try {
    if (!fs.statSync(startReal).isDirectory()) {
      return fail("not a directory");
    }
  } catch {
    return fail("path is not accessible");
  }
  let nodeCount = 0;
  let pruned = 0;
  let truncated = false;
  const build = (real: string, depth: number): Array<TreeNode> => {
    let dirents: Array<fs.Dirent>;
    try {
      dirents = fs.readdirSync(real, { withFileTypes: true });
    } catch {
      pruned += 1;
      return [];
    }
    dirents.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    const out: Array<TreeNode> = [];
    for (const d of dirents) {
      if (nodeCount >= LIMITS.MAX_TREE_NODES) {
        truncated = true;
        break;
      }
      const full = `${real}/${d.name}`;
      if (isSensitivePath(full).sensitive) {
        pruned += 1;
        continue;
      }
      if (d.isSymbolicLink()) {
        try {
          const targetReal = fs.realpathSync(full);
          if (!resolveWithinRoot(root, targetReal).ok) {
            pruned += 1;
            continue;
          }
          if (isSensitivePath(targetReal).sensitive) {
            pruned += 1;
            continue;
          }
          nodeCount += 1;
          out.push({ name: d.name, kind: "symlink" });
        } catch {
          pruned += 1;
        }
        continue;
      }
      if (d.isDirectory()) {
        nodeCount += 1;
        if (depth + 1 < LIMITS.MAX_TREE_DEPTH) {
          const children = build(full, depth + 1);
          out.push({ name: d.name, kind: "dir", children: Object.freeze(children) });
        } else {
          // Depth cap: mark truncated only if content was actually cut.
          try {
            if (fs.readdirSync(full).length > 0) {
              truncated = true;
            }
          } catch {
            pruned += 1;
          }
          out.push({ name: d.name, kind: "dir", children: Object.freeze([]) });
        }
        continue;
      }
      if (!containmentOk(root, full)) {
        pruned += 1;
        continue;
      }
      nodeCount += 1;
      out.push({ name: d.name, kind: d.isFile() ? "file" : "other" });
    }
    return out;
  };
  const nodes = Object.freeze(build(startReal, 0));
  return {
    ok: true,
    value: Object.freeze({ nodes, pruned, truncated }),
    redacted: false,
  };
}
