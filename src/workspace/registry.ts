/**
 * Trusted workspace registry (M7 sections 1/2/15). Registration is a
 * TRUSTED application operation — the planner can only reference an
 * existing workspaceId, never define a root.
 *
 * Roots are canonicalized (realpath) at registration with dev+ino
 * bound; every request re-resolves and re-checks (existence,
 * directory, identity, sensitivity) so replacement/disappearance
 * fails closed. Single-shot TOCTOU between check and use remains a
 * documented limitation (M3 carryover); no locking in M7.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { isSensitivePath } from "../executor/sensitive-paths.js";
import { WORKSPACE_LIMITS } from "./limits.js";

const WORKSPACE_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{0,127}$/i;

export interface WorkspaceRegistration {
  readonly id: string;
  /** Canonical realpath at registration time. */
  readonly root: string;
  readonly dev: number;
  readonly ino: number;
}

export interface WorkspaceRegistry {
  readonly workspaces: Map<string, WorkspaceRegistration>;
}

export function createWorkspaceRegistry(): WorkspaceRegistry {
  return { workspaces: new Map() };
}

export type RegistrationResult =
  | { readonly ok: true; readonly workspace: WorkspaceRegistration }
  | { readonly ok: false; readonly reason: string };

/** Trusted registration. Throws nothing; refuses hostile roots. */
export function registerWorkspace(
  registry: WorkspaceRegistry,
  id: string,
  root: string,
): RegistrationResult {
  if (typeof id !== "string" || !WORKSPACE_ID_PATTERN.test(id)) {
    return { ok: false, reason: "invalid workspace id" };
  }
  if (typeof root !== "string" || root.length === 0 || root.length > WORKSPACE_LIMITS.MAX_WORKSPACE_PATH_CHARS) {
    return { ok: false, reason: "invalid workspace root" };
  }
  if (root.includes("\0") || !path.isAbsolute(root)) {
    return { ok: false, reason: "workspace root must be absolute" };
  }
  if (registry.workspaces.size >= WORKSPACE_LIMITS.MAX_WORKSPACES && !registry.workspaces.has(id)) {
    return { ok: false, reason: "workspace registry full" };
  }
  let canonical: string;
  let stat: fs.Stats;
  try {
    canonical = fs.realpathSync(path.normalize(root));
    stat = fs.statSync(canonical);
  } catch {
    return { ok: false, reason: "workspace root not accessible" };
  }
  if (!stat.isDirectory()) {
    return { ok: false, reason: "workspace root is not a directory" };
  }
  if (isSensitivePath(canonical).sensitive) {
    return { ok: false, reason: "workspace root is sensitive" };
  }
  const workspace: WorkspaceRegistration = Object.freeze({
    id,
    root: canonical,
    dev: stat.dev,
    ino: stat.ino,
  });
  registry.workspaces.set(id, workspace);
  return { ok: true, workspace };
}

export type ReverifyResult =
  | { readonly ok: true; readonly root: string }
  | { readonly ok: false; readonly reason: string };

/**
 * Re-resolve + re-check the registered root at request time.
 * Detects disappearance, replacement (dev/ino drift), and newly
 * sensitive paths. Fail closed on anything unexpected.
 */
export function reverifyWorkspace(
  registry: WorkspaceRegistry,
  id: string,
): ReverifyResult {
  const registered = registry.workspaces.get(id);
  if (registered === undefined) {
    return { ok: false, reason: "unknown workspace" };
  }
  let canonical: string;
  let stat: fs.Stats;
  try {
    canonical = fs.realpathSync(registered.root);
    stat = fs.statSync(canonical);
  } catch {
    return { ok: false, reason: "workspace root disappeared" };
  }
  if (!stat.isDirectory()) {
    return { ok: false, reason: "workspace root is no longer a directory" };
  }
  if (stat.dev !== registered.dev || stat.ino !== registered.ino) {
    return { ok: false, reason: "workspace root changed unexpectedly" };
  }
  if (isSensitivePath(canonical).sensitive) {
    return { ok: false, reason: "workspace root is sensitive" };
  }
  return { ok: true, root: canonical };
}
