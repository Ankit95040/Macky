/**
 * M2 capability registry: authorization DATA only (M2 deliverables 2/6).
 *
 * This module is separate from M1 `capabilities.ts` (left frozen).
 * Every entry declares its explicit security boundary: family,
 * operations, trusted risk tier, confirmation requirement,
 * sleep-gating, and whether it is resource-scoped.
 *
 * The risk tier is TRUSTED policy data. The planner requests a
 * capability; it can never declare the tier. No implementation sits
 * behind these entries — no shell, filesystem, network, browser,
 * screen, keyboard, mouse, or macOS APIs, not even as placeholders.
 */

/** Trusted risk tiers (M2 section 6). Planner input never sets these. */
export type RiskTier = 0 | 1 | 2 | 3;

export type CapabilityFamily =
  | "filesystem"
  | "terminal"
  | "git"
  | "browser"
  | "screen"
  | "app-control"
  | "keyboard"
  | "mouse"
  | "network"
  | "memory"
  | "audit"
  | "sleep";

export interface CapabilityDefinition {
  readonly id: string;
  readonly family: CapabilityFamily;
  /** Exact operation names. No fuzzy matching, no inference. */
  readonly operations: ReadonlyArray<string>;
  /** Trusted tier. Tier >= 2 always requires explicit human approval. */
  readonly riskTier: RiskTier;
  readonly requiresConfirmation: boolean;
  readonly sleepGated: boolean;
  /** True when requests must carry a resource inside the grant scope. */
  readonly scoped: boolean;
  readonly description: string;
}

function def(d: CapabilityDefinition): CapabilityDefinition {
  return Object.freeze({
    ...d,
    operations: Object.freeze([...d.operations]),
  });
}

export const CAPABILITY_DEFINITIONS: ReadonlyArray<CapabilityDefinition> =
  Object.freeze([
    // ---- filesystem ----
    def({
      id: "filesystem.read",
      family: "filesystem",
      operations: ["read", "list"],
      riskTier: 0,
      requiresConfirmation: false,
      sleepGated: true,
      scoped: true,
      description: "Tier 0: read files / list directories inside grant scope.",
    }),
    def({
      id: "filesystem.write",
      family: "filesystem",
      operations: ["create", "edit", "mkdir"],
      riskTier: 1,
      requiresConfirmation: false,
      sleepGated: true,
      scoped: true,
      description:
        "Tier 1: create/edit files and directories inside grant scope.",
    }),
    def({
      id: "filesystem.delete",
      family: "filesystem",
      operations: ["delete"],
      riskTier: 3,
      requiresConfirmation: true,
      sleepGated: true,
      scoped: true,
      description: "Tier 3: destructive filesystem operations.",
    }),
    // ---- terminal (authorization data only; no execution in M2) ----
    def({
      id: "terminal.run",
      family: "terminal",
      operations: ["run-tests"],
      riskTier: 1,
      requiresConfirmation: false,
      sleepGated: true,
      scoped: false,
      description:
        "Tier 1: run tests through a future authorized executor. " +
        "No command execution exists in M2.",
    }),
    // ---- git ----
    def({
      id: "git.read",
      family: "git",
      operations: ["status", "log", "diff"],
      riskTier: 0,
      requiresConfirmation: false,
      sleepGated: true,
      scoped: true,
      description: "Tier 0: read-only git inspection inside grant scope.",
    }),
    def({
      id: "git.commit",
      family: "git",
      operations: ["commit"],
      riskTier: 2,
      requiresConfirmation: true,
      sleepGated: true,
      scoped: true,
      description: "Tier 2: git commit inside grant scope.",
    }),
    def({
      id: "git.push",
      family: "git",
      operations: ["push"],
      riskTier: 2,
      requiresConfirmation: true,
      sleepGated: true,
      scoped: true,
      description: "Tier 2: git push (external, hard to reverse).",
    }),
    // ---- browser ----
    def({
      id: "browser.read",
      family: "browser",
      operations: ["read"],
      riskTier: 1,
      requiresConfirmation: false,
      sleepGated: true,
      scoped: true,
      description: "Tier 1: read browser content inside grant scope.",
    }),
    def({
      id: "browser.navigate",
      family: "browser",
      operations: ["navigate"],
      riskTier: 2,
      requiresConfirmation: true,
      sleepGated: true,
      scoped: true,
      description: "Tier 2: navigate the browser (external effects).",
    }),
    // ---- screen ----
    def({
      id: "screen.capture",
      family: "screen",
      operations: ["capture"],
      riskTier: 2,
      requiresConfirmation: true,
      sleepGated: true,
      scoped: false,
      description: "Tier 2: screen capture. Never while asleep.",
    }),
    // ---- app / computer control ----
    def({
      id: "app.control",
      family: "app-control",
      operations: ["control"],
      riskTier: 3,
      requiresConfirmation: true,
      sleepGated: true,
      scoped: false,
      description: "Tier 3: control applications / the computer.",
    }),
    // ---- keyboard / mouse ----
    def({
      id: "keyboard.input",
      family: "keyboard",
      operations: ["send"],
      riskTier: 3,
      requiresConfirmation: true,
      sleepGated: true,
      scoped: false,
      description: "Tier 3: synthesize keyboard input.",
    }),
    def({
      id: "mouse.input",
      family: "mouse",
      operations: ["send"],
      riskTier: 3,
      requiresConfirmation: true,
      sleepGated: true,
      scoped: false,
      description: "Tier 3: synthesize mouse input.",
    }),
    // ---- network ----
    def({
      id: "network.request",
      family: "network",
      operations: ["request"],
      riskTier: 2,
      requiresConfirmation: true,
      sleepGated: true,
      scoped: true,
      description:
        "Tier 2: network requests bounded to the grant's domain scope.",
    }),
    // ---- memory ----
    def({
      id: "memory.read",
      family: "memory",
      operations: ["read"],
      riskTier: 0,
      requiresConfirmation: false,
      sleepGated: true,
      scoped: true,
      description: "Tier 0: read memory inside grant scope.",
    }),
    def({
      id: "memory.write",
      family: "memory",
      operations: ["write"],
      riskTier: 2,
      requiresConfirmation: true,
      sleepGated: true,
      scoped: true,
      description: "Tier 2: memory writes. Never while asleep.",
    }),
    // ---- audit / sleep (mirror the M1 set for the M2 pipeline) ----
    def({
      id: "audit.append",
      family: "audit",
      operations: ["append"],
      riskTier: 0,
      requiresConfirmation: false,
      sleepGated: false,
      scoped: false,
      description: "Tier 0: append to the audit log (M1-compatible).",
    }),
    def({
      id: "audit.read",
      family: "audit",
      operations: ["read"],
      riskTier: 0,
      requiresConfirmation: false,
      sleepGated: false,
      scoped: false,
      description: "Tier 0: read the audit log (M1-compatible).",
    }),
    def({
      id: "system.sleep",
      family: "sleep",
      operations: ["sleep"],
      riskTier: 0,
      requiresConfirmation: false,
      sleepGated: false,
      scoped: false,
      description: "Tier 0: enter SLEEP, always available (M1-compatible).",
    }),
  ]);

/**
 * Deliberately ABSENT from the registry (planner can never obtain):
 * system.wake (wake is a trusted local action, never a capability),
 * policy modification, secret access, shell execution, Docker control.
 * Absence + default-deny = ungrantable.
 */

/** Pure lookup. Unknown ids return undefined (caller must deny). */
export function getCapabilityDefinition(
  id: string,
): CapabilityDefinition | undefined {
  return CAPABILITY_DEFINITIONS.find(
    (d: CapabilityDefinition): boolean => d.id === id,
  );
}

/** Exact operation match only. */
export function isDeclaredOperation(
  definition: CapabilityDefinition,
  operation: string,
): boolean {
  return definition.operations.includes(operation);
}

// ---- scope containment (pure) ----

const PATH_FAMILIES: ReadonlySet<CapabilityFamily> = new Set([
  "filesystem",
  "git",
  "memory",
  "browser",
]);

/** Normalize an absolute path; undefined when malformed or escaping. */
function normalizePath(value: string): string | undefined {
  if (!value.startsWith("/")) {
    return undefined;
  }
  const parts = value.split("/");
  const stack: Array<string> = [];
  for (const part of parts) {
    if (part === "" || part === ".") {
      continue;
    }
    if (part === "..") {
      const prev = stack.pop();
      if (prev === undefined) {
        return undefined;
      }
      continue;
    }
    stack.push(part);
  }
  return `/${stack.join("/")}`;
}

function normalizeDomain(value: string): string | undefined {
  const lower = value.toLowerCase();
  if (/^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$/.test(lower)) {
    return lower;
  }
  return undefined;
}

/**
 * Deterministic containment: the request resource must fall inside the
 * trusted grant scope. Paths use segment-boundary prefix matching
 * ("/project" contains "/project/src" but NOT "/project-evil" or "/").
 * Network scopes are domains (exact or subdomain). No fuzzy matching.
 */
export function isWithinScope(
  definition: CapabilityDefinition,
  scope: string,
  resource: string,
): boolean {
  if (definition.family === "network") {
    const scopeDomain = normalizeDomain(scope);
    const resourceHost = normalizeDomain(resource);
    if (scopeDomain === undefined || resourceHost === undefined) {
      return false;
    }
    return (
      resourceHost === scopeDomain ||
      resourceHost.endsWith(`.${scopeDomain}`)
    );
  }
  if (PATH_FAMILIES.has(definition.family)) {
    const scopePath = normalizePath(scope);
    const resourcePath = normalizePath(resource);
    if (scopePath === undefined || resourcePath === undefined) {
      return false;
    }
    if (resourcePath === scopePath) {
      return true;
    }
    if (scopePath === "/") {
      return resourcePath.startsWith("/");
    }
    return resourcePath.startsWith(`${scopePath}/`);
  }
  return false;
}

/** Validate a grant scope shape at issuance time (trusted path). */
export function isWellFormedScope(
  definition: CapabilityDefinition,
  scope: string,
): boolean {
  if (!definition.scoped) {
    return scope === "";
  }
  if (definition.family === "network") {
    return normalizeDomain(scope) !== undefined;
  }
  if (PATH_FAMILIES.has(definition.family)) {
    return normalizePath(scope) !== undefined;
  }
  return false;
}
