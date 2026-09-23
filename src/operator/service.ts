/**
 * Trusted local operator funnel (M16). ONE validated entry point per
 * explicitly allowed operator action. Each function validates its
 * input, applies funnel policy (tier allowlist, scope policy,
 * digest rule), then delegates EXACTLY ONCE to an existing trusted
 * session helper — which owns all behavior and audit emission. M16
 * emits no audit events of its own and reproduces no authorization,
 * executor, filesystem, or durability logic.
 *
 * Import discipline (enforced by test): kernel capability registry +
 * persistence session helpers + workspace registry (read-only root
 * lookup) + zod + node:os/path/fs for scope checks. Never planner,
 * llm, conversation, voice, web, memory, executor, MCP, or OS
 * control. In particular there is deliberately NO disengage export:
 * kill release has no operator path in M16.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { getCapabilityDefinition } from "../kernel/capability-model.js";
import {
  confirmInSession,
  engageSessionKill,
  grantToSession,
  revokeSessionGrant,
  sleepSession,
  wakeSession,
  type SecureSession,
} from "../persistence/session.js";
import {
  reverifyWorkspace,
  type WorkspaceRegistry,
} from "../workspace/registry.js";
import {
  OperatorAuditTailSchema,
  OperatorConfirmSchema,
  OperatorGrantSchema,
  OperatorRevokeSchema,
  OperatorWakeSchema,
} from "./actions.js";

export type OperatorRefusal = { readonly ok: false; readonly reason: string };

/** Capabilities whose confirmations must carry a valid digest (M13 rule). */
const DIGEST_REQUIRED_CAPABILITIES: ReadonlyArray<string> = Object.freeze([
  "speech.announce",
]);

const PATH_SCOPED_FAMILIES: ReadonlySet<string> = new Set([
  "filesystem",
  "git",
  "memory",
  "browser",
  "terminal",
]);

function refuse(reason: string): OperatorRefusal {
  return { ok: false, reason };
}

export function getStatus(session: SecureSession): {
  readonly epoch: number;
  readonly sleep: string;
  readonly killEngaged: boolean;
  readonly grantCount: number;
  readonly confirmationCount: number;
  readonly auditHealthy: boolean;
} {
  return Object.freeze({
    epoch: session.epoch,
    sleep: session.sleep,
    killEngaged: session.killSwitch.engaged === true,
    grantCount: session.grants.length,
    confirmationCount: session.confirmations.length,
    auditHealthy: session.auditHealthy,
  });
}

export function sleepOp(session: SecureSession): { readonly ok: true; readonly sleep: "SLEEP" } {
  sleepSession(session);
  return { ok: true as const, sleep: "SLEEP" as const };
}

export function wakeOp(
  session: SecureSession,
  input: unknown,
): { readonly ok: true; readonly woken: boolean } | OperatorRefusal {
  const parsed = OperatorWakeSchema.safeParse(input);
  if (!parsed.success) {
    return refuse("invalid wake action");
  }
  return { ok: true as const, woken: wakeSession(session, { kind: parsed.data.kind }) };
}

export function engageKillOp(session: SecureSession): { readonly ok: true; readonly engaged: true } {
  engageSessionKill(session);
  return { ok: true as const, engaged: true as const };
}

/**
 * Scope policy: Tier0/1 path-scoped grants must resolve inside a
 * reverified registered workspace or the ~/.macky operator area.
 * Unscoped capabilities require an empty scope. Network scopes are
 * not issuable through the funnel (no domain policy yet). Roots,
 * traversal-shaped, non-absolute, and non-directory scopes refuse.
 * Sensitive-target enforcement stays downstream in M3 by design.
 */
function scopeAllowed(
  registry: WorkspaceRegistry,
  family: string,
  scoped: boolean,
  scope: string,
): { readonly ok: true } | OperatorRefusal {
  if (!scoped) {
    return scope === "" ? { ok: true } : refuse("unscoped capability requires empty scope");
  }
  if (family === "network") {
    return refuse("network scopes are not issuable through the operator funnel");
  }
  if (!PATH_SCOPED_FAMILIES.has(family)) {
    return refuse("scope family not issuable through the operator funnel");
  }
  if (scope.length === 0 || !path.isAbsolute(scope) || scope.includes("\0") || scope.includes("\\")) {
    return refuse("scope must be an absolute path");
  }
  if (scope.split("/").includes("..")) {
    return refuse("scope traversal refused");
  }
  let real: string;
  try {
    real = fs.realpathSync(path.normalize(scope));
    if (!fs.statSync(real).isDirectory()) {
      return refuse("scope is not a directory");
    }
  } catch {
    return refuse("scope not accessible");
  }
  const mackyDir = path.join(os.homedir(), ".macky");
  if (real === mackyDir || real.startsWith(`${mackyDir}/`)) {
    return { ok: true };
  }
  for (const id of registry.workspaces.keys()) {
    const reverified = reverifyWorkspace(registry, id);
    if (!reverified.ok) {
      continue;
    }
    if (real === reverified.root || real.startsWith(`${reverified.root}/`)) {
      return { ok: true };
    }
  }
  return refuse("scope outside approved workspaces");
}

export function issueGrantOp(
  session: SecureSession,
  registry: WorkspaceRegistry,
  input: unknown,
):
  | { readonly ok: true; readonly grantId: string }
  | OperatorRefusal {
  const parsed = OperatorGrantSchema.safeParse(input);
  if (!parsed.success) {
    return refuse("invalid grant issuance");
  }
  const definition = getCapabilityDefinition(parsed.data.capability);
  if (definition === undefined) {
    return refuse("unknown capability");
  }
  if (definition.riskTier === 2 || definition.riskTier === 3) {
    return refuse("Tier2/Tier3 grants are not issuable through the operator funnel");
  }
  const scopeCheck = scopeAllowed(registry, definition.family, definition.scoped, parsed.data.scope);
  if (!scopeCheck.ok) {
    return scopeCheck;
  }
  const issued = grantToSession(session, {
    grantId: parsed.data.grantId,
    taskId: parsed.data.taskId,
    capability: parsed.data.capability,
    scope: parsed.data.scope,
  });
  if (!issued.ok) {
    return refuse(issued.reason);
  }
  return { ok: true as const, grantId: parsed.data.grantId };
}

export function revokeGrantOp(
  session: SecureSession,
  input: unknown,
): { readonly ok: true } | OperatorRefusal {
  const parsed = OperatorRevokeSchema.safeParse(input);
  if (!parsed.success) {
    return refuse("invalid revocation");
  }
  revokeSessionGrant(session, parsed.data.grantId);
  return { ok: true as const };
}

export function recordConfirmationOp(
  session: SecureSession,
  input: unknown,
): { readonly ok: true } | OperatorRefusal {
  const parsed = OperatorConfirmSchema.safeParse(input);
  if (!parsed.success) {
    return refuse("invalid confirmation record");
  }
  const definition = getCapabilityDefinition(parsed.data.capability);
  if (definition === undefined) {
    return refuse("unknown capability");
  }
  if (DIGEST_REQUIRED_CAPABILITIES.includes(parsed.data.capability) && parsed.data.digest === undefined) {
    return refuse("digest-bound confirmation required");
  }
  confirmInSession(session, {
    taskId: parsed.data.taskId,
    capability: parsed.data.capability,
    operation: parsed.data.operation,
    resource: parsed.data.resource,
    ...(parsed.data.digest !== undefined ? { digest: parsed.data.digest } : {}),
  });
  return { ok: true as const };
}

export function readAuditTailOp(
  session: SecureSession,
  input: unknown,
): { readonly ok: true; readonly events: ReadonlyArray<unknown> } | OperatorRefusal {
  const parsed = OperatorAuditTailSchema.safeParse(input);
  if (!parsed.success) {
    return refuse("invalid audit tail request");
  }
  let raw: string;
  try {
    raw = fs.readFileSync(session.sink.path, "utf8");
  } catch {
    return refuse("audit sink unreadable");
  }
  const events: Array<unknown> = [];
  const lines = raw.split("\n");
  for (let i = lines.length - 1; i >= 0 && events.length < parsed.data.limit; i -= 1) {
    const line = lines[i] ?? "";
    if (line.length === 0) {
      continue;
    }
    try {
      events.push(JSON.parse(line) as unknown);
    } catch {
      continue;
    }
  }
  return { ok: true as const, events: Object.freeze(events.reverse()) };
}
