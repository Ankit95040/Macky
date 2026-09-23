/**
 * Task-scoped capability grants (M2 deliverables 3/10).
 *
 * Core rule: THE PLANNER PROPOSES ACTIONS. TRUSTED CODE ISSUES
 * CAPABILITIES. Grants are created only by `issueGrant`, which takes
 * validated parameters from the trusted layer — never a planner
 * payload. A planner-provided taskId is a lookup key, never proof of
 * authorization: the pipeline resolves grants from the TRUSTED context.
 *
 * Pure data + pure functions. No I/O, no OS APIs.
 */
import {
  getCapabilityDefinition,
  isWellFormedScope,
} from "./capability-model.js";

export interface TrustedTaskGrant {
  readonly grantId: string;
  readonly taskId: string;
  readonly capability: string;
  /** Resource scope (path or domain); "" for unscoped capabilities. */
  readonly scope: string;
  readonly revoked: boolean;
}

export interface GrantIssuance {
  readonly grantId: string;
  readonly taskId: string;
  readonly capability: string;
  readonly scope: string;
}

const GRANT_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{0,127}$/i;

/**
 * Issue a grant. Trusted-path constructor: parameters come from
 * trusted code, so invalid input throws loudly (programmer error),
 * it never fails closed silently into a planner-visible decision.
 */
export function issueGrant(issuance: GrantIssuance): TrustedTaskGrant {
  if (
    !GRANT_ID_PATTERN.test(issuance.grantId) ||
    !GRANT_ID_PATTERN.test(issuance.taskId)
  ) {
    throw new Error("issueGrant: grantId/taskId have invalid shape");
  }
  const definition = getCapabilityDefinition(issuance.capability);
  if (definition === undefined) {
    throw new Error(
      `issueGrant: unknown capability "${issuance.capability}"`,
    );
  }
  if (!isWellFormedScope(definition, issuance.scope)) {
    throw new Error(
      `issueGrant: malformed scope for "${issuance.capability}"`,
    );
  }
  return Object.freeze({
    grantId: issuance.grantId,
    taskId: issuance.taskId,
    capability: issuance.capability,
    scope: issuance.scope,
    revoked: false,
  });
}

/** Revoke by id. Returns a NEW frozen array; input never mutated. */
export function revokeGrant(
  grants: ReadonlyArray<TrustedTaskGrant>,
  grantId: string,
): ReadonlyArray<TrustedTaskGrant> {
  const next = grants.map(
    (g: TrustedTaskGrant): TrustedTaskGrant =>
      g.grantId === grantId ? Object.freeze({ ...g, revoked: true }) : g,
  );
  return Object.freeze(next);
}

/** All grants bound to a task (lookup key only — not proof). */
export function grantsForTask(
  grants: ReadonlyArray<TrustedTaskGrant>,
  taskId: string,
): ReadonlyArray<TrustedTaskGrant> {
  return grants.filter((g: TrustedTaskGrant): boolean => g.taskId === taskId);
}
