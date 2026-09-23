/**
 * Deterministic authorization pipeline (M2 sections 5/11/12).
 *
 * UNTRUSTED planner request
 *  → 1. parse/validate (strict schema; forged fields fail closed)
 *  → 2. resolve trusted capability definition
 *  → 3. resolve trusted task grant (planner taskId is a lookup key only)
 *  → 4. sleep-state enforcement (SLEEP denies everything gated)
 *  → 5. capability identity + operation check (exact match, no fuzzy)
 *  → 6. resource/scope containment check
 *  → 7. trusted risk tier (planner risk metadata cannot exist here:
 *       the schema rejects it, and the tier comes only from the
 *       registry)
 *  → 8. confirmation requirement (tier >= 2 or declaration flag)
 *  → 9. trusted confirmation state (mock store; planner approval
 *       has zero authority)
 *  → 10. final decision + exactly one audit event
 *
 * M2 ONLY AUTHORIZES. There is no execution API in this module —
 * no child_process, no fs, no net, no automation of any kind.
 * A decision must NEVER be read as "already executed".
 */
import {
  ActionRequestSchema,
  type ActionRequest,
} from "./action-request.js";
import {
  appendSecurityEvent,
  type AuditLog,
  type SecurityEventType,
} from "./audit.js";
import { getCapability as getLegacyCapability } from "./capabilities.js";
import {
  getCapabilityDefinition,
  isDeclaredOperation,
  isWithinScope,
  type CapabilityDefinition,
  type RiskTier,
} from "./capability-model.js";
import {
  hasConfirmation,
  type ConfirmationStore,
} from "./confirm.js";
import { evaluateProposal } from "./policy.js";
import { grantsForTask, type TrustedTaskGrant } from "./task-grants.js";
import { redactSecrets } from "./audit.js";
import type { SleepState } from "./types.js";

export type AuthorizationVerdict =
  | "allow"
  | "deny"
  | "require-confirmation";

export interface AuthorizationCheck {
  readonly name: string;
  readonly passed: boolean;
  readonly detail: string;
}

export interface AuthorizationDecision {
  readonly verdict: AuthorizationVerdict;
  readonly reason: string;
  readonly capability: string;
  readonly operation: string;
  readonly taskId: string | undefined;
  readonly riskTier: RiskTier;
  readonly checks: ReadonlyArray<AuthorizationCheck>;
}

export interface AuthorizationContext {
  readonly sleep: SleepState;
  readonly grants: ReadonlyArray<TrustedTaskGrant>;
  readonly confirmations: ConfirmationStore;
  readonly log: AuditLog;
}

export interface AuthorizationResult {
  readonly decision: AuthorizationDecision;
  readonly log: AuditLog;
}

function check(
  name: string,
  passed: boolean,
  detail: string,
): AuthorizationCheck {
  return Object.freeze({ name, passed, detail });
}

function finish(
  ctx: AuthorizationContext,
  event: SecurityEventType,
  detail: string,
  decision: Omit<AuthorizationDecision, "checks"> & {
    checks: Array<AuthorizationCheck>;
  },
): AuthorizationResult {
  const checks = Object.freeze([...decision.checks]);
  const finalDecision: AuthorizationDecision = Object.freeze({
    ...decision,
    reason: redactSecrets(decision.reason),
    checks,
  });
  return {
    decision: finalDecision,
    log: appendSecurityEvent(ctx.log, event, detail, ctx.sleep),
  };
}

/**
 * Authorize one untrusted request. Pure: returns the decision plus the
 * next audit log; nothing is executed, nothing is mutated.
 */
export function authorize(
  request: unknown,
  ctx: AuthorizationContext,
): AuthorizationResult {
  // -- step 1: parse / validate (untrusted input) -------------------------
  const parsed = ActionRequestSchema.safeParse(request);
  if (!parsed.success) {
    return finish(
      ctx,
      "request.validation-failed",
      "request validation failed: untrusted proposal rejected",
      {
        verdict: "deny",
        reason: "request failed validation: untrusted planner output rejected",
        capability: "unknown",
        operation: "unknown",
        taskId: undefined,
        riskTier: 3,
        checks: [check("request.valid", false, "strict schema rejected")],
      },
    );
  }
  const req: ActionRequest = parsed.data;

  // -- M1-compat route: legacy capability ids keep M1 semantics ------------
  if (getLegacyCapability(req.capability) !== undefined) {
    return authorizeLegacy(req, ctx);
  }

  const checks: Array<AuthorizationCheck> = [
    check("request.valid", true, "strict schema accepted"),
  ];

  // -- step 2: resolve trusted capability definition -----------------------
  const definition: CapabilityDefinition | undefined =
    getCapabilityDefinition(req.capability);
  if (definition === undefined) {
    checks.push(check("capability.declared", false, "unknown capability"));
    return finish(
      ctx,
      "capability.lookup-failed",
      `capability lookup failed for "${req.capability}"`,
      {
        verdict: "deny",
        reason: `unknown capability "${req.capability}": default deny`,
        capability: req.capability,
        operation: req.operation,
        taskId: req.taskId,
        riskTier: 3,
        checks,
      },
    );
  }
  checks.push(
    check("capability.declared", true, `family "${definition.family}"`),
  );

  // -- step 3: resolve trusted task grant ----------------------------------
  // The planner's taskId is a lookup key, never proof. Grants come from
  // the TRUSTED context; a forged or unknown taskId simply finds nothing.
  if (req.taskId === undefined) {
    checks.push(check("task.bound", false, "request carries no taskId"));
    return finish(ctx, "authorization.unknown-task", "request without task binding rejected", {
      verdict: "deny",
      reason: "no task binding: default deny",
      capability: definition.id,
      operation: req.operation,
      taskId: undefined,
      riskTier: definition.riskTier,
      checks,
    });
  }
  const candidates = grantsForTask(ctx.grants, req.taskId);
  const live = candidates.filter(
    (g: TrustedTaskGrant): boolean =>
      g.capability === definition.id && !g.revoked,
  );
  const revokedMatch = candidates.some(
    (g: TrustedTaskGrant): boolean =>
      g.capability === definition.id && g.revoked,
  );
  if (live.length === 0) {
    checks.push(
      check(
        "task.grant",
        false,
        revokedMatch ? "only revoked grants" : "no grant for task+capability",
      ),
    );
    return finish(
      ctx,
      revokedMatch ? "authorization.denied" : "authorization.no-grant",
      revokedMatch
        ? `revoked grant used for "${definition.id}"`
        : `no grant for task "${req.taskId}" capability "${definition.id}"`,
      {
        verdict: "deny",
        reason: revokedMatch
          ? "grant revoked: default deny"
          : "no trusted grant binds this task to the capability: default deny",
        capability: definition.id,
        operation: req.operation,
        taskId: req.taskId,
        riskTier: definition.riskTier,
        checks,
      },
    );
  }
  checks.push(check("task.grant", true, `${live.length} live grant(s)`));

  // -- step 4: sleep-state enforcement --------------------------------------
  // SLEEP denies every gated capability, including previously valid ones.
  if (ctx.sleep === "SLEEP" && definition.sleepGated) {
    checks.push(check("sleep.open", false, "system is asleep"));
    return finish(
      ctx,
      "sleep.denied",
      `sleep gate denied "${definition.id}" while SLEEP`,
      {
        verdict: "deny",
        reason: `sleep gate: capability "${definition.id}" not allowed while SLEEP`,
        capability: definition.id,
        operation: req.operation,
        taskId: req.taskId,
        riskTier: definition.riskTier,
        checks,
      },
    );
  }
  checks.push(check("sleep.open", true, `system is ${ctx.sleep}`));

  // -- step 5: operation must be declared (exact match) ----------------------
  if (!isDeclaredOperation(definition, req.operation)) {
    checks.push(
      check("operation.declared", false, `undeclared "${req.operation}"`),
    );
    return finish(
      ctx,
      "operation.denied",
      `undeclared operation "${req.operation}" for "${definition.id}"`,
      {
        verdict: "deny",
        reason: `undeclared operation "${req.operation}": default deny`,
        capability: definition.id,
        operation: req.operation,
        taskId: req.taskId,
        riskTier: definition.riskTier,
        checks,
      },
    );
  }
  checks.push(check("operation.declared", true, req.operation));

  // -- step 6: scope containment ----------------------------------------------
  // Scoped capabilities require a resource inside a live grant's scope.
  // Unscoped capabilities must carry no resource (fail closed on extras).
  if (definition.scoped) {
    if (req.resource === undefined) {
      checks.push(check("scope.present", false, "resource missing"));
      return finish(
        ctx,
        "scope.denied",
        `missing resource for scoped capability "${definition.id}"`,
        {
          verdict: "deny",
          reason: "missing required resource: default deny",
          capability: definition.id,
          operation: req.operation,
          taskId: req.taskId,
          riskTier: definition.riskTier,
          checks,
        },
      );
    }
    const inside = live.some((g: TrustedTaskGrant): boolean =>
      isWithinScope(definition, g.scope, req.resource as string),
    );
    if (!inside) {
      checks.push(check("scope.inside", false, "resource outside grant scope"));
      return finish(
        ctx,
        "scope.denied",
        `scope denial for "${definition.id}" outside granted scope`,
        {
          verdict: "deny",
          reason: "resource outside trusted grant scope: default deny",
          capability: definition.id,
          operation: req.operation,
          taskId: req.taskId,
          riskTier: definition.riskTier,
          checks,
        },
      );
    }
    checks.push(check("scope.inside", true, "resource within grant scope"));
  } else if (req.resource !== undefined) {
    checks.push(check("scope.absent", false, "unexpected resource"));
    return finish(
      ctx,
      "scope.denied",
      `unexpected resource for unscoped capability "${definition.id}"`,
      {
        verdict: "deny",
        reason: "unexpected resource on unscoped capability: default deny",
        capability: definition.id,
        operation: req.operation,
        taskId: req.taskId,
        riskTier: definition.riskTier,
        checks,
      },
    );
  }

  // -- step 7: trusted risk tier (never from the request) -----------------------
  const tier: RiskTier = definition.riskTier;
  checks.push(check("risk.tier", true, `trusted tier ${tier}`));

  // -- steps 8+9: confirmation requirement + trusted confirmation state --------
  const confirmationKey = {
    taskId: req.taskId as string,
    capability: definition.id,
    operation: req.operation,
    resource: req.resource ?? "",
  };
  if (definition.requiresConfirmation || tier >= 2) {
    checks.push(
      check("confirmation.required", true, `tier ${tier} needs approval`),
    );
    if (!hasConfirmation(ctx.confirmations, confirmationKey)) {
      return finish(
        ctx,
        "confirmation.required",
        `confirmation required for "${definition.id}" tier ${tier}`,
        {
          verdict: "require-confirmation",
          reason: `capability "${definition.id}" (tier ${tier}) requires explicit human approval`,
          capability: definition.id,
          operation: req.operation,
          taskId: req.taskId,
          riskTier: tier,
          checks,
        },
      );
    }
    checks.push(check("confirmation.present", true, "trusted record found"));
    return finish(
      ctx,
      "confirmation.satisfied",
      `trusted confirmation satisfied for "${definition.id}"`,
      {
        verdict: "allow",
        reason: `explicit human approval recorded for "${definition.id}"`,
        capability: definition.id,
        operation: req.operation,
        taskId: req.taskId,
        riskTier: tier,
        checks,
      },
    );
  }

  // -- step 10: allow (low tiers, all gates passed) ------------------------------
  checks.push(check("confirmation.required", false, `tier ${tier} is low`));
  return finish(
    ctx,
    "authorization.allowed",
    `allowed "${definition.id}" tier ${tier}`,
    {
      verdict: "allow",
      reason: `capability "${definition.id}" granted at tier ${tier}`,
      capability: definition.id,
      operation: req.operation,
      taskId: req.taskId,
      riskTier: tier,
      checks,
    },
  );
}

/**
 * M1-compat route. Legacy ids (system.sleep, audit.*) keep byte-identical
 * M1 semantics by delegating to the frozen M1 evaluator. The M2 request
 * maps to action/capability; category and risk are never forwarded, so
 * planner risk metadata cannot leak into the legacy path either.
 */
function authorizeLegacy(
  req: ActionRequest,
  ctx: AuthorizationContext,
): AuthorizationResult {
  const legacy = evaluateProposal(
    { action: `${req.capability}:${req.operation}`, capability: req.capability },
    { sleep: ctx.sleep },
  );
  const checks: Array<AuthorizationCheck> = [
    check("request.valid", true, "strict schema accepted"),
    check("capability.legacy", true, "M1-compat path"),
  ];
  if (legacy.verdict === "allow") {
    return finish(ctx, "authorization.allowed", `allowed "${req.capability}" (M1-compat)`, {
      verdict: "allow",
      reason: legacy.reason,
      capability: req.capability,
      operation: req.operation,
      taskId: req.taskId,
      riskTier: 0,
      checks,
    });
  }
  if (legacy.verdict === "require-confirmation") {
    return finish(ctx, "confirmation.required", `confirmation required for "${req.capability}" (M1-compat)`, {
      verdict: "require-confirmation",
      reason: legacy.reason,
      capability: req.capability,
      operation: req.operation,
      taskId: req.taskId,
      riskTier: 0,
      checks,
    });
  }
  return finish(ctx, "authorization.denied", `denied "${req.capability}" (M1-compat)`, {
    verdict: "deny",
    reason: legacy.reason,
    capability: req.capability,
    operation: req.operation,
    taskId: req.taskId,
    riskTier: 0,
    checks,
  });
}
