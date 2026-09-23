import { describe, expect, it } from "vitest";
import {
  authorize,
  type AuthorizationContext,
} from "../src/kernel/authorize.js";
import {
  recordConfirmation,
  createConfirmationStore,
} from "../src/kernel/confirm.js";
import { issueGrant } from "../src/kernel/task-grants.js";
import { makeCtx } from "./m2-fixtures.js";

function deleteCtx(base: AuthorizationContext): AuthorizationContext {
  return {
    ...base,
    grants: [
      issueGrant({
        grantId: "g-del",
        taskId: "task-A",
        capability: "filesystem.delete",
        scope: "/project",
      }),
    ],
    confirmations: createConfirmationStore(),
  };
}

describe("M2 risk escalation: trusted tier always wins", () => {
  it("Tier3 capability with forged Tier0 claim is rejected AND stays Tier3", () => {
    const { ctx } = makeCtx();
    const forged = authorize(
      {
        capability: "filesystem.delete",
        operation: "delete",
        resource: "/project/old.txt",
        taskId: "task-A",
        risk: "Tier0",
      } as unknown,
      ctx,
    );
    // Forged field → strict schema fails closed.
    expect(forged.decision.verdict).toBe("deny");

    // Same request without forgery: trusted Tier3 applies
    // (confirmation required, never a silent allow).
    const clean = authorize(
      {
        capability: "filesystem.delete",
        operation: "delete",
        resource: "/project/old.txt",
        taskId: "task-A",
      },
      deleteCtx(ctx),
    );
    expect(clean.decision.verdict).toBe("require-confirmation");
    expect(clean.decision.riskTier).toBe(3);
  });

  it("reverse direction: forged high-risk claim on Tier0 cannot change the tier", () => {
    const { ctx } = makeCtx();
    const forged = authorize(
      {
        capability: "filesystem.read",
        operation: "read",
        resource: "/project/a.txt",
        taskId: "task-A",
        risk: "Tier3",
      } as unknown,
      ctx,
    );
    expect(forged.decision.verdict).toBe("deny");

    const clean = authorize(
      {
        capability: "filesystem.read",
        operation: "read",
        resource: "/project/a.txt",
        taskId: "task-A",
      },
      ctx,
    );
    expect(clean.decision.verdict).toBe("allow");
    expect(clean.decision.riskTier).toBe(0);
  });

  it("trusted confirmation satisfies Tier3; planner approval never does", () => {
    const { ctx } = makeCtx();
    const base = deleteCtx(ctx);
    const confirmed = {
      ...base,
      confirmations: recordConfirmation(base.confirmations, {
        taskId: "task-A",
        capability: "filesystem.delete",
        operation: "delete",
        resource: "/project/old.txt",
      }),
    };
    const r = authorize(
      {
        capability: "filesystem.delete",
        operation: "delete",
        resource: "/project/old.txt",
        taskId: "task-A",
      },
      confirmed,
    );
    expect(r.decision.verdict).toBe("allow");
    expect(r.decision.riskTier).toBe(3);
  });
});
