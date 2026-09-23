import { describe, expect, it } from "vitest";
import { authorize } from "../src/kernel/authorize.js";
import * as authorizeModule from "../src/kernel/authorize.js";
import * as modelModule from "../src/kernel/capability-model.js";
import * as grantsModule from "../src/kernel/task-grants.js";
import {
  CAPABILITY_DEFINITIONS,
  getCapabilityDefinition,
} from "../src/kernel/capability-model.js";
import { makeCtx } from "./m2-fixtures.js";

describe("M2 policy immutability: planner path mutates nothing", () => {
  it("registry and grants are frozen; tampering with copies has no effect", () => {
    expect(Object.isFrozen(CAPABILITY_DEFINITIONS)).toBe(true);
    const before = getCapabilityDefinition("filesystem.read");
    expect(before).toBeDefined();
    expect(Object.isFrozen(before)).toBe(true);

    // Attempt to poison a local copy: later evaluations unaffected.
    const { ctx } = makeCtx();
    const mutableCopy = { ...(before as object) } as Record<string, unknown>;
    mutableCopy["riskTier"] = 0;
    mutableCopy["operations"] = ["read", "write", "delete"];
    const r = authorize(
      {
        capability: "filesystem.delete",
        operation: "delete",
        resource: "/project/x.txt",
        taskId: "task-A",
      },
      ctx,
    );
    // filesystem.delete grant exists in fixtures but needs confirmation.
    expect(r.decision.riskTier).toBe(3);
    expect(r.decision.verdict).toBe("require-confirmation");
  });

  it("no policy-mutation API is reachable from planner-facing modules", () => {
    const allExports = [
      ...Object.keys(authorizeModule),
      ...Object.keys(modelModule),
      ...Object.keys(grantsModule),
    ].map((k) => k.toLowerCase());
    for (const forbidden of [
      "updatepolicy",
      "setpolicy",
      "mutate",
      "definecapability",
      "registercapability",
      "mintgrant",
      "setrisk",
      "override",
      "setsleep",
      "wake",
    ]) {
      expect(
        allExports.some((n) => n.includes(forbidden)),
        `must not export anything like "${forbidden}"`,
      ).toBe(false);
    }
  });

  it("repeated evaluation is stable: no cross-request state leaks", () => {
    const { ctx } = makeCtx();
    const req = {
      capability: "git.read",
      operation: "log",
      resource: "/project",
      taskId: "task-A",
    };
    const first = authorize(req, ctx).decision;
    // Attacker tries to smuggle authority between calls via shared object.
    const poisoned = { ...req, capability: "git.push" };
    expect(authorize(poisoned, ctx).decision.verdict).toBe("deny");
    expect(authorize(req, ctx).decision).toEqual(first);
  });

  it("policy-modification capabilities do not exist (absence = ungrantable)", () => {
    for (const id of [
      "policy.modify",
      "policy.write",
      "capability.mint",
      "secrets.read",
      "system.wake",
      "shell.exec",
    ]) {
      expect(getCapabilityDefinition(id)).toBeUndefined();
      const { ctx } = makeCtx();
      expect(
        authorize({ capability: id, operation: "any", taskId: "task-A" }, ctx)
          .decision.verdict,
      ).toBe("deny");
    }
  });
});
