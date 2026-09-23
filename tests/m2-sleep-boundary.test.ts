import { describe, expect, it } from "vitest";
import { authorize } from "../src/kernel/authorize.js";
import {
  CAPABILITY_DEFINITIONS,
  type CapabilityFamily,
} from "../src/kernel/capability-model.js";
import { enterSleep, requestWake } from "../src/kernel/sleep.js";
import { makeCtx } from "./m2-fixtures.js";

const PROBE: Record<CapabilityFamily, () => Record<string, string>> = {
  filesystem: () => ({
    capability: "filesystem.read",
    operation: "read",
    resource: "/project/a.txt",
    taskId: "task-A",
  }),
  terminal: () => ({
    capability: "terminal.run",
    operation: "run-tests",
    taskId: "task-A",
  }),
  git: () => ({
    capability: "git.read",
    operation: "status",
    resource: "/project",
    taskId: "task-A",
  }),
  browser: () => ({
    capability: "browser.read",
    operation: "read",
    resource: "/project/page",
    taskId: "task-A",
  }),
  screen: () => ({
    capability: "screen.capture",
    operation: "capture",
    taskId: "task-A",
  }),
  "app-control": () => ({
    capability: "app.control",
    operation: "control",
    taskId: "task-A",
  }),
  keyboard: () => ({
    capability: "keyboard.input",
    operation: "send",
    taskId: "task-A",
  }),
  mouse: () => ({
    capability: "mouse.input",
    operation: "send",
    taskId: "task-A",
  }),
  network: () => ({
    capability: "network.request",
    operation: "request",
    resource: "example.com",
    taskId: "task-A",
  }),
  memory: () => ({
    capability: "memory.read",
    operation: "read",
    resource: "/mem/session",
    taskId: "task-A",
  }),
  audit: () => ({
    capability: "audit.append",
    operation: "append",
    taskId: "task-A",
  }),
  sleep: () => ({
    capability: "system.sleep",
    operation: "sleep",
    taskId: "task-A",
  }),
};

describe("M2 sleep enforcement: asleep denies observation and execution", () => {
  it("denies every capability family while SLEEP", () => {
    const families = new Set<CapabilityFamily>(
      CAPABILITY_DEFINITIONS.map((d) => d.family),
    );
    expect(families.size).toBeGreaterThanOrEqual(12);
    for (const family of families) {
      const probe = PROBE[family];
      if (probe === undefined) {
        throw new Error(`missing sleep probe for family "${family}"`);
      }
      const { ctx } = makeCtx({ sleep: "SLEEP" });
      const r = authorize(probe(), ctx);
      if (family === "audit" || family === "sleep") {
        // M1-compat: audit/sleep stay available so transitions are recorded.
        expect(r.decision.verdict, family).toBe("allow");
      } else {
        expect(r.decision.verdict, family).toBe("deny");
      }
    }
  });

  it("sleep transition revokes usability: allow → sleep → deny", () => {
    const { ctx } = makeCtx({ sleep: "AWAKE" });
    const req = {
      capability: "filesystem.read",
      operation: "read",
      resource: "/project/src/index.ts",
      taskId: "task-A",
    };
    expect(authorize(req, ctx).decision.verdict).toBe("allow");

    const asleep = { ...ctx, sleep: enterSleep(ctx.sleep) };
    const denied = authorize(req, asleep);
    expect(denied.decision.verdict).toBe("deny");
    expect(denied.decision.reason).toMatch(/sleep/i);
  });

  it("inverse: sleep → explicit trusted wake → normal evaluation resumes", () => {
    const { ctx } = makeCtx({ sleep: "SLEEP" });
    const req = {
      capability: "filesystem.read",
      operation: "read",
      resource: "/project/src/index.ts",
      taskId: "task-A",
    };
    expect(authorize(req, ctx).decision.verdict).toBe("deny");

    // Planner cannot wake: a wake CLAIM inside the request is just a
    // forged field and fails closed.
    const claimed = authorize(
      { ...req, wake: true, kind: "ui-action" },
      ctx,
    );
    expect(claimed.decision.verdict).toBe("deny");

    // Only the trusted local action wakes.
    const awake = { ...ctx, sleep: requestWake(ctx.sleep, { kind: "ui-action" }) };
    expect(authorize(req, awake).decision.verdict).toBe("allow");
  });

  it("pre-sleep confirmation does not survive sleep", () => {
    const { ctx } = makeCtx({ sleep: "AWAKE" });
    const req = {
      capability: "network.request",
      operation: "request",
      resource: "example.com",
      taskId: "task-A",
    };
    // Tier2 without confirmation → require-confirmation while awake.
    expect(authorize(req, ctx).decision.verdict).toBe("require-confirmation");
    // Same request while asleep → hard deny, not confirmation-pending.
    const asleep = { ...ctx, sleep: "SLEEP" as const };
    expect(authorize(req, asleep).decision.verdict).toBe("deny");
  });
});
