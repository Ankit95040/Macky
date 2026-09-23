import { describe, expect, it } from "vitest";
import {
  appendSecurityEvent,
  createLog,
  redactSecrets,
} from "../src/kernel/audit.js";
import { authorize } from "../src/kernel/authorize.js";
import { makeCtx } from "./m2-fixtures.js";

describe("M2 audit events: outcomes recorded, secrets never logged", () => {
  it("each terminal outcome emits exactly one typed event", () => {
    const { ctx } = makeCtx();
    const allowed = authorize(
      {
        capability: "filesystem.read",
        operation: "read",
        resource: "/project/a.txt",
        taskId: "task-A",
      },
      ctx,
    );
    expect(allowed.log.events).toHaveLength(1);
    expect(allowed.log.events[0]?.type).toBe("authorization.allowed");

    const denied = authorize(
      { capability: "nope", operation: "x", taskId: "task-A" },
      ctx,
    );
    expect(denied.log.events).toHaveLength(1);
    expect(denied.log.events[0]?.type).toBe("capability.lookup-failed");

    const invalid = authorize({ garbage: true }, ctx);
    expect(invalid.log.events).toHaveLength(1);
    expect(invalid.log.events[0]?.type).toBe("request.validation-failed");
  });

  it("sequence numbers stay monotonic across chained evaluations", () => {
    const { ctx } = makeCtx();
    const r1 = authorize(
      {
        capability: "filesystem.read",
        operation: "read",
        resource: "/project/a.txt",
        taskId: "task-A",
      },
      ctx,
    );
    const r2 = authorize(
      { capability: "nope", operation: "x", taskId: "task-A" },
      { ...ctx, log: r1.log },
    );
    expect(r2.log.events.map((e) => e.seq)).toEqual([1, 2]);
  });

  it("secrets in request details are redacted before logging", () => {
    expect(redactSecrets("api_key=sk-live-abcdef123456")).toBe(
      "api_key=[REDACTED]",
    );
    expect(redactSecrets('token: "hunter2-secret"')).toBe("token: [REDACTED]");
    expect(
      redactSecrets("-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----"),
    ).toBe("[REDACTED-PEM]");

    const log = appendSecurityEvent(
      createLog(),
      "scope.denied",
      "resource password=hunter2 rejected",
      "AWAKE",
    );
    expect(log.events[0]?.detail).not.toContain("hunter2");
  });

  it("trusted lifecycle events append cleanly; planner cannot rewrite history", () => {
    const { ctx } = makeCtx();
    const log1 = appendSecurityEvent(
      ctx.log,
      "capability.issued",
      "issued g-x for task-A",
      "AWAKE",
    );
    const log2 = appendSecurityEvent(log1, "sleep.entered", "entered SLEEP", "SLEEP");
    expect(log2.events.map((e) => e.type)).toEqual([
      "capability.issued",
      "sleep.entered",
    ]);
    expect(ctx.log.events).toHaveLength(0);
  });
});
