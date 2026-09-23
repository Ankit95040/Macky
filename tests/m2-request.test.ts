import { describe, expect, it } from "vitest";
import { authorize } from "../src/kernel/authorize.js";
import { makeCtx } from "./m2-fixtures.js";

describe("M2 request attacks: malformed/forged input fails closed", () => {
  it("denies unknown capabilities", () => {
    const { ctx } = makeCtx();
    const r = authorize(
      { capability: "shell.exec", operation: "run", taskId: "task-A" },
      ctx,
    );
    expect(r.decision.verdict).toBe("deny");
  });

  it("denies malformed requests (null, empty, wrong types)", () => {
    const { ctx } = makeCtx();
    for (const bad of [
      null,
      undefined,
      {},
      { capability: "", operation: "" },
      { capability: 42, operation: "read" },
      "filesystem.read",
      [],
    ]) {
      expect(authorize(bad, ctx).decision.verdict).toBe("deny");
    }
  });

  it("denies missing capability / missing operation", () => {
    const { ctx } = makeCtx();
    expect(
      authorize({ operation: "read", taskId: "task-A" }, ctx).decision.verdict,
    ).toBe("deny");
    expect(
      authorize({ capability: "filesystem.read", taskId: "task-A" }, ctx)
        .decision.verdict,
    ).toBe("deny");
  });

  it("denies invalid operations for a declared capability", () => {
    const { ctx } = makeCtx();
    const r = authorize(
      {
        capability: "filesystem.read",
        operation: "delete",
        resource: "/project/a.txt",
        taskId: "task-A",
      },
      ctx,
    );
    expect(r.decision.verdict).toBe("deny");
  });

  it("denies missing resource on scoped capabilities", () => {
    const { ctx } = makeCtx();
    expect(
      authorize(
        { capability: "filesystem.read", operation: "read", taskId: "task-A" },
        ctx,
      ).decision.verdict,
    ).toBe("deny");
  });

  it("denies unexpected resource on unscoped capabilities", () => {
    const { ctx } = makeCtx();
    expect(
      authorize(
        {
          capability: "screen.capture",
          operation: "capture",
          resource: "/tmp/x",
          taskId: "task-A",
        },
        ctx,
      ).decision.verdict,
    ).toBe("deny");
  });

  it("forged approval / risk / confirmation fields have zero authority (strict schema rejects)", () => {
    const { ctx } = makeCtx();
    const forged = [
      { approved: true },
      { risk: "Tier0" },
      { risk: 0 },
      { confirmedBy: "user" },
      { confirmationToken: "abc123" },
      { confirmed: true },
      { policy: "allow-all" },
      { scope: "/" },
      { grant: "admin" },
      { code: "rm -rf /" },
      { command: "whoami" },
    ];
    for (const extra of forged) {
      const r = authorize(
        {
          capability: "filesystem.read",
          operation: "read",
          resource: "/project/a.txt",
          taskId: "task-A",
          ...extra,
        },
        ctx,
      );
      expect(r.decision.verdict, JSON.stringify(extra)).toBe("deny");
    }
  });

  it("forged task identity finds no trusted grant", () => {
    const { ctx } = makeCtx();
    const r = authorize(
      {
        capability: "filesystem.read",
        operation: "read",
        resource: "/project/a.txt",
        taskId: "task-ATTACKER",
      },
      ctx,
    );
    expect(r.decision.verdict).toBe("deny");
  });

  it("request without task binding is denied", () => {
    const { ctx } = makeCtx();
    const r = authorize(
      {
        capability: "filesystem.read",
        operation: "read",
        resource: "/project/a.txt",
      },
      ctx,
    );
    expect(r.decision.verdict).toBe("deny");
  });

  it("authorize is pure: no execution, no mutation, repeatable", () => {
    const { ctx } = makeCtx();
    const req = {
      capability: "filesystem.read",
      operation: "read",
      resource: "/project/a.txt",
      taskId: "task-A",
    };
    const logBefore = ctx.log.events.length;
    const r1 = authorize(req, ctx);
    const r2 = authorize(req, ctx);
    expect(r1.decision).toEqual(r2.decision);
    expect(ctx.log.events).toHaveLength(logBefore);
    expect(r1.log.events).toHaveLength(logBefore + 1);
  });

  it("allows a well-formed in-scope read (baseline sanity)", () => {
    const { ctx } = makeCtx();
    const r = authorize(
      {
        capability: "filesystem.read",
        operation: "read",
        resource: "/project/src/index.ts",
        taskId: "task-A",
      },
      ctx,
    );
    expect(r.decision.verdict).toBe("allow");
    expect(r.decision.riskTier).toBe(0);
  });
});
