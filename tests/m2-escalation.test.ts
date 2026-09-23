import { describe, expect, it } from "vitest";
import { authorize } from "../src/kernel/authorize.js";
import { makeCtx } from "./m2-fixtures.js";

/**
 * Given filesystem.read("/project") (+ git.read + network/example.com),
 * every broadening attempt must be denied.
 */
describe("M2 capability escalation: grants never broaden", () => {
  it('denies filesystem.read("/") (scope escape to root)', () => {
    const { ctx } = makeCtx();
    expect(
      authorize(
        {
          capability: "filesystem.read",
          operation: "read",
          resource: "/",
          taskId: "task-A",
        },
        ctx,
      ).decision.verdict,
    ).toBe("deny");
  });

  it('denies filesystem.read("/project-evil") (prefix sibling, segment boundary)', () => {
    const { ctx } = makeCtx();
    expect(
      authorize(
        {
          capability: "filesystem.read",
          operation: "read",
          resource: "/project-evil/secret.txt",
          taskId: "task-A",
        },
        ctx,
      ).decision.verdict,
    ).toBe("deny");
  });

  it('denies filesystem.read("/etc/passwd") (outside scope)', () => {
    const { ctx } = makeCtx();
    expect(
      authorize(
        {
          capability: "filesystem.read",
          operation: "read",
          resource: "/etc/passwd",
          taskId: "task-A",
        },
        ctx,
      ).decision.verdict,
    ).toBe("deny");
  });

  it('denies path traversal "/project/../etc/passwd"', () => {
    const { ctx } = makeCtx();
    expect(
      authorize(
        {
          capability: "filesystem.read",
          operation: "read",
          resource: "/project/../etc/passwd",
          taskId: "task-A",
        },
        ctx,
      ).decision.verdict,
    ).toBe("deny");
  });

  it('denies filesystem.write("/project") (capability escalation read→write)', () => {
    const { ctx } = makeCtx();
    expect(
      authorize(
        {
          capability: "filesystem.write",
          operation: "create",
          resource: "/project/new.txt",
          taskId: "task-A",
        },
        ctx,
      ).decision.verdict,
    ).toBe("deny");
  });

  it('denies filesystem.write("/") (double escalation)', () => {
    const { ctx } = makeCtx();
    expect(
      authorize(
        {
          capability: "filesystem.write",
          operation: "create",
          resource: "/evil.txt",
          taskId: "task-A",
        },
        ctx,
      ).decision.verdict,
    ).toBe("deny");
  });

  it("denies terminal.run (ungranted family)", () => {
    const { ctx } = makeCtx();
    expect(
      authorize(
        { capability: "terminal.run", operation: "run-tests", taskId: "task-A" },
        ctx,
      ).decision.verdict,
    ).toBe("deny");
  });

  it('denies network.request("attacker.com") (domain scope escape)', () => {
    const { ctx } = makeCtx();
    expect(
      authorize(
        {
          capability: "network.request",
          operation: "request",
          resource: "attacker.com",
          taskId: "task-A",
        },
        ctx,
      ).decision.verdict,
    ).toBe("deny");
    expect(
      authorize(
        {
          capability: "network.request",
          operation: "request",
          resource: "example.com.evil.com",
          taskId: "task-A",
        },
        ctx,
      ).decision.verdict,
    ).toBe("deny");
  });

  it("denies operation escalation within a granted family (git.read grant, commit op)", () => {
    const { ctx } = makeCtx();
    expect(
      authorize(
        {
          capability: "git.read",
          operation: "commit",
          resource: "/project",
          taskId: "task-A",
        },
        ctx,
      ).decision.verdict,
    ).toBe("deny");
  });

  it("allows legitimate in-scope uses (no over-denial)", () => {
    const { ctx } = makeCtx();
    expect(
      authorize(
        {
          capability: "filesystem.read",
          operation: "list",
          resource: "/project",
          taskId: "task-A",
        },
        ctx,
      ).decision.verdict,
    ).toBe("allow");
    // Tier2 network grant is valid but still needs human approval:
    // the grant gets the request *to* the confirmation stage, never past it.
    const net = authorize(
      {
        capability: "network.request",
        operation: "request",
        resource: "api.example.com",
        taskId: "task-A",
      },
      ctx,
    );
    expect(net.decision.verdict).toBe("require-confirmation");
    expect(net.decision.riskTier).toBe(2);
  });
});
