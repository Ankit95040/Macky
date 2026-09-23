import { describe, expect, it } from "vitest";
import { authorize } from "../src/kernel/authorize.js";
import { issueGrant, revokeGrant } from "../src/kernel/task-grants.js";
import { makeCtx } from "./m2-fixtures.js";

describe("M2 revocation: stale capabilities fail closed", () => {
  it("issue → allow → revoke → deny", () => {
    const { ctx } = makeCtx();
    const req = {
      capability: "filesystem.read",
      operation: "read",
      resource: "/project/a.txt",
      taskId: "task-A",
    };
    expect(authorize(req, ctx).decision.verdict).toBe("allow");

    const revoked = revokeGrant(ctx.grants, "g-fs-read");
    expect(
      authorize(req, { ...ctx, grants: revoked }).decision.verdict,
    ).toBe("deny");

    // Original array untouched (persistent structure).
    expect(
      ctx.grants.find((g) => g.grantId === "g-fs-read")?.revoked,
    ).toBe(false);
  });

  it("revoking an unknown grant id changes nothing", () => {
    const { ctx } = makeCtx();
    const same = revokeGrant(ctx.grants, "g-does-not-exist");
    expect(same).toHaveLength(ctx.grants.length);
    expect(
      authorize(
        {
          capability: "filesystem.read",
          operation: "read",
          resource: "/project/a.txt",
          taskId: "task-A",
        },
        { ...ctx, grants: same },
      ).decision.verdict,
    ).toBe("allow");
  });

  it("trusted issuance validates: unknown capability / malformed scope throw", () => {
    expect(() =>
      issueGrant({
        grantId: "g-bad",
        taskId: "task-A",
        capability: "shell.exec",
        scope: "/",
      }),
    ).toThrow();
    expect(() =>
      issueGrant({
        grantId: "g-bad",
        taskId: "task-A",
        capability: "filesystem.read",
        scope: "relative/path",
      }),
    ).toThrow();
  });
});
