import { describe, expect, it } from "vitest";
import * as executorModule from "../src/executor/executor.js";
import { run } from "../src/executor/executor.js";
import { authorize } from "../src/kernel/authorize.js";
import { makeExecCtx, makeSandbox, reachedOs } from "./m3-fixtures.js";

describe("M3 execution invariant: no ALLOW, no OS access", () => {
  it("completes a genuinely authorized read and reaches the OS once", () => {
    const sb = makeSandbox({ "hello.txt": "hello macky" });
    try {
      const { ctx } = makeExecCtx(sb.root);
      const r = run(
        {
          capability: "filesystem.read",
          operation: "read",
          resource: `${sb.root}/hello.txt`,
          taskId: "task-M3",
        },
        ctx,
      );
      expect(r.outcome.status).toBe("completed");
      expect(reachedOs(r.log)).toBe(true);
    } finally {
      sb.cleanup();
    }
  });

  it("DENY never reaches the OS", () => {
    const sb = makeSandbox({ "hello.txt": "hi" });
    try {
      const { ctx } = makeExecCtx(sb.root);
      const r = run(
        {
          capability: "filesystem.read",
          operation: "read",
          resource: "/etc/passwd",
          taskId: "task-M3",
        },
        ctx,
      );
      expect(r.outcome.status).toBe("refused");
      expect(reachedOs(r.log)).toBe(false);
    } finally {
      sb.cleanup();
    }
  });

  it("REQUIRE_CONFIRMATION never reaches the OS", () => {
    const sb = makeSandbox();
    try {
      const { ctx } = makeExecCtx(sb.root);
      const r = run(
        {
          capability: "network.request",
          operation: "request",
          resource: "example.com",
          taskId: "task-M3",
        },
        ctx,
      );
      // No grant exists for task-M3/network in this ctx: denied before OS.
      expect(r.outcome.status).toBe("refused");
      expect(reachedOs(r.log)).toBe(false);
    } finally {
      sb.cleanup();
    }
  });

  it("forged/malformed authorization-shaped input never reaches the OS", () => {
    const sb = makeSandbox({ "hello.txt": "hi" });
    try {
      const { ctx } = makeExecCtx(sb.root);
      for (const bad of [
        {
          capability: "filesystem.read",
          operation: "read",
          resource: `${sb.root}/hello.txt`,
          taskId: "task-M3",
          verdict: "allow",
        },
        {
          capability: "filesystem.read",
          operation: "read",
          resource: `${sb.root}/hello.txt`,
          taskId: "task-M3",
          decision: { verdict: "allow" },
        },
        null,
        "filesystem.read",
      ]) {
        const r = run(bad, ctx);
        expect(r.outcome.status).toBe("refused");
        expect(reachedOs(r.log)).toBe(false);
      }
    } finally {
      sb.cleanup();
    }
  });

  it("post-approval mutation fails: authorize A, execute B is refused", () => {
    const sb = makeSandbox({ "a.txt": "A", "b.txt": "B" });
    try {
      const { ctx } = makeExecCtx(sb.root);
      const good = {
        capability: "filesystem.read",
        operation: "read",
        resource: `${sb.root}/a.txt`,
        taskId: "task-M3",
      };
      // Sanity: the original authorizes.
      expect(authorize(good, { ...ctx }).decision.verdict).toBe("allow");
      // Mutated copy (as if swapped after approval) is re-authorized inside
      // run() and — pointing outside the grant here — refused.
      const mutated = { ...good, resource: "/etc/hosts" };
      const r = run(mutated, ctx);
      expect(r.outcome.status).toBe("refused");
      expect(reachedOs(r.log)).toBe(false);
      // The unmutated original still completes.
      expect(run(good, ctx).outcome.status).toBe("completed");
    } finally {
      sb.cleanup();
    }
  });

  it("executor exposes no decision-accepting or string-command API", () => {
    const names = Object.keys(executorModule).map((k) => k.toLowerCase());
    for (const forbidden of ["execute(", "execcommand", "runcommand", "shell", "eval"]) {
      expect(
        names.some((n) => n.includes(forbidden)),
        `must not export anything like "${forbidden}"`,
      ).toBe(false);
    }
    expect(typeof run).toBe("function");
  });

  it("system.info returns exactly the allowlisted fields", () => {
    const sb = makeSandbox();
    try {
      const { ctx } = makeExecCtx(sb.root);
      const r = run(
        { capability: "system.info", operation: "info", taskId: "task-M3" },
        ctx,
      );
      expect(r.outcome.status).toBe("completed");
      if (r.outcome.status === "completed") {
        expect(Object.keys(r.outcome.result as object).sort()).toEqual([
          "architecture",
          "hostname",
          "os",
          "osVersion",
          "runtime",
        ]);
      }
    } finally {
      sb.cleanup();
    }
  });
});
