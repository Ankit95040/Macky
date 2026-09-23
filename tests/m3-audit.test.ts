import { describe, expect, it } from "vitest";
import { run } from "../src/executor/executor.js";
import { makeExecCtx, makeSandbox } from "./m3-fixtures.js";

describe("M3 audit: every executor attempt leaves a typed, content-free trail", () => {
  it("completed run emits allowed → started → completed, no file contents", () => {
    const sb = makeSandbox({ "a.txt": "SECRET-FREE hello" });
    try {
      const { ctx } = makeExecCtx(sb.root);
      const r = run(
        {
          capability: "filesystem.read",
          operation: "read",
          resource: `${sb.root}/a.txt`,
          taskId: "task-M3",
        },
        ctx,
      );
      expect(r.outcome.status).toBe("completed");
      expect(r.log.events.map((e) => e.type)).toEqual([
        "authorization.allowed",
        "execution.started",
        "execution.completed",
      ]);
      const blob = r.log.events.map((e) => `${e.type} ${e.detail}`).join("\n");
      expect(blob).not.toContain("SECRET-FREE hello");
      expect(r.log.events.map((e) => e.seq)).toEqual([1, 2, 3]);
    } finally {
      sb.cleanup();
    }
  });

  it("refused run emits the auth outcome plus execution.rejected", () => {
    const sb = makeSandbox();
    try {
      const { ctx } = makeExecCtx(sb.root);
      const malformed = run({ garbage: true }, ctx);
      expect(malformed.outcome.status).toBe("refused");
      const mtypes = malformed.log.events.map((e) => e.type);
      expect(mtypes[mtypes.length - 1]).toBe("execution.rejected");
      expect(mtypes).toContain("request.validation-failed");

      const unknown = run(
        { capability: "shell.exec", operation: "run", taskId: "task-M3" },
        ctx,
      );
      expect(unknown.outcome.status).toBe("refused");
      expect(unknown.log.events.map((e) => e.type)).toContain(
        "capability.lookup-failed",
      );
    } finally {
      sb.cleanup();
    }
  });

  it("redaction and limits leave their own typed events", () => {
    const sb = makeSandbox({ "t.txt": "token: hunter2-secret" });
    try {
      const { ctx } = makeExecCtx(sb.root);
      const r = run(
        {
          capability: "filesystem.read",
          operation: "read",
          resource: `${sb.root}/t.txt`,
          taskId: "task-M3",
        },
        ctx,
      );
      expect(r.log.events.some((e) => e.type === "result.redacted")).toBe(true);
      const blob = r.log.events.map((e) => e.detail).join("\n");
      expect(blob).not.toContain("hunter2-secret");
    } finally {
      sb.cleanup();
    }
  });
});
