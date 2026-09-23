import * as fs from "node:fs";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import { LIMITS } from "../src/executor/limits.js";
import { run } from "../src/executor/executor.js";
import { makeExecCtx, makeSandbox } from "./m3-fixtures.js";

describe("M3 resource limits: bounded, never silently truncated", () => {
  it("denies files over MAX_FILE_BYTES", () => {
    const sb = makeSandbox();
    try {
      const big = "x".repeat(LIMITS.MAX_FILE_BYTES + 1);
      fs.writeFileSync(path.join(sb.root, "big.txt"), big);
      const { ctx } = makeExecCtx(sb.root);
      const r = run(
        {
          capability: "filesystem.read",
          operation: "read",
          resource: `${sb.root}/big.txt`,
          taskId: "task-M3",
        },
        ctx,
      );
      expect(r.outcome.status).toBe("refused");
      if (r.outcome.status === "refused") {
        expect(r.outcome.reason).toMatch(/limit/i);
      }
      expect(r.log.events.some((e) => e.type === "limit.exceeded")).toBe(true);
    } finally {
      sb.cleanup();
    }
  });

  it("reads files exactly at the limit", () => {
    const sb = makeSandbox();
    try {
      fs.writeFileSync(
        path.join(sb.root, "edge.txt"),
        "y".repeat(LIMITS.MAX_FILE_BYTES),
      );
      const { ctx } = makeExecCtx(sb.root);
      const r = run(
        {
          capability: "filesystem.read",
          operation: "read",
          resource: `${sb.root}/edge.txt`,
          taskId: "task-M3",
        },
        ctx,
      );
      expect(r.outcome.status).toBe("completed");
    } finally {
      sb.cleanup();
    }
  });

  it("denies directories over MAX_DIR_ENTRIES", () => {
    const sb = makeSandbox();
    try {
      for (let i = 0; i < LIMITS.MAX_DIR_ENTRIES + 1; i += 1) {
        fs.writeFileSync(path.join(sb.root, `f-${i}.txt`), "z");
      }
      const { ctx } = makeExecCtx(sb.root);
      const r = run(
        {
          capability: "filesystem.read",
          operation: "list",
          resource: sb.root,
          taskId: "task-M3",
        },
        ctx,
      );
      expect(r.outcome.status).toBe("refused");
      if (r.outcome.status === "refused") {
        expect(r.outcome.reason).toMatch(/limit/i);
      }
    } finally {
      sb.cleanup();
    }
  });

  it("limits are conservative constants, listing is non-recursive", () => {
    expect(LIMITS.MAX_FILE_BYTES).toBeLessThanOrEqual(64 * 1024);
    expect(LIMITS.MAX_DIR_ENTRIES).toBeLessThanOrEqual(200);
    expect(LIMITS.MAX_RESULT_BYTES).toBeLessThanOrEqual(256 * 1024);
    expect(LIMITS.LIST_RECURSIVE).toBe(false);
  });
});
