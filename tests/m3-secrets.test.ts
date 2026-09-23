import * as fs from "node:fs";
import { describe, expect, it } from "vitest";
import { run } from "../src/executor/executor.js";
import { makeExecCtx, makeSandbox } from "./m3-fixtures.js";

describe("M3 secret exposure: deny files, redact content", () => {
  it("redacts token content in an otherwise permitted file", () => {
    const sb = makeSandbox({ "app.txt": "start\napi_key=sk-live-abcdef123456789\nend" });
    try {
      const { ctx } = makeExecCtx(sb.root);
      const r = run(
        {
          capability: "filesystem.read",
          operation: "read",
          resource: `${sb.root}/app.txt`,
          taskId: "task-M3",
        },
        ctx,
      );
      expect(r.outcome.status).toBe("completed");
      if (r.outcome.status === "completed") {
        expect(r.outcome.redacted).toBe(true);
        expect(r.outcome.result as string).toContain("[REDACTED]");
        expect(r.outcome.result as string).not.toContain("sk-live-abcdef123456789");
      }
      expect(r.log.events.some((e) => e.type === "result.redacted")).toBe(true);
      const blob = r.log.events.map((e) => e.detail).join("\n");
      expect(blob).not.toContain("sk-live-abcdef123456789");
    } finally {
      sb.cleanup();
    }
  });

  it("redacts PEM blocks", () => {
    const sb = makeSandbox({
      "notes.txt":
        "hello\n-----BEGIN RSA PRIVATE KEY-----\nZmFrZXk=\n-----END RSA PRIVATE KEY-----\nbye",
    });
    try {
      const { ctx } = makeExecCtx(sb.root);
      const r = run(
        {
          capability: "filesystem.read",
          operation: "read",
          resource: `${sb.root}/notes.txt`,
          taskId: "task-M3",
        },
        ctx,
      );
      expect(r.outcome.status).toBe("completed");
      if (r.outcome.status === "completed") {
        expect(r.outcome.result as string).toContain("[REDACTED-PEM]");
        expect(r.outcome.result as string).not.toContain("ZmFrZXk=");
      }
    } finally {
      sb.cleanup();
    }
  });

  it("refuses binary content instead of returning it", () => {
    const sb = makeSandbox({ "clean.txt": "clean" });
    try {
      fs.writeFileSync(`${sb.root}/blob.bin`, Buffer.from([0x00, 0x01, 0x02, 0x41]));
      const { ctx } = makeExecCtx(sb.root);
      const r = run(
        {
          capability: "filesystem.read",
          operation: "read",
          resource: `${sb.root}/blob.bin`,
          taskId: "task-M3",
        },
        ctx,
      );
      expect(r.outcome.status).toBe("refused");
    } finally {
      sb.cleanup();
    }
  });
});
