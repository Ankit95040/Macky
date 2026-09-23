import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import { boot } from "../src/bootstrap/boot.js";
import {
  grantToSession,
  runDurable,
  wakeSession,
} from "../src/persistence/session.js";import { verifyAuditFile } from "../src/persistence/audit-store.js";

function tmpDir(): string {
  return fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "macky-m4-")));
}

describe("M4 durable execution: M3 reads work end-to-end, degrade fails closed", () => {
  it("authorized read completes and persists its full trail", () => {
    const dir = tmpDir();
    const work = tmpDir();
    try {
      const booted = boot(dir);
      if (!booted.ok) return;
      const s = booted.session;
      expect(
        grantToSession(s, {
          grantId: "g-w",
          taskId: "task-A",
          capability: "filesystem.read",
          scope: work,
        }      ).ok,
      ).toBe(true);
      fs.writeFileSync(path.join(work, "a.txt"), "hello");
      expect(wakeSession(s, { kind: "ui-action" })).toBe(true);
      const r = runDurable(s, {
        epoch: s.epoch,
        request: {
          capability: "filesystem.read",
          operation: "read",
          resource: `${work}/a.txt`,
          taskId: "task-A",
        },
      });
      expect(r.outcome.status).toBe("completed");
      expect(r.auditPersisted).toBe(true);
      const v = verifyAuditFile(path.join(dir, "audit.jsonl"));
      expect(v.ok).toBe(true);
      const types = v.events.map((e) => e.type);
      expect(types).toContain("capability.issued");
      expect(types).toContain("authorization.allowed");
      expect(types).toContain("execution.completed");
      expect(new Set(v.events.map((e) => e.epoch))).toEqual(new Set([s.epoch]));
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
      fs.rmSync(work, { recursive: true, force: true });
    }
  });

  it("unwritable sink degrades: pre-execution refusal, then session-wide refuse", () => {
    const dir = tmpDir();
    const work = tmpDir();
    try {
      const booted = boot(dir);
      if (!booted.ok) return;
      const s = booted.session;
      // Break the sink: replace the audit file with a directory.
      fs.rmSync(path.join(dir, "audit.jsonl"));
      fs.mkdirSync(path.join(dir, "audit.jsonl"));
      grantToSession(s, {
        grantId: "g-w",
        taskId: "task-A",
        capability: "filesystem.read",
        scope: work,
      });
      fs.writeFileSync(path.join(work, "a.txt"), "hello");
      const r = runDurable(s, {
        epoch: s.epoch,
        request: {
          capability: "filesystem.read",
          operation: "read",
          resource: `${work}/a.txt`,
          taskId: "task-A",
        },
      });
      // Refused BEFORE any OS touch; session degraded afterwards.
      expect(r.outcome.status).toBe("refused");
      expect(s.auditHealthy).toBe(false);
      const again = runDurable(s, { epoch: s.epoch, request: {} });
      expect(again.outcome.status).toBe("refused");
      if (again.outcome.status === "refused") {
        expect(again.outcome.stage).toBe("audit");
      }
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
      fs.rmSync(work, { recursive: true, force: true });
    }
  });

  it("planner cannot steer persistence: forged paths/config in envelope die", () => {
    const dir = tmpDir();
    try {
      const booted = boot(dir);
      if (!booted.ok) return;
      const s = booted.session;
      wakeSession(s, { kind: "ui-action" });
      for (const evil of [
        { epoch: s.epoch, request: {}, auditPath: "/tmp/evil.jsonl" },
        { epoch: s.epoch, request: {}, stateDir: "/tmp/evil" },
        { epoch: s.epoch, request: { capability: "filesystem.read", operation: "read", resource: "/x", taskId: "t", auditPath: "/tmp/e" } },
      ]) {
        const r = runDurable(s, evil);
        expect(r.outcome.status).toBe("refused");
      }
      expect(fs.existsSync("/tmp/evil.jsonl")).toBe(false);
      expect(fs.existsSync("/tmp/evil")).toBe(false);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
