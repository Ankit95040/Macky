import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import { boot } from "../src/bootstrap/boot.js";
import { grantToSession, runDurable, wakeSession } from "../src/persistence/session.js";

function tmpDir(): string {
  return fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "macky-m4-")));
}

const FAKE_PEM = "-----BEGIN RSA PRIVATE KEY-----\nZmFrZXk=\n-----END RSA PRIVATE KEY-----";

describe("M4 audit secrecy: synthetic secrets never reach disk", () => {
  it("no secret survives in audit.jsonl or security-state.json", () => {
    const dir = tmpDir();
    const work = tmpDir();
    try {
      const booted = boot(dir);
      if (!booted.ok) return;
      const s = booted.session;
      grantToSession(s, {
        grantId: "g-w",
        taskId: "task-A",
        capability: "filesystem.read",
        scope: work,
      });
      fs.writeFileSync(
        path.join(work, "leak.txt"),
        `api_key=sk-live-abcdef123456789\npassword=hunter2-secret\n${FAKE_PEM}\n`,
      );
      expect(wakeSession(s, { kind: "ui-action" })).toBe(true);
      const r = runDurable(s, {
        epoch: s.epoch,
        request: {
          capability: "filesystem.read",
          operation: "read",
          resource: `${work}/leak.txt`,
          taskId: "task-A",
        },
      });
      expect(r.outcome.status).toBe("completed");
      const audit = fs.readFileSync(path.join(dir, "audit.jsonl"), "utf8");
      const state = fs.readFileSync(path.join(dir, "security-state.json"), "utf8");
      for (const secret of ["sk-live-abcdef123456789", "hunter2-secret", "ZmFrZXk="]) {
        expect(audit, secret).not.toContain(secret);
        expect(state, secret).not.toContain(secret);
      }
      // State file carries only version + epoch numbers.
      expect(JSON.parse(state)).toEqual({ schemaVersion: 1, epoch: 1 });
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
      fs.rmSync(work, { recursive: true, force: true });
    }
  });
});
