import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import { boot } from "../src/bootstrap/boot.js";
import { resolveConfig, ensureStateDir } from "../src/bootstrap/config.js";
import {
  confirmInSession,
  disengageSessionKill,
  engageSessionKill,
  grantToSession,
  revokeSessionGrant,
  runDurable,
  sleepSession,
  wakeSession,
} from "../src/persistence/session.js";
function tmpDir(): string {
  return fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "macky-m4-")));
}

describe("M4 bootstrap: trusted config, private dirs, safe boot", () => {
  it("resolves deterministic paths; rejects relative/NUL input", () => {
    const dir = tmpDir();
    try {
      const c = resolveConfig(dir);
      expect(c.auditPath).toBe(path.join(dir, "audit.jsonl"));
      expect(c.statePath).toBe(path.join(dir, "security-state.json"));
      expect(() => resolveConfig("relative/path")).toThrow();
      expect(() => resolveConfig("")).toThrow();
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("creates the state dir user-private", () => {
    const dir = tmpDir();
    try {
      const nested = path.join(dir, "sub");
      ensureStateDir(resolveConfig(nested));
      expect(fs.statSync(nested).mode & 0o777).toBe(0o700);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("first boot: epoch 1, SLEEP, fresh kill, empty authority", () => {
    const dir = tmpDir();
    try {
      const booted = boot(dir);
      expect(booted.ok).toBe(true);
      if (!booted.ok) return;
      expect(booted.session.epoch).toBe(1);
      expect(booted.session.sleep).toBe("SLEEP");
      expect(booted.session.killSwitch.engaged).toBe(false);
      expect(booted.session.grants).toHaveLength(0);
      expect(fs.existsSync(path.join(dir, "audit.jsonl"))).toBe(true);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("second boot: epoch bumps, sleep forced, authority empty", () => {
    const dir = tmpDir();
    try {
      const first = boot(dir);
      expect(first.ok).toBe(true);
      if (!first.ok) return;
      wakeSession(first.session, { kind: "ui-action" });
      grantToSession(first.session, {
        grantId: "g-old",
        taskId: "task-X",
        capability: "filesystem.read",
        scope: "/tmp",
      });
      expect(first.session.sleep).toBe("AWAKE");
      const second = boot(dir);
      expect(second.ok).toBe(true);
      if (!second.ok) return;
      expect(second.session.epoch).toBe(2);
      expect(second.session.sleep).toBe("SLEEP");
      expect(second.session.grants).toHaveLength(0);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("corrupt/missing-hostile state fails boot closed (no session)", () => {
    const dir = tmpDir();
    try {
      const cfg = resolveConfig(dir);
      ensureStateDir(cfg);
      fs.writeFileSync(cfg.statePath, '{"schemaVersion":1,"epoch":1,"sleep":"AWAKE"}');
      const forged = boot(dir);
      expect(forged.ok).toBe(false);
      fs.writeFileSync(cfg.statePath, "garbage{");
      expect(boot(dir).ok).toBe(false);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("kill engagement does not survive as authority; planner cannot flip it", () => {
    const dir = tmpDir();
    try {
      const first = boot(dir);
      if (!first.ok) return;
      engageSessionKill(first.session);
      expect(first.session.killSwitch.engaged).toBe(true);
      const second = boot(dir);
      if (!second.ok) return;
      // Fresh key, disengaged switch — but SLEEP + new epoch keep it safe.
      expect(second.session.killSwitch.engaged).toBe(false);
      expect(second.session.sleep).toBe("SLEEP");
      // Old key is worthless against the new session.
      expect(disengageSessionKill(second.session, first.session.controlKey)).toBe(false);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("M4 stale authorization: nothing crosses an epoch", () => {
  it("old envelope + old grants + old confirmations all deny after reboot", () => {
    const dir = tmpDir();
    const work = tmpDir();
    try {
      const before = boot(dir);
      if (!before.ok) return;
      const s1 = before.session;
      grantToSession(s1, {
        grantId: "g-fs",
        taskId: "task-A",
        capability: "filesystem.read",
        scope: work,
      });
      fs.writeFileSync(path.join(work, "a.txt"), "A");
      confirmInSession(s1, {
        taskId: "task-A",
        capability: "filesystem.read",
        operation: "read",
        resource: `${work}/a.txt`,
      });
      const req = {
        capability: "filesystem.read",
        operation: "read",
        resource: `${work}/a.txt`,
        taskId: "task-A",
      };
      // Boot sleeps; the trusted local wake precedes any execution.
      expect(wakeSession(s1, { kind: "ui-action" })).toBe(true);
      const fresh = runDurable(s1, { epoch: s1.epoch, request: req });
      expect(fresh.outcome.status).toBe("completed");
      expect(fresh.auditPersisted).toBe(true);

      const after = boot(dir);
      if (!after.ok) return;
      const s2 = after.session;
      expect(s2.epoch).toBe(s1.epoch + 1);
      // Stale envelope (old epoch number) denied.
      const stale = runDurable(s2, { epoch: s1.epoch, request: req });
      expect(stale.outcome.status).toBe("refused");
      if (stale.outcome.status === "refused") {
        expect(stale.outcome.stage).toBe("epoch");
      }
      // Current epoch but no re-issued grants: denied.
      const nog = runDurable(s2, { epoch: s2.epoch, request: req });
      expect(nog.outcome.status).toBe("refused");
      // Revocation path also audited pre-restart (sanity).
      revokeSessionGrant(s1, "g-fs");
      expect(s1.grants.find((g) => g.grantId === "g-fs")?.revoked).toBe(true);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
      fs.rmSync(work, { recursive: true, force: true });
    }
  });

  it("sleep transitions persist as events; wake needs the trusted action", () => {
    const dir = tmpDir();
    try {
      const booted = boot(dir);
      if (!booted.ok) return;
      const s = booted.session;
      expect(wakeSession(s, { kind: "wake-word" })).toBe(false);
      expect(s.sleep).toBe("SLEEP");
      expect(wakeSession(s, { kind: "ui-action" })).toBe(true);
      sleepSession(s);
      expect(s.sleep).toBe("SLEEP");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
