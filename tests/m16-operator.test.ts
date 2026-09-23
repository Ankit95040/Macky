import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import { boot } from "../src/bootstrap/boot.js";
import { wakeSession } from "../src/persistence/session.js";
import type { SecureSession } from "../src/persistence/session.js";
import * as operatorModule from "../src/operator/index.js";
import {
  engageKillOp,
  getStatus,
  issueGrantOp,
  readAuditTailOp,
  recordConfirmationOp,
  revokeGrantOp,
  sleepOp,
  wakeOp,
} from "../src/operator/service.js";
import { createWorkspaceRegistry, registerWorkspace } from "../src/workspace/registry.js";
import { speechTextDigest } from "../src/speech/service.js";

function tmpDir(): string {
  return fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "macky-m16-")));
}

interface Rig {
  dir: string;
  work: string;
  session: SecureSession;
  cleanup: () => void;
}

function rigged(): Rig {
  const dir = tmpDir();
  const work = tmpDir();
  fs.mkdirSync(path.join(work, "proj"), { recursive: true });
  const booted = boot(dir);
  if (!booted.ok) throw new Error("boot failed");
  wakeSession(booted.session, { kind: "ui-action" });
  return { dir, work, session: booted.session, cleanup: () => { fs.rmSync(dir, { recursive: true, force: true }); fs.rmSync(work, { recursive: true, force: true }); } };
}

function registryFor(work: string): ReturnType<typeof createWorkspaceRegistry> {
  const registry = createWorkspaceRegistry();
  const reg = registerWorkspace(registry, "ws-op", work);
  if (!reg.ok) throw new Error(`register failed: ${reg.reason}`);
  return registry;
}

function auditLines(dir: string): Array<string> {
  return fs.readFileSync(path.join(dir, "audit.jsonl"), "utf8").split("\n").filter((l) => l.length > 0);
}

describe("M16 status A–B", () => {
  it("A. status exposes only bounded safe metadata", () => {
    const rig = rigged();
    try {
      const status = getStatus(rig.session);
      expect(Object.keys(status).sort()).toEqual([
        "auditHealthy", "confirmationCount", "epoch", "grantCount", "killEngaged", "sleep",
      ]);
      expect(status.epoch).toBe(1);
      expect(status.sleep).toBe("AWAKE");
      expect(status.killEngaged).toBe(false);
      expect(status.grantCount).toBe(0);
    } finally {
      rig.cleanup();
    }
  });
  it("B. status never exposes controlKey or secrets", () => {
    const rig = rigged();
    try {
      const blob = JSON.stringify(getStatus(rig.session));
      expect(blob).not.toContain("controlKey");
      expect(blob).not.toContain("token");
      expect(blob).not.toContain("BEGIN");
    } finally {
      rig.cleanup();
    }
  });
});

describe("M16 sleep/kill/wake C–E, AB", () => {
  it("C/D. wake and sleep delegate with identical semantics", () => {
    const rig = rigged();
    try {
      const slept = sleepOp(rig.session);
      expect(slept).toEqual({ ok: true, sleep: "SLEEP" });
      expect(rig.session.sleep).toBe("SLEEP");
      const badWake = wakeOp(rig.session, { kind: "wake-word" });
      expect(badWake.ok).toBe(false);
      expect(rig.session.sleep).toBe("SLEEP");
      const woken = wakeOp(rig.session, { kind: "ui-action" });
      expect(woken).toEqual({ ok: true, woken: true });
      expect(rig.session.sleep).toBe("AWAKE");
    } finally {
      rig.cleanup();
    }
  });
  it("E. kill engages; AB. semantics unchanged (irreversible here)", () => {
    const rig = rigged();
    try {
      expect(engageKillOp(rig.session)).toEqual({ ok: true, engaged: true });
      expect(rig.session.killSwitch.engaged).toBe(true);
    } finally {
      rig.cleanup();
    }
  });
  it("F. no disengage export exists", () => {
    expect(Object.keys(operatorModule).join(" ").toLowerCase().includes("disengage")).toBe(false);
  });
});

describe("M16 grants G–Q", () => {
  it("G/H. Tier0/Tier1 grants succeed in valid scopes", () => {
    const rig = rigged();
    try {
      const registry = registryFor(rig.work);
      const a = issueGrantOp(rig.session, registry, {
        taskId: "task-O", grantId: "g-read", capability: "filesystem.read", scope: `${rig.work}/proj`,
      });
      expect(a).toEqual({ ok: true, grantId: "g-read" });
      const b = issueGrantOp(rig.session, registry, {
        taskId: "task-O", grantId: "g-id", capability: "command.id", scope: rig.work,
      });
      // command.id is Tier2 → refused (covered in I); use Tier1 network-free Tier0 instead.
      expect(b.ok).toBe(false);
      const c = issueGrantOp(rig.session, registry, {
        taskId: "task-O", grantId: "g-sys", capability: "system.info", scope: "",
      });
      expect(c).toEqual({ ok: true, grantId: "g-sys" });
      expect(rig.session.grants).toHaveLength(2);
    } finally {
      rig.cleanup();
    }
  });
  it("I/J. Tier2 and Tier3 refused", () => {
    const rig = rigged();
    try {
      const registry = registryFor(rig.work);
      expect(issueGrantOp(rig.session, registry, {
        taskId: "t", grantId: "g2", capability: "command.id", scope: rig.work,
      }).ok).toBe(false);
      expect(issueGrantOp(rig.session, registry, {
        taskId: "t", grantId: "g3", capability: "filesystem.delete", scope: rig.work,
      }).ok).toBe(false);
      expect(rig.session.grants).toHaveLength(0);
    } finally {
      rig.cleanup();
    }
  });
  it("K/L/M. root, home-root, and unregistered roots refused", () => {
    const rig = rigged();
    try {
      const registry = registryFor(rig.work);
      expect(issueGrantOp(rig.session, registry, {
        taskId: "t", grantId: "g1", capability: "filesystem.read", scope: "/",
      }).ok).toBe(false);
      expect(issueGrantOp(rig.session, registry, {
        taskId: "t", grantId: "g2", capability: "filesystem.read", scope: os.homedir(),
      }).ok).toBe(false);
      const other = tmpDir();
      try {
        expect(issueGrantOp(rig.session, registry, {
          taskId: "t", grantId: "g3", capability: "filesystem.read", scope: other,
        }).ok).toBe(false);
      } finally {
        fs.rmSync(other, { recursive: true, force: true });
      }
      // ~/.macky operator area is explicitly approved when present.
      const mackyModels = path.join(os.homedir(), ".macky", "models");
      if (fs.existsSync(mackyModels)) {
        expect(issueGrantOp(rig.session, registry, {
          taskId: "t", grantId: "gm", capability: "filesystem.read", scope: mackyModels,
        }).ok).toBe(true);
      }
      expect(rig.session.grants.every((g) => g.scope !== "/" && g.scope !== os.homedir())).toBe(true);
    } finally {
      rig.cleanup();
    }
  });
  it("N. registered workspace descendant accepted", () => {
    const rig = rigged();
    try {
      const registry = registryFor(rig.work);
      const r = issueGrantOp(rig.session, registry, {
        taskId: "t", grantId: "g", capability: "git.read", scope: `${rig.work}/proj`,
      });
      expect(r.ok).toBe(true);
    } finally {
      rig.cleanup();
    }
  });
  it("O/Q. traversal and malformed capability refused", () => {
    const rig = rigged();
    try {
      const registry = registryFor(rig.work);
      expect(issueGrantOp(rig.session, registry, {
        taskId: "t", grantId: "g1", capability: "filesystem.read", scope: `${rig.work}/../etc`,
      }).ok).toBe(false);
      expect(issueGrantOp(rig.session, registry, {
        taskId: "t", grantId: "g2", capability: "shell.exec", scope: rig.work,
      }).ok).toBe(false);
      expect(issueGrantOp(rig.session, registry, {
        taskId: "t!!!", grantId: "g3", capability: "filesystem.read", scope: rig.work,
      }).ok).toBe(false);
      expect(issueGrantOp(rig.session, registry, {
        taskId: "t", grantId: "g4", capability: "filesystem.read", scope: rig.work, admin: true,
      }).ok).toBe(false);
      expect(rig.session.grants).toHaveLength(0);
    } finally {
      rig.cleanup();
    }
  });
  it("P. unscoped capabilities require empty scope", () => {
    const rig = rigged();
    try {
      const registry = registryFor(rig.work);
      expect(issueGrantOp(rig.session, registry, {
        taskId: "t", grantId: "g1", capability: "audit.read", scope: rig.work,
      }).ok).toBe(false);
      expect(issueGrantOp(rig.session, registry, {
        taskId: "t", grantId: "g2", capability: "audit.read", scope: "",
      }).ok).toBe(true);
    } finally {
      rig.cleanup();
    }
  });
});

describe("M16 revoke/confirm/audit R–X, AD", () => {
  it("R. revoke delegates correctly", () => {
    const rig = rigged();
    try {
      const registry = registryFor(rig.work);
      issueGrantOp(rig.session, registry, {
        taskId: "t", grantId: "g", capability: "filesystem.read", scope: rig.work,
      });
      expect(rig.session.grants).toHaveLength(1);
      expect(revokeGrantOp(rig.session, { grantId: "g" })).toEqual({ ok: true });
      expect(rig.session.grants.find((g) => g.grantId === "g")?.revoked).toBe(true);
      expect(revokeGrantOp(rig.session, { grantId: 42 }).ok).toBe(false);
    } finally {
      rig.cleanup();
    }
  });
  it("S/T. confirmation validation incl. speech digest rule", () => {
    const rig = rigged();
    try {
      const ok = recordConfirmationOp(rig.session, {
        taskId: "t", capability: "git.read", operation: "log", resource: "/p",
      });
      expect(ok).toEqual({ ok: true });
      // speech.announce without digest refused; with digest accepted.
      expect(recordConfirmationOp(rig.session, {
        taskId: "t", capability: "speech.announce", operation: "announce", resource: "",
      }).ok).toBe(false);
      const digest = speechTextDigest("hello");
      expect(recordConfirmationOp(rig.session, {
        taskId: "t", capability: "speech.announce", operation: "announce", resource: "", digest,
      }).ok).toBe(true);
      expect(recordConfirmationOp(rig.session, {
        taskId: "t", capability: "nope.cap", operation: "x", resource: "",
      }).ok).toBe(false);
      expect(rig.session.confirmations).toHaveLength(2);
    } finally {
      rig.cleanup();
    }
  });
  it("U/V. exactly one audit event per mutation, none invented", () => {
    const rig = rigged();
    try {
      const registry = registryFor(rig.work);
      const count = (): number => auditLines(rig.dir).length;
      const n0 = count();
      sleepOp(rig.session);
      expect(count()).toBe(n0 + 1);
      wakeOp(rig.session, { kind: "ui-action" });
      expect(count()).toBe(n0 + 2);
      issueGrantOp(rig.session, registry, {
        taskId: "t", grantId: "g", capability: "filesystem.read", scope: rig.work,
      });
      expect(count()).toBe(n0 + 3);
      revokeGrantOp(rig.session, { grantId: "g" });
      expect(count()).toBe(n0 + 4);
      recordConfirmationOp(rig.session, {
        taskId: "t", capability: "git.read", operation: "log", resource: "/p",
      });
      expect(count()).toBe(n0 + 5);
      engageKillOp(rig.session);
      expect(count()).toBe(n0 + 6);
    } finally {
      rig.cleanup();
    }
  });
  it("W/X/AD. audit tail bounded, clean, fail-closed", () => {
    const rig = rigged();
    try {
      const registry = registryFor(rig.work);
      for (let i = 0; i < 3; i += 1) {
        issueGrantOp(rig.session, registry, {
          taskId: "t", grantId: `g-${i}`, capability: "filesystem.read", scope: rig.work,
        });
      }
      const tail = readAuditTailOp(rig.session, { limit: 2 });
      expect(tail.ok).toBe(true);
      if (tail.ok) {
        expect(tail.events.length).toBeLessThanOrEqual(2);
      }
      expect(readAuditTailOp(rig.session, { limit: 0 }).ok).toBe(false);
      expect(readAuditTailOp(rig.session, { limit: 101 }).ok).toBe(false);
      const blob = auditLines(rig.dir).join("\n");
      expect(blob).not.toContain("controlKey");
      // AD: unwritable sink fails the mutation closed with rollback.
      fs.rmSync(path.join(rig.dir, "audit.jsonl"));
      fs.mkdirSync(path.join(rig.dir, "audit.jsonl"));
      const before = rig.session.grants.length;
      const r = issueGrantOp(rig.session, registry, {
        taskId: "t", grantId: "g-dead", capability: "filesystem.read", scope: rig.work,
      });
      expect(r.ok).toBe(false);
      expect(rig.session.grants).toHaveLength(before);
    } finally {
      fs.rmSync(path.join(rig.dir, "audit.jsonl"), { recursive: true, force: true });
      rig.cleanup();
    }
  });
});
