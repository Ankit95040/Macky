import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import { boot } from "../src/bootstrap/boot.js";
import {
  confirmInSession,
  engageSessionKill,
  grantToSession,
  revokeSessionGrant,
  wakeSession,
} from "../src/persistence/session.js";
import type { SecureSession } from "../src/persistence/session.js";
import {
  ALLOWED_COMMANDS,
} from "../src/commands/registry.js";
import { buildChildEnv, releaseCommandSlot, runSpawned, tryAcquireCommandSlot } from "../src/commands/runner.js";
import { handleCommandProposal } from "../src/persistence/command-service.js";
import {
  createWorkspaceRegistry,
  registerWorkspace,
} from "../src/workspace/registry.js";

function tmpDir(): string {
  return fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "macky-m8-")));
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
  const booted = boot(dir);
  if (!booted.ok) throw new Error("boot failed");
  fs.writeFileSync(path.join(work, "a.txt"), "x");
  const registry = createWorkspaceRegistry();
  if (!registerWorkspace(registry, "ws-cmd", work).ok) throw new Error("register failed");
  for (const [grantId, capability] of [
    ["g-echo", "command.echo"],
    ["g-printf", "command.printf"],
    ["g-whoami", "command.whoami"],
    ["g-pwd", "command.pwd"],
    ["g-id", "command.id"],
  ] as Array<[string, string]>) {
    const r = grantToSession(booted.session, { grantId, taskId: "task-C", capability, scope: work });
    if (!r.ok) throw new Error("grant failed");
  }
  wakeSession(booted.session, { kind: "ui-action" });
  (booted.session as unknown as { __ws: unknown }).__ws = registry;
  return { dir, work, session: booted.session, cleanup: () => { fs.rmSync(dir, { recursive: true, force: true }); fs.rmSync(work, { recursive: true, force: true }); } };
}

function wsOf(rig: Rig): ReturnType<typeof createWorkspaceRegistry> {
  return (rig.session as unknown as { __ws: ReturnType<typeof createWorkspaceRegistry> }).__ws;
}

function run(rig: Rig, output: unknown): ReturnType<typeof handleCommandProposal> {
  return handleCommandProposal(rig.session, { taskId: "task-C", workspaceIds: ["ws-cmd"] }, wsOf(rig), output);
}

function cmd(commandId: string, extra?: Record<string, unknown>): Record<string, unknown> {
  return { v: 1, operation: "command-exec", commandId, workspaceId: "ws-cmd", cwd: ".", argv: [], ...extra };
}

describe("M8 happy path + Tier2 A", () => {
  it("A. registered commands execute with bounded contracts", async () => {
    const rig = rigged();
    try {
      const who = await run(rig, cmd("command.whoami"));
      expect(who.outcome.status).toBe("completed");
      const echo = await run(rig, cmd("command.echo", { argv: ["hello", "m8"] }));
      expect(echo.outcome.status).toBe("completed");
      if (echo.outcome.status === "completed") {
        const c = echo.outcome.result as { stdout: string; exitCode: number };
        expect(c.stdout).toBe("hello m8\n");
        expect(c.exitCode).toBe(0);
      }
      const printf = await run(rig, cmd("command.printf", { argv: ["%s=%d", "n", "7"] }));
      expect(printf.outcome.status).toBe("completed");
      if (printf.outcome.status === "completed") {
        expect((printf.outcome.result as { stdout: string }).stdout).toBe("n=7");
      }
      const pwd = await run(rig, cmd("command.pwd"));
      expect(pwd.outcome.status).toBe("completed");
    } finally {
      rig.cleanup();
    }
  });
  it("Tier2 id needs trusted confirmation, then executes", async () => {
    const rig = rigged();
    try {
      const pending = await run(rig, cmd("command.id"));
      expect(pending.outcome.status).toBe("refused");
      confirmInSession(rig.session, {
        taskId: "task-C", capability: "command.id", operation: "run", resource: rig.work,
      });
      const allowed = await run(rig, cmd("command.id"));
      expect(allowed.outcome.status).toBe("completed");
      if (allowed.outcome.status === "completed") {
        expect((allowed.outcome.result as { stdout: string }).stdout.length).toBeGreaterThan(0);
      }
    } finally {
      rig.cleanup();
    }
  });
});

describe("M8 proposal forgery B–J, AV", () => {
  it("B–I + AV. unknown/forged/trusted-field proposals refused", async () => {
    const rig = rigged();
    try {
      const bad: Array<[string, unknown]> = [
        ["unknown", cmd("command.frobnicate")],
        ["executable", { ...cmd("command.echo", { argv: ["x"] }), executable: "/bin/echo" }],
        ["risk", { ...cmd("command.echo", { argv: ["x"] }), risk: "tier0", riskTier: 0 }],
        ["capability", { ...cmd("command.echo", { argv: ["x"] }), capability: "command.echo" }],
        ["approval", { ...cmd("command.echo", { argv: ["x"] }), approved: true }],
        ["confirmation", { ...cmd("command.echo", { argv: ["x"] }), confirmedBy: "user", confirmationToken: "t" }],
        ["env", { ...cmd("command.echo", { argv: ["x"] }), env: { FOO: "bar" } }],
        ["timeout", { ...cmd("command.echo", { argv: ["x"] }), timeoutMs: 99999 }],
        ["extra", { ...cmd("command.echo", { argv: ["x"] }), policy: "allow-all", grant: {}, scope: "/" }],
        ["shell-string", "echo hi"],
        ["audit-forge", { ...cmd("command.echo", { argv: ["x"] }), auditPath: "/tmp/e", seq: 1, hash: "x" }],
      ];
      for (const [name, output] of bad) {
        const r = await run(rig, output);
        expect(r.outcome.status, name).toBe("refused");
      }
    } finally {
      rig.cleanup();
    }
  });
});

describe("M8 shell/argv attacks J–X, AJ", () => {
  it("K–M. shells refused as Tier3", async () => {
    const rig = rigged();
    try {
      for (const id of ["shell.sh", "shell.bash", "shell.zsh"]) {
        const r = await run(rig, cmd(id, { argv: ["-c", "echo hi"] }));
        expect(r.outcome.status, id).toBe("refused");
      }
    } finally {
      rig.cleanup();
    }
  });
  it("N–T, AJ. metacharacters refused, never stripped", async () => {
    const rig = rigged();
    try {
      for (const argv of [
        ["a|b"], ["a&b"], ["a;b"], ["a>b"], ["a<b"], ["a$b"], ["`whoami`"], ["$(whoami)"],
        ["a\nb"], ["a\rb"], ["a\0b"], ["x", "&"], ["a(b"], ["a*b"], ["a?b"], ["a[0]"],
        ["a{b}"], ["a~b"], ["a#b"], ["a!b"], ["a\\b"],
      ]) {
        const r = await run(rig, cmd("command.echo", { argv }));
        expect(r.outcome.status, JSON.stringify(argv)).toBe("refused");
      }
    } finally {
      rig.cleanup();
    }
  });
  it("U–X. hostile cwd refused", async () => {
    const rig = rigged();
    try {
      for (const cwd of ["/etc", "../..", "%2e%2e/x", "a\\b", ""]) {
        const r = await run(rig, { ...cmd("command.pwd"), cwd });
        expect(r.outcome.status, JSON.stringify(cwd)).toBe("refused");
      }
    } finally {
      rig.cleanup();
    }
  });
});

describe("M8 workspace Y–AA + sleep/kill/epoch AP–AS", () => {
  it("Y/Z/AA. binding, drift, sensitivity enforced", async () => {
    const rig = rigged();
    try {
      const evil = await handleCommandProposal(
        rig.session, { taskId: "task-C", workspaceIds: ["ws-cmd"] }, wsOf(rig),
        { v: 1, operation: "command-exec", commandId: "command.whoami", workspaceId: "ws-evil", cwd: ".", argv: [] },
      );
      expect(evil.outcome.status).toBe("refused");
      const moved = `${rig.work}-moved`;
      fs.renameSync(rig.work, moved);
      try {
        expect((await run(rig, cmd("command.pwd"))).outcome.status).toBe("refused");
      } finally {
        fs.renameSync(moved, rig.work);
      }
      const other = tmpDir();
      try {
        fs.mkdirSync(path.join(other, ".ssh"));
        expect(registerWorkspace(wsOf(rig), "ws-sens", path.join(other, ".ssh")).ok).toBe(false);
      } finally {
        fs.rmSync(other, { recursive: true, force: true });
      }
    } finally {
      rig.cleanup();
    }
  });
  it("AP/AQ. sleep and kill deny before spawn", async () => {
    const dir = tmpDir();
    const work = tmpDir();
    try {
      const booted = boot(dir);
      if (!booted.ok) throw new Error("boot failed");
      const registry = createWorkspaceRegistry();
      registerWorkspace(registry, "ws", work);
      grantToSession(booted.session, { grantId: "g", taskId: "t", capability: "command.whoami", scope: work });
      const asleep = await handleCommandProposal(
        booted.session, { taskId: "t", workspaceIds: ["ws"] }, registry,
        { v: 1, operation: "command-exec", commandId: "command.whoami", workspaceId: "ws", cwd: ".", argv: [] },
      );
      expect(asleep.outcome.status).toBe("refused");
      engageSessionKill(booted.session);
      wakeSession(booted.session, { kind: "ui-action" });
      const killed = await handleCommandProposal(
        booted.session, { taskId: "t", workspaceIds: ["ws"] }, registry,
        { v: 1, operation: "command-exec", commandId: "command.whoami", workspaceId: "ws", cwd: ".", argv: [] },
      );
      expect(killed.outcome.status).toBe("refused");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
      fs.rmSync(work, { recursive: true, force: true });
    }
  });
  it("AR/AS. reboot and revocation invalidate", async () => {
    const dir = tmpDir();
    const work = tmpDir();
    try {
      const first = boot(dir);
      if (!first.ok) throw new Error("boot failed");
      const registry = createWorkspaceRegistry();
      registerWorkspace(registry, "ws", work);
      grantToSession(first.session, { grantId: "g", taskId: "t", capability: "command.whoami", scope: work });
      wakeSession(first.session, { kind: "ui-action" });
      const ok = await handleCommandProposal(
        first.session, { taskId: "t", workspaceIds: ["ws"] }, registry,
        { v: 1, operation: "command-exec", commandId: "command.whoami", workspaceId: "ws", cwd: ".", argv: [] },
      );
      expect(ok.outcome.status).toBe("completed");
      revokeSessionGrant(first.session, "g");
      const revoked = await handleCommandProposal(
        first.session, { taskId: "t", workspaceIds: ["ws"] }, registry,
        { v: 1, operation: "command-exec", commandId: "command.whoami", workspaceId: "ws", cwd: ".", argv: [] },
      );
      expect(revoked.outcome.status).toBe("refused");
      const second = boot(dir);
      if (!second.ok) throw new Error("reboot failed");
      const stale = await handleCommandProposal(
        second.session, { taskId: "t", workspaceIds: ["ws"] }, registry,
        { v: 1, operation: "command-exec", commandId: "command.whoami", workspaceId: "ws", cwd: ".", argv: [] },
      );
      expect(stale.outcome.status).toBe("refused");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
      fs.rmSync(work, { recursive: true, force: true });
    }
  });
});

describe("M8 denylist AC–AI, BC–BD + Tier3 AT", () => {
  it("dangerous ids denied; Tier3 immune to forged confirmation", async () => {
    const rig = rigged();
    try {
      for (const id of [
        "net.curl", "net.ssh", "priv.sudo", "fs.rm", "fs.mv", "fs.chmod", "fs.chown",
        "pkg.npm", "pkg.npx", "lang.python", "lang.node", "mac.osascript", "vcs.git",
        "shell.sh", "fs.mkdir", "fs.touch", "fs.ln", "fs.cp",
      ]) {
        const r = await run(rig, cmd(id, { argv: [] }));
        expect(r.outcome.status, id).toBe("refused");
      }
      // Forged confirmation cannot revive Tier3.
      confirmInSession(rig.session, {
        taskId: "task-C", capability: "command.echo", operation: "run", resource: rig.work,
      });
      expect((await run(rig, cmd("priv.sudo", { argv: [] }))).outcome.status).toBe("refused");
      expect((await run(rig, cmd("fs.rm", { argv: ["x"] }))).outcome.status).toBe("refused");
    } finally {
      rig.cleanup();
    }
  });
  it("BD. allowed registry is network-free and explicit", () => {
    expect(ALLOWED_COMMANDS.length).toBe(5);
    for (const def of ALLOWED_COMMANDS) {
      expect(def.capability.startsWith("command.")).toBe(true);
      expect(def.executable.startsWith("/")).toBe(true);
      expect(def.executable).not.toMatch(/curl|wget|ssh|sh$|bash/);
    }
  });
  it("BC. absolute filesystem targets die in argv validation", async () => {
    const rig = rigged();
    try {
      expect((await run(rig, cmd("command.echo", { argv: ["/tmp/x"] }))).outcome.status).toBe("refused");
      expect((await run(rig, cmd("command.printf", { argv: ["%s", "a/b"] }))).outcome.status).toBe("refused");
    } finally {
      rig.cleanup();
    }
  });
});

describe("M8 environment AB/BB + printf guard", () => {
  it("AB. child env is exactly the minimal set", () => {
    process.env["MACKY_FAKE_SECRET"] = "hunter2-test";
    process.env["SSH_AUTH_SOCK"] = "/tmp/fake.sock";
    process.env["AWS_SECRET_ACCESS_KEY"] = "fake-aws";
    try {
      expect(buildChildEnv()).toEqual({ LC_ALL: "C" });
    } finally {
      delete process.env["MACKY_FAKE_SECRET"];
      delete process.env["SSH_AUTH_SOCK"];
      delete process.env["AWS_SECRET_ACCESS_KEY"];
    }
  });
  it("BB. PATH smuggling refused; printf %n refused", async () => {
    const rig = rigged();
    try {
      expect((await run(rig, { ...cmd("command.echo", { argv: ["x"] }), PATH: "/tmp/evil" })).outcome.status).toBe("refused");
      expect((await run(rig, cmd("command.printf", { argv: ["%n", "x"] }))).outcome.status).toBe("refused");
      expect((await run(rig, cmd("command.printf", { argv: ["%x", "x"] }))).outcome.status).toBe("refused");
      expect((await run(rig, cmd("command.whoami", { argv: ["x"] }))).outcome.status).toBe("refused");
    } finally {
      rig.cleanup();
    }
  });
});

describe("M8 limits AL–AM + argv bytes", () => {
  it("AL/AM. arity and size caps refuse", async () => {
    const rig = rigged();
    try {
      expect((await run(rig, cmd("command.echo", { argv: Array.from({ length: 17 }, (_, i) => `a${i}`) }))).outcome.status).toBe("refused");
      expect((await run(rig, cmd("command.echo", { argv: ["x".repeat(1025)] }))).outcome.status).toBe("refused");
      // 16 × 1024 'é' = 32 KiB > 16 KiB total cap.
      expect((await run(rig, cmd("command.echo", { argv: Array.from({ length: 16 }, () => "é".repeat(1024)) }))).outcome.status).toBe("refused");
    } finally {
      rig.cleanup();
    }
  });
});
