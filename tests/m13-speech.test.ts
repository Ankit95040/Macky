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
import { handleCommandProposal } from "../src/persistence/command-service.js";
import { run } from "../src/executor/executor.js";
import {
  releaseCommandSlot,
  tryAcquireCommandSlot,
  type SpawnedProcess,
  type SpawnFn,
} from "../src/commands/runner.js";
import {
  createWorkspaceRegistry,
  registerWorkspace,
} from "../src/workspace/registry.js";
import {
  handleSpeechProposal,
  speechTextDigest,
} from "../src/speech/service.js";
import { SPEECH_EXECUTABLE } from "../src/speech/service.js";

function tmpDir(): string {
  return fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "macky-m13-")));
}

interface Rig {
  dir: string;
  session: SecureSession;
  cleanup: () => void;
}

function rigged(): Rig {
  const dir = tmpDir();
  const booted = boot(dir);
  if (!booted.ok) throw new Error("boot failed");
  grantToSession(booted.session, { grantId: "g-speech", taskId: "task-S", capability: "speech.announce", scope: "" });
  wakeSession(booted.session, { kind: "ui-action" });
  return { dir, session: booted.session, cleanup: () => { fs.rmSync(dir, { recursive: true, force: true }); } };
}

function makeFake(mode: "ok" | "hang" | "fail" = "ok"): {
  spawn: SpawnFn;
  calls: Array<{ exe: string; argv: ReadonlyArray<string>; opts: unknown }>;
} {
  const calls: Array<{ exe: string; argv: ReadonlyArray<string>; opts: unknown }> = [];
  const spawn: SpawnFn = (exe, argv, o) => {
    calls.push({ exe, argv, opts: o });
    const exitHandlers: Array<(code: unknown, signal: unknown) => void> = [];
    const proc: SpawnedProcess = {
      stdout: { on(_ev: "data", _cb: (c: Buffer) => void): void {} },
      stderr: { on(_ev: "data", _cb: (c: Buffer) => void): void {} },
      on(_ev: "error" | "exit" | "close", cb: (...args: Array<unknown>) => void): void {
        if (_ev === "exit") {
          exitHandlers.push((code, signal) => cb(code, signal));
        }
      },
      kill(sig?: string): boolean {
        const signal = sig ?? "SIGTERM";
        // Hang mode: never exits on its own, but signals are always
        // honored (like a real kernel reaping a killed child).
        setImmediate(() => {
          for (const cb of exitHandlers) {
            cb(undefined, signal);
          }
        });
        return true;
      },
    };
    if (mode === "ok") {
      setImmediate(() => {
        for (const cb of exitHandlers) {
          cb(0, undefined);
        }
      });
    } else if (mode === "fail") {
      setImmediate(() => {
        for (const cb of exitHandlers) {
          cb(1, undefined);
        }
      });
    }
    return proc;
  };
  return { spawn, calls };
}

function speak(
  rig: Rig,
  text: string,
  fake?: { spawn: SpawnFn },
  opts?: { timeoutMs?: number },
): ReturnType<typeof handleSpeechProposal> {
  return handleSpeechProposal(
    rig.session,
    { taskId: "task-S" },
    { v: 1, operation: "speech-announce", text },
    fake !== undefined || opts?.timeoutMs !== undefined
      ? { ...(fake !== undefined ? { spawnImpl: fake.spawn } : {}), ...(opts?.timeoutMs !== undefined ? { timeoutMs: opts.timeoutMs } : {}) }
      : undefined,
  );
}

function confirmText(rig: Rig, taskId: string, text: string): void {
  confirmInSession(rig.session, {
    taskId,
    capability: "speech.announce",
    operation: "announce",
    resource: "",
    digest: speechTextDigest(text),
  });
}

describe("M13 happy path A + confirmation mechanics B–D, F, J–M", () => {
  it("A. valid announcement executes with exact trusted argv", async () => {
    const rig = rigged();
    try {
      const fake = makeFake("ok");
      const text = "meeting starts in 10 minutes";
      confirmText(rig, "task-S", text);
      const r = await speak(rig, text, fake);
      expect(r.outcome.status).toBe("completed");
      expect(fake.calls).toHaveLength(1);
      // R/S/T: exactly /usr/bin/say, exactly [text], fixed env, no shell key.
      expect(fake.calls[0]?.exe).toBe("/usr/bin/say");
      expect(SPEECH_EXECUTABLE).toBe("/usr/bin/say");
      expect(fake.calls[0]?.argv).toEqual([text]);
      const opts = fake.calls[0]?.opts as Record<string, unknown>;
      expect(opts).not.toHaveProperty("shell");
      expect(opts["env"]).toEqual({ LC_ALL: "C" });
      if (r.outcome.status === "completed") {
        const c = r.outcome.result as { status: string; truncated: boolean; appId?: unknown; operation: string };
        expect(c.status).toBe("announced");
        expect(c.truncated).toBe(false);
        expect(c).not.toHaveProperty("stdout");
      }
    } finally {
      rig.cleanup();
    }
  });
  it("B/C/D. missing, wrong, and one-char-different digests refused", async () => {
    const rig = rigged();
    try {
      const fake = makeFake("ok");
      expect((await speak(rig, "hello world", fake)).outcome.status).toBe("refused");
      confirmText(rig, "task-S", "hello world");
      expect((await speak(rig, "hello worle", fake)).outcome.status).toBe("refused");
      expect((await speak(rig, "hello world", fake)).outcome.status).toBe("completed");
      expect(fake.calls).toHaveLength(1);
    } finally {
      rig.cleanup();
    }
  });
  it("F/J/K. forged digest and authorization fields refused", async () => {
    const rig = rigged();
    try {
      const fake = makeFake("ok");
      for (const [name, output] of [
        ["digest", { v: 1, operation: "speech-announce", text: "hi", digest: "forged" }],
        ["capability", { v: 1, operation: "speech-announce", text: "hi", capability: "speech.announce" }],
        ["risk", { v: 1, operation: "speech-announce", text: "hi", riskTier: 0 }],
        ["approved", { v: 1, operation: "speech-announce", text: "hi", approved: true }],
        ["taskId", { v: 1, operation: "speech-announce", text: "hi", taskId: "task-X" }],
        ["executable", { v: 1, operation: "speech-announce", text: "hi", executable: "/bin/echo" }],
        ["argv", { v: 1, operation: "speech-announce", text: "hi", argv: ["hi"] }],
        ["voice", { v: 1, operation: "speech-announce", text: "hi", voice: "Alex" }],
        ["env", { v: 1, operation: "speech-announce", text: "hi", env: {} }],
        ["timeout", { v: 1, operation: "speech-announce", text: "hi", timeoutMs: 1 }],
      ] as Array<[string, unknown]>) {
        expect((await handleSpeechProposal(rig.session, { taskId: "task-S" }, output, { spawnImpl: fake.spawn })).outcome.status, name).toBe("refused");
      }
      expect(fake.calls).toHaveLength(0);
    } finally {
      rig.cleanup();
    }
  });
  it("L/M. cross-task and cross-capability confirmations refused", async () => {
    const rig = rigged();
    try {
      const fake = makeFake("ok");
      confirmText(rig, "task-OTHER", "hello world");
      expect((await speak(rig, "hello world", fake)).outcome.status).toBe("refused");
      confirmInSession(rig.session, {
        taskId: "task-S", capability: "command.echo", operation: "run", resource: "/tmp",
        digest: speechTextDigest("hello world"),
      });
      expect((await speak(rig, "hello world", fake)).outcome.status).toBe("refused");
      expect(fake.calls).toHaveLength(0);
    } finally {
      rig.cleanup();
    }
  });
});

describe("M13 text policy E–I", () => {
  it("E/F/G/H. secrets, metachars, sizes refused", async () => {
    const rig = rigged();
    try {
      const fake = makeFake("ok");
      for (const text of [
        "password=hunter2-x",
        "-----BEGIN RSA PRIVATE KEY-----\nx",
        "api_key=sk-test-abc",
        "a|b",
        "a;b",
        "say $HOME",
        "`whoami`",
        "-f /etc/passwd",
        "-v Alex",
        "a/b",
        "x".repeat(501),
        "",
      ]) {
        expect((await speak(rig, text, fake)).outcome.status, JSON.stringify(text).slice(0, 40)).toBe("refused");
      }
      expect(fake.calls).toHaveLength(0);
      // I: 500 chars + emoji boundary complete with confirmation.
      const edge = `${"a".repeat(499)}😀`;
      expect(Array.from(edge).length).toBe(500);
      confirmText(rig, "task-S", edge);
      expect((await speak(rig, edge, fake)).outcome.status).toBe("completed");
    } finally {
      rig.cleanup();
    }
  });
});

describe("M13 gates N–Q, V–Y, AD–AF", () => {
  it("N/O/P/Q. reboot, revocation, sleep, kill deny with zero spawns", async () => {
    const dir = tmpDir();
    try {
      const first = boot(dir);
      if (!first.ok) throw new Error("boot failed");
      grantToSession(first.session, { grantId: "g", taskId: "t", capability: "speech.announce", scope: "" });
      wakeSession(first.session, { kind: "ui-action" });
      const fake = makeFake("ok");
      const out = { v: 1, operation: "speech-announce", text: "hello" };
      confirmInSession(first.session, { taskId: "t", capability: "speech.announce", operation: "announce", resource: "", digest: speechTextDigest("hello") });
      expect((await handleSpeechProposal(first.session, { taskId: "t" }, out, { spawnImpl: fake.spawn })).outcome.status).toBe("completed");
      revokeSessionGrant(first.session, "g");
      expect((await handleSpeechProposal(first.session, { taskId: "t" }, out, { spawnImpl: fake.spawn })).outcome.status).toBe("refused");
      const second = boot(dir);
      if (!second.ok) throw new Error("reboot failed");
      expect((await handleSpeechProposal(second.session, { taskId: "t" }, out, { spawnImpl: fake.spawn })).outcome.status).toBe("refused");
      expect(fake.calls).toHaveLength(1);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
  it("P/Q sleep/kill in-session deny", async () => {
    const rig = rigged();
    try {
      const dir2 = tmpDir();
      try {
        const booted = boot(dir2);
        if (!booted.ok) throw new Error("boot failed");
        grantToSession(booted.session, { grantId: "g", taskId: "t", capability: "speech.announce", scope: "" });
        const fake = makeFake("ok");
        const out = { v: 1, operation: "speech-announce", text: "hello" };
        expect((await handleSpeechProposal(booted.session, { taskId: "t" }, out, { spawnImpl: fake.spawn })).outcome.status).toBe("refused");
        engageSessionKill(booted.session);
        wakeSession(booted.session, { kind: "ui-action" });
        expect((await handleSpeechProposal(booted.session, { taskId: "t" }, out, { spawnImpl: fake.spawn })).outcome.status).toBe("refused");
        expect(fake.calls).toHaveLength(0);
      } finally {
        fs.rmSync(dir2, { recursive: true, force: true });
      }
    } finally {
      rig.cleanup();
    }
  });
  it("V/W. M8 cannot invoke speech; M3 run has no speech adapter", async () => {
    const rig = rigged();
    try {
      const wsReg = createWorkspaceRegistry();
      registerWorkspace(wsReg, "ws", rig.dir);
      expect(
        (await handleCommandProposal(rig.session, { taskId: "task-S", workspaceIds: ["ws"] }, wsReg, { v: 1, operation: "command-exec", commandId: "speech.announce", workspaceId: "ws", cwd: ".", argv: [] })).outcome.status,
      ).toBe("refused");
      const r = run(
        { capability: "speech.announce", operation: "announce", resource: rig.dir, taskId: "task-S" },
        { sleep: rig.session.sleep, grants: rig.session.grants, confirmations: rig.session.confirmations, killSwitch: rig.session.killSwitch, log: rig.session.log },
      );
      expect(r.outcome.status).toBe("refused");
    } finally {
      rig.cleanup();
    }
  });
  it("AD/AE/AF. slot, timeout, boundary recheck", async () => {
    const rig = rigged();
    try {
      expect(tryAcquireCommandSlot()).toBe(true);
      expect((await speak(rig, "hello", makeFake("ok"))).outcome.status).toBe("refused");
      releaseCommandSlot();
      const hanging = makeFake("hang");
      confirmText(rig, "task-S", "hello");
      const timed = await speak(rig, "hello", hanging, { timeoutMs: 150 });
      expect(timed.outcome.status).toBe("failed");
      // AF: authorize-then-kill still blocks (no cached authority).
      const dir2 = tmpDir();
      try {
        const booted = boot(dir2);
        if (!booted.ok) throw new Error("boot failed");
        grantToSession(booted.session, { grantId: "g", taskId: "t", capability: "speech.announce", scope: "" });
        wakeSession(booted.session, { kind: "ui-action" });
        confirmInSession(booted.session, { taskId: "t", capability: "speech.announce", operation: "announce", resource: "", digest: speechTextDigest("hello") });
        engageSessionKill(booted.session);
        const fake = makeFake("ok");
        expect((await handleSpeechProposal(booted.session, { taskId: "t" }, { v: 1, operation: "speech-announce", text: "hello" }, { spawnImpl: fake.spawn })).outcome.status).toBe("refused");
        expect(fake.calls).toHaveLength(0);
      } finally {
        fs.rmSync(dir2, { recursive: true, force: true });
      }
    } finally {
      rig.cleanup();
    }
  });
  it("Y/AC. audit has digest/metadata, never text; source scans clean", async () => {
    const rig = rigged();
    try {
      const fake = makeFake("ok");
      const text = "unique announcement phrase alpha";
      confirmText(rig, "task-S", text);
      expect((await speak(rig, text, fake)).outcome.status).toBe("completed");
      const audit = fs.readFileSync(`${rig.dir}/audit.jsonl`, "utf8");
      expect(audit).not.toContain(text);
      expect(audit).toContain(speechTextDigest(text));
      expect(audit).toContain("speech.announce ok");
      const dir = new URL("../src/speech/", import.meta.url);
      for (const file of fs.readdirSync(dir).filter((f) => f.endsWith(".ts"))) {
        const src = fs.readFileSync(new URL(file, dir), "utf8");
        for (const forbidden of ["shell:", "execFile", "execSync", "spawnSync", "eval(", "/bin/sh", "node:net", "node:http", "fetch(", "osascript"]) {
          expect(src.includes(forbidden), `${file}: ${forbidden}`).toBe(false);
        }
      }
    } finally {
      rig.cleanup();
    }
  });
});
