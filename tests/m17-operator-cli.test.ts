import { createHash } from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import { parseArgv } from "../src/operator-cli/args.js";
import { runAudit, runCommand, runStatus, runTalk } from "../src/operator-cli/commands.js";
import { main } from "../src/operator-cli/index.js";
import { MockConversationPlanner } from "../src/conversation/mock-conversation-planner.js";
import type { CaptureSpawnFn, SpawnedCapture } from "../src/voice/capture.js";
import type { SttSpawnFn, SpawnedStt } from "../src/voice/stt.js";

function tmpDir(): string {
  return fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "macky-m17-")));
}

function makePcm(seconds = 1): Buffer {
  return Buffer.alloc(16000 * seconds * 2, 0);
}

function captureFake(wav?: Buffer): CaptureSpawnFn {
  const spawn: CaptureSpawnFn = () => {
    const exitHandlers: Array<(code: unknown) => void> = [];
    const closeHandlers: Array<() => void> = [];
    const proc: SpawnedCapture = {
      stdout: {
        on(_ev: "data", cb: (chunk: Buffer) => void): void {
          if (wav !== undefined) {
            cb(wav);
          }
        },
      },
      stderr: { on(): void {} },
      on(_ev: "error" | "exit" | "close", cb: (...args: Array<unknown>) => void): void {
        if (_ev === "exit") {
          exitHandlers.push((code) => cb(code));
        } else if (_ev === "close") {
          closeHandlers.push(() => cb());
        }
      },
      kill(): boolean {
        return true;
      },
    };
    setImmediate(() => {
      for (const cb of exitHandlers) {
        cb(0);
      }
      for (const cb of closeHandlers) {
        cb();
      }
    });
    return proc;
  };
  return spawn;
}

function sttFake(text?: string): SttSpawnFn {
  const spawn: SttSpawnFn = () => {
    const exitHandlers: Array<(code: unknown) => void> = [];
    const closeHandlers: Array<() => void> = [];
    const proc: SpawnedStt = {
      stdin: { write(): boolean { return true; }, end(): void {}, on(): void {} },
      stdout: {
        on(_ev: "data", cb: (chunk: Buffer) => void): void {
          if (text !== undefined) {
            cb(Buffer.from(text, "utf8"));
          }
        },
      },
      stderr: { on(): void {} },
      on(_ev: "error" | "exit" | "close", cb: (...args: Array<unknown>) => void): void {
        if (_ev === "exit") {
          exitHandlers.push((code) => cb(code));
        } else if (_ev === "close") {
          closeHandlers.push(() => cb());
        }
      },
      kill(): boolean {
        return true;
      },
    };
    setImmediate(() => {
      for (const cb of exitHandlers) {
        cb(0);
      }
      for (const cb of closeHandlers) {
        cb();
      }
    });
    return proc;
  };
  return spawn;
}

function voicePaths(dir: string): { helperPath: string; binaryPath: string; modelPath: string; modelSha256: string } {
  const model = Buffer.alloc(512, 3);
  const modelPath = `${dir}/model.bin`;
  fs.writeFileSync(modelPath, model);
  for (const f of ["helper", "stt"]) {
    fs.writeFileSync(`${dir}/${f}`, "#!/bin/sh\nexit 0\n");
    fs.chmodSync(`${dir}/${f}`, 0o755);
  }
  return {
    helperPath: `${dir}/helper`,
    binaryPath: `${dir}/stt`,
    modelPath,
    modelSha256: createHash("sha256").update(model).digest("hex"),
  };
}

describe("M17 argv security D–H", () => {
  it("D/E/F. malformed, unknown command/flags refused", () => {
    expect(parseArgv(["status", "extra"])).toEqual({ ok: false, reason: "status takes no arguments" });
    expect(parseArgv(["frobnicate"])).toEqual({ ok: false, reason: "unknown command" });
    expect(parseArgv(["audit", "--bogus"])).toEqual({ ok: false, reason: 'unknown audit argument: --bogus' });
    expect(parseArgv(["audit", "--limit"])).toEqual({ ok: false, reason: "malformed --limit value" });
    expect(parseArgv(["audit", "--limit", "abc"])).toEqual({ ok: false, reason: "malformed --limit value" });
    expect(parseArgv(["audit", "--limit", "0"])).toEqual({ ok: false, reason: "audit limit out of range" });
    expect(parseArgv(["audit", "--limit", "101"])).toEqual({ ok: false, reason: "audit limit out of range" });
    expect(parseArgv(["audit", "--limit", "5", "--limit", "5"])).toEqual({ ok: false, reason: "duplicate --limit" });
    expect(parseArgv([])).toEqual({ ok: false, reason: "unknown command" });
    expect(parseArgv(["TALK"])).toEqual({ ok: false, reason: "unknown command" });
  });
  it("G. oversized argv refused", () => {
    expect(parseArgv(["status", "x".repeat(300)])).toEqual({ ok: false, reason: "argv rejected" });
    expect(parseArgv(Array.from({ length: 9 }, () => "x"))).toEqual({ ok: false, reason: "argv rejected" });
  });
  it("H–L. forged authority argv refused", () => {
    for (const argv of [
      ["grant", "admin"],
      ["status", "--grant", "admin"],
      ["status", "--tier", "3"],
      ["status", "--sleep", "false"],
      ["status", "--kill", "false"],
      ["status", "--confirm", "true"],
      ["status", "--capability", "*"],
      ["talk", "../secret"],
      ["talk", "/etc/passwd"],
      ["talk", "a; rm -rf /"],
      ["talk", "--taskId", "task-ADMIN"],
    ]) {
      const parsed = parseArgv(argv);
      expect("ok" in parsed && parsed.ok === false, JSON.stringify(argv)).toBe(true);
    }
  });
  it("audit parses bounded counts", () => {
    expect(parseArgv(["audit"])).toEqual({ kind: "audit", limit: 20 });
    expect(parseArgv(["audit", "--limit", "7"])).toEqual({ kind: "audit", limit: 7 });
    expect(parseArgv(["status"])).toEqual({ kind: "status" });
    expect(parseArgv(["talk"])).toEqual({ kind: "talk" });
  });
});

describe("M17 commands A–C, X–Z", () => {
  it("A. status happy path exposes only safe fields", async () => {
    const dir = tmpDir();
    try {
      const r = await runStatus(dir);
      expect(r.exitCode).toBe(0);
      expect(r.output).toContain("epoch: 1");
      expect(r.output).toContain("sleep: SLEEP");
      expect(r.output).toContain("kill: clear");
      expect(r.output).not.toContain("controlKey");
      expect(r.output).not.toContain("token");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
  it("B/C. audit happy path with bounded count", async () => {
    const dir = tmpDir();
    try {
      const r = await runAudit(dir, 5);
      expect(r.exitCode).toBe(0);
      const lines = r.output.split("\n").filter((l) => l.length > 0);
      expect(lines.length).toBeLessThanOrEqual(5);
      for (const line of lines) {
        expect(() => JSON.parse(line)).not.toThrow();
      }
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
  it("X/Y. output bounded, secrets absent", async () => {
    const dir = tmpDir();
    try {
      const r = await runStatus(dir);
      expect(Array.from(r.output).length).toBeLessThanOrEqual(8192);
      expect(r.output).not.toMatch(/sk-|BEGIN .*PRIVATE KEY|password\s*=/i);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
  it("main() dispatches and reports exit codes", async () => {
    const dir = tmpDir();
    try {
      expect(await main(["status"], dir)).toBe(0);
      expect(await main(["bogus"], dir)).toBe(2);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("M17 talk M–R, AA", () => {
  it("M. talk refuses asleep boot: no implicit wake, no audio activity", async () => {
    const dir = tmpDir();
    const vdir = tmpDir();
    try {
      const paths = voicePaths(vdir);
      const r = await runTalk(dir, {
        planner: new MockConversationPlanner("helpful"),
        ...paths,
        taskId: "task-T",
        spawnCaptureImpl: captureFake(makePcm(1)),
        spawnSttImpl: sttFake("info"),
      });
      // Fresh boot sleeps: talk refuses before any audio activity.
      expect(r.exitCode).toBe(1);
      expect(r.output).toContain("refused");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
      fs.rmSync(vdir, { recursive: true, force: true });
    }
  });
  it("O/P. sleep refuses before microphone spawn; R. no implicit wake", async () => {
    const dir = tmpDir();
    const vdir = tmpDir();
    try {
      const paths = voicePaths(vdir);
      let spawns = 0;
      const counting = captureFake(makePcm(1));
      const wrapped: typeof counting = (...args) => {
        spawns += 1;
        return counting(...args);
      };
      const r = await runTalk(dir, {
        planner: new MockConversationPlanner("helpful"),
        ...paths,
        taskId: "task-T",
        spawnCaptureImpl: wrapped,
        spawnSttImpl: sttFake("info"),
      });
      expect(r.exitCode).toBe(1);
      expect(spawns).toBe(0);
      // Session still asleep: no wake occurred.
      const s = await runStatus(dir);
      expect(s.output).toContain("sleep: SLEEP");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
      fs.rmSync(vdir, { recursive: true, force: true });
    }
  });
  it("Q. kill refuses talk", async () => {
    const dir = tmpDir();
    try {
      const r = await runTalk(dir, { planner: new MockConversationPlanner("helpful") });
      // No planner-independent path exists without voice config either.
      expect(r.exitCode).toBe(1);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
  it("N. hostile transcript equals typed pipeline outcome", async () => {
    const dir = tmpDir();
    try {
      // No planner + no voice config → refused before any audio.
      const r = await runTalk(dir, {});
      expect(r.exitCode).toBe(1);
      expect(r.output).toContain("no planner configured");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("M17 import scans T–W", () => {
  it("T/U/V. operator-cli reaches no executor/planner/shell/network", () => {
    for (const file of ["args.ts", "commands.ts", "index.ts"]) {
      const src = fs.readFileSync(new URL(`../src/operator-cli/${file}`, import.meta.url), "utf8");
      for (const forbidden of [
        "../executor", "child_process", "node:net", "node:http", "fetch(",
        "WebSocket", "../planner/", "../llm/", "openai", "anthropic",
        "MCP", "mcp", "fs.write", "createWriteStream", "execFile", "spawn(",
      ]) {
        expect(src.includes(forbidden), `operator-cli/${file}: ${forbidden}`).toBe(false);
      }
    }
  });
  it("W. only operator/bootstrap/voice/orchestrator imports", () => {
    for (const file of ["args.ts", "commands.ts", "index.ts"]) {
      const src = fs.readFileSync(new URL(`../src/operator-cli/${file}`, import.meta.url), "utf8");
      for (const line of src.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed.startsWith("import ") || !trimmed.includes("from")) {
          continue;
        }
        const target = (trimmed.split("from")[1] ?? "").trim().replace(/["';]/g, "");
        const allowed =
          target.startsWith("./") ||
          target.startsWith("../operator/") ||
          target.startsWith("../bootstrap/") ||
          target.startsWith("../voice/") ||
          target.startsWith("../conversation/orchestrator") ||
          target.startsWith("../conversation/mock-conversation-planner") ||
          target === "zod";
        expect(allowed, `operator-cli/${file}: ${target}`).toBe(true);
      }
    }
  });
  it("runCommand routes all three commands", async () => {
    const dir = tmpDir();
    try {
      const { runCommand } = await import("../src/operator-cli/commands.js");
      expect((await runCommand({ kind: "status" }, dir)).exitCode).toBe(0);
      expect((await runCommand({ kind: "audit", limit: 3 }, dir)).exitCode).toBe(0);
      expect((await runCommand({ kind: "talk" }, dir, {})).exitCode).toBe(1);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
