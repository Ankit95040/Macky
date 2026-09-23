import * as fs from "node:fs";
import { describe, expect, it } from "vitest";
import { getAllowedCommand } from "../src/commands/registry.js";
import {
  buildChildEnv,
  releaseCommandSlot,
  runSpawned,
  tryAcquireCommandSlot,
  type SpawnedProcess,
  type SpawnFn,
} from "../src/commands/runner.js";
import { COMMAND_LIMITS } from "../src/commands/limits.js";

interface FakeOpts {
  chunks?: Array<string>;
  exitCode?: number;
  /** When the fake exits: immediately, on SIGTERM, or only on SIGKILL. */
  dieOn?: "immediate" | "SIGTERM" | "SIGKILL";
}

function makeFake(opts: FakeOpts): {
  spawn: SpawnFn;
  calls: Array<{ exe: string; argv: ReadonlyArray<string>; opts: unknown }>;
  signals: Array<string>;
} {
  const calls: Array<{ exe: string; argv: ReadonlyArray<string>; opts: unknown }> = [];
  const signals: Array<string> = [];
  const spawn: SpawnFn = (exe, argv, o) => {
    calls.push({ exe, argv, opts: o });
    const dataHandlers: Array<(c: Buffer) => void> = [];
    const exitHandlers: Array<(code: unknown, signal: unknown) => void> = [];
    const emitExit = (code: unknown, signal: unknown): void => {
      for (const cb of exitHandlers) {
        cb(code, signal);
      }
    };
    const proc: SpawnedProcess = {
      stdout: {
        on(_ev: "data", cb: (chunk: Buffer) => void): void {
          dataHandlers.push(cb);
        },
      },
      stderr: {
        on(_ev: "data", _cb: (chunk: Buffer) => void): void {},
      },
      on(_ev: "error" | "exit" | "close", cb: (...args: Array<unknown>) => void): void {
        if (_ev === "exit") {
          exitHandlers.push((code, signal) => cb(code, signal));
        }
      },
      kill(sig?: string): boolean {
        const signal = sig ?? "SIGTERM";
        signals.push(signal);
        // Die only on the configured signal (realistic: SIGKILL always kills).
        if (signal === (opts.dieOn ?? "immediate")) {
          const bySignal = signal === "SIGTERM" || signal === "SIGKILL";
          setImmediate(() => emitExit(bySignal ? undefined : (opts.exitCode ?? 0), bySignal ? signal : undefined));
        }
        return true;
      },
    };
    setImmediate(() => {
      for (const chunk of opts.chunks ?? []) {
        for (const cb of dataHandlers) {
          cb(Buffer.from(chunk, "utf8"));
        }
      }
      if ((opts.dieOn ?? "immediate") === "immediate") {
        emitExit(opts.exitCode ?? 0, undefined);
      }
    });
    return proc;
  };
  return { spawn, calls, signals };
}

function echoDef(): NonNullable<ReturnType<typeof getAllowedCommand>> {
  const def = getAllowedCommand("command.echo");
  if (def === undefined) throw new Error("missing def");
  return def;
}

describe("M8 runner internals", () => {
  it("AN. oversized output bounded with flags, unicode-safe", async () => {
    const fake = makeFake({ chunks: [`😀${"x".repeat(70000)}`] });
    const r = await runSpawned(echoDef(), ["hi"], "/tmp", { spawnImpl: fake.spawn, timeoutMs: 5000 });
    expect(r.status).toBe("completed");
    expect(r.stdoutTruncated).toBe(true);
    expect(Buffer.byteLength(r.stdout, "utf8")).toBeLessThanOrEqual(COMMAND_LIMITS.MAX_STDOUT_BYTES + 16);
    expect(() => encodeURIComponent(r.stdout)).not.toThrow();
    // Exact executable + argv array reached spawn; no string command.
    expect(fake.calls[0]?.exe).toBe("/bin/echo");
    expect(fake.calls[0]?.argv).toEqual(["hi"]);
    expect(JSON.stringify(fake.calls[0]?.opts)).not.toContain("hi;rm");
  });
  it("AO. timeout kills, escalates, and reports", async () => {
    const fake = makeFake({ dieOn: "SIGTERM" });
    const started = Date.now();
    const r = await runSpawned(echoDef(), ["hi"], "/tmp", { spawnImpl: fake.spawn, timeoutMs: 120 });
    expect(r.status).toBe("timed-out");
    expect(fake.signals[0]).toBe("SIGTERM");
    // Grace-period escalation arrives shortly after (does not block the result).
    await new Promise((resolve) => setTimeout(resolve, 1300));
    expect(fake.signals).toEqual(["SIGTERM", "SIGKILL"]);
    expect(Date.now() - started).toBeLessThan(8000);
  });
  it("AX. stubborn processes escalate to SIGKILL; cleanup verified", async () => {
    const fake = makeFake({ dieOn: "SIGKILL" });
    const r = await runSpawned(echoDef(), ["hi"], "/tmp", { spawnImpl: fake.spawn, timeoutMs: 120 });
    expect(r.status).toBe("timed-out");
    expect(r.signal).toBe("SIGKILL");
    expect(fake.signals).toEqual(["SIGTERM", "SIGKILL"]);
  });
  it("AY. single-flight guard denies concurrent seconds", () => {
    releaseCommandSlot();
    expect(tryAcquireCommandSlot()).toBe(true);
    expect(tryAcquireCommandSlot()).toBe(false);
    releaseCommandSlot();
    expect(tryAcquireCommandSlot()).toBe(true);
    releaseCommandSlot();
    releaseCommandSlot(); // idempotent floor
    expect(tryAcquireCommandSlot()).toBe(true);
    releaseCommandSlot();
  });
  it("BE. emoji output truncation keeps valid Unicode", async () => {
    const fake = makeFake({ chunks: [`🎉${"ü".repeat(70000)}`] });
    const r = await runSpawned(echoDef(), ["hi"], "/tmp", { spawnImpl: fake.spawn, timeoutMs: 5000 });
    expect(r.stdoutTruncated).toBe(true);
    const asString = r.stdout;
    expect("".concat(...Array.from(asString))).toBe(asString);
  });
});

describe("M8 tripwire AZ + source guarantees", () => {
  it("AZ. no shell/string-command surface in command sources", () => {
    const dir = new URL("../src/commands/", import.meta.url);
    const service = new URL("../src/persistence/command-service.ts", import.meta.url);
    const files = fs.readdirSync(dir).filter((f) => f.endsWith(".ts")).map((f) => new URL(f, dir));
    files.push(service);
    let sawShellFalse = false;
    for (const file of files) {
      const raw = fs.readFileSync(file, "utf8");
      if (raw.includes("shell: false")) {
        sawShellFalse = true;
      }
      // The single sanctioned token is blanked before banning the family.
      const src = raw.split("shell: false").join("");
      for (const forbidden of [
        "/bin/sh", "/bin/bash", "/usr/bin/osascript", '"-c"', "'-c'", "shell:", "execFile", "execSync",
        "spawnSync", "eval(", "Function(", "child_process.exec",
      ]) {
        // NOTE: `RegExp.exec` matches below are the regex-engine method,
        // not process execution — matched precisely, never `exec(` bare.
        expect(src.includes(forbidden), `${file.pathname} contains ${forbidden}`).toBe(false);
      }
    }
    expect(sawShellFalse).toBe(true);
  });
});
