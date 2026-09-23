/**
 * Trusted process runner (M8 sections 7/10/11/12). Direct spawn ONLY:
 * exact executable, exact argv array, shell never involved — there is
 * no code path that renders executable+argv into a string. stdin is
 * ignored, no PTY, no shell startup files, fixed minimal environment.
 *
 * Bounded streaming (per-stream byte caps with truncation flags),
 * timeout with SIGTERM→(grace)→SIGKILL escalation, single in-flight
 * command guard. spawn is injectable so timeout/cleanup paths are
 * unit-testable without slow binaries. Unicode-safe decode via
 * StringDecoder (no split multibyte sequences).
 */
import { spawn as nodeSpawn, type ChildProcess } from "node:child_process";
import { StringDecoder } from "node:string_decoder";
import { COMMAND_LIMITS } from "./limits.js";
import { truncateText } from "../workspace/text.js";
import type { CommandDefinition } from "./registry.js";
import type { CommandResult } from "./result.js";

/** Exact environment a child receives. Nothing else. Ever. */
export function buildChildEnv(): Record<string, string> {
  return { LC_ALL: "C" };
}

/** Minimal child surface the runner needs (Node's ChildProcess satisfies it). */
export interface SpawnedProcess {
  readonly stdout: { on(event: "data", cb: (chunk: Buffer) => void): void } | null;
  readonly stderr: { on(event: "data", cb: (chunk: Buffer) => void): void } | null;
  on(event: "error" | "exit" | "close", cb: (...args: Array<unknown>) => void): void;
  kill(signal?: string): boolean;
}

export type SpawnFn = (
  executable: string,
  argv: ReadonlyArray<string>,
  opts: { cwd: string; env: Record<string, string>; stdio: Array<string> },
) => SpawnedProcess;

const defaultSpawn: SpawnFn = (exe, argv, opts) =>
  nodeSpawn(exe, [...argv], {
    cwd: opts.cwd,
    env: opts.env,
    stdio: opts.stdio as Array<"ignore" | "pipe" | "pipe">,
    shell: false,
    windowsHide: true,
  }) as unknown as SpawnedProcess;

let inFlight = 0;

/** Single-command guard (M8 concurrency limit: 1). */
export function tryAcquireCommandSlot(): boolean {
  if (inFlight >= COMMAND_LIMITS.MAX_CONCURRENT_COMMANDS) {
    return false;
  }
  inFlight += 1;
  return true;
}

export function releaseCommandSlot(): void {
  inFlight = Math.max(0, inFlight - 1);
}

export interface RunOptions {
  readonly timeoutMs?: number;
  readonly spawnImpl?: SpawnFn;
}

interface Collected {
  text: string;
  truncated: boolean;
}

/**
 * Spawn, stream bounded output, enforce timeout with escalation.
 * Resolves refused-style CommandResults for every outcome — never
 * throws on process behavior (spawn setup errors become `failed`).
 */
export async function runSpawned(
  definition: CommandDefinition,
  argv: ReadonlyArray<string>,
  cwd: string,
  opts?: RunOptions,
): Promise<CommandResult> {
  const timeoutMs = opts?.timeoutMs ?? COMMAND_LIMITS.COMMAND_TIMEOUT_MS;
  const spawnImpl = opts?.spawnImpl ?? defaultSpawn;
  const started = Date.now();
  let child: SpawnedProcess;
  try {
    child = spawnImpl(definition.executable, argv, {
      cwd,
      env: buildChildEnv(),
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch {
    return {
      v: 1, status: "failed", stdout: "", stderr: "",
      stdoutTruncated: false, stderrTruncated: false, durationMs: 0,
    };
  }

  const outDecoder = new StringDecoder("utf8");
  const errDecoder = new StringDecoder("utf8");

  const onData = (
    chunk: Buffer,
    state: { bytes: number; text: string; truncated: boolean },
    cap: number,
    decoder: StringDecoder,
  ): void => {
    const remaining = cap - state.bytes;
    if (remaining <= 0) {
      state.truncated = true;
      return;
    }
    const slice = chunk.subarray(0, remaining);
    state.bytes += slice.length;
    state.text += decoder.write(slice);
    if (chunk.length > remaining) {
      state.truncated = true;
    }
  };

  const outState = { bytes: 0, text: "", truncated: false };
  const errState = { bytes: 0, text: "", truncated: false };
  child.stdout?.on("data", (chunk: Buffer) => {
    onData(chunk, outState, COMMAND_LIMITS.MAX_STDOUT_BYTES, outDecoder);
  });
  child.stderr?.on("data", (chunk: Buffer) => {
    onData(chunk, errState, COMMAND_LIMITS.MAX_STDERR_BYTES, errDecoder);
  });

  let timedOut = false;
  let settled = false;
  const outcome = await new Promise<{
    exitCode: number | undefined;
    signal: string | undefined;
    spawnError: boolean;
  }>((resolve) => {
    const finish = (exitCode: number | undefined, signal: string | undefined, spawnError: boolean): void => {
      if (settled) {
        return;
      }
      settled = true;
      resolve({ exitCode, signal, spawnError });
    };
    const timer = setTimeout(() => {
      timedOut = true;
      try {
        child.kill("SIGTERM");
      } catch {
        finish(undefined, undefined, true);
        return;
      }
      setTimeout(() => {
        try {
          child.kill("SIGKILL");
        } catch {
          // Already gone; exit/close below still settles.
        }
      }, COMMAND_LIMITS.KILL_GRACE_MS);
    }, timeoutMs);
    child.on("error", () => {
      clearTimeout(timer);
      finish(undefined, undefined, true);
    });
    child.on("exit", (code: unknown, signal: unknown) => {
      clearTimeout(timer);
      finish(
        typeof code === "number" ? code : undefined,
        typeof signal === "string" ? signal : undefined,
        false,
      );
    });
  });

  outState.text += outDecoder.end();
  errState.text += errDecoder.end();
  // Belt and suspenders: byte caps enforced while streaming; final
  // Unicode-safe bounding on decode (shared M7 utility).
  const outFinal = truncateText(outState.text, COMMAND_LIMITS.MAX_STDOUT_BYTES, "…[truncated]");
  const errFinal = truncateText(errState.text, COMMAND_LIMITS.MAX_STDERR_BYTES, "…[truncated]");
  const durationMs = Date.now() - started;

  if (timedOut) {
    return {
      v: 1, status: "timed-out",
      signal: outcome.signal,
      stdout: outFinal.text, stderr: errFinal.text,
      stdoutTruncated: outState.truncated || outFinal.truncated,
      stderrTruncated: errState.truncated || errFinal.truncated,
      durationMs,
    };
  }
  if (outcome.spawnError) {
    return {
      v: 1, status: "failed", stdout: "", stderr: "",
      stdoutTruncated: false, stderrTruncated: false, durationMs,
    };
  }
  return {
    v: 1,
    status: "completed",
    ...(outcome.exitCode !== undefined ? { exitCode: outcome.exitCode } : {}),
    ...(outcome.signal !== undefined ? { signal: outcome.signal } : {}),
    stdout: outFinal.text,
    stderr: errFinal.text,
    stdoutTruncated: outState.truncated || outFinal.truncated,
    stderrTruncated: errState.truncated || errFinal.truncated,
    durationMs,
  };
}
