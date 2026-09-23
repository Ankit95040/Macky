/**
 * Trusted microphone capture (M14 §4). Spawns the first-party Swift
 * helper with NO arguments — format, duration cap, and behavior are
 * compiled-in trusted constants, so no planner, transcript, or caller
 * data can configure capture. Raw PCM bytes accumulate in a bounded
 * in-memory buffer only (killed past the cap); nothing is written to
 * disk. Exit codes are the helper's trusted contract: 0 finished,
 * 1 audio/permission failure. Watchdog + SIGTERM→SIGKILL teardown.
 */
import { spawn as nodeSpawn } from "node:child_process";
import { VOICE_LIMITS } from "./limits.js";

export interface CaptureHandle {
  readonly kill: (signal?: string) => boolean;
  readonly done: Promise<CaptureOutcome>;
}

export type CaptureOutcome =
  | { readonly ok: true; readonly wav: Buffer }
  | { readonly ok: false; readonly reason: string };

export interface SpawnedCapture {
  readonly stdout: { on(event: "data", cb: (chunk: Buffer) => void): void } | null;
  readonly stderr: { on(event: "data", cb: (chunk: Buffer) => void): void } | null;
  on(event: "error" | "exit" | "close", cb: (...args: Array<unknown>) => void): void;
  kill(signal?: string): boolean;
}

export type CaptureSpawnFn = (
  executable: string,
  argv: ReadonlyArray<string>,
  opts: { env: Record<string, string>; stdio: Array<string> },
) => SpawnedCapture;

const defaultCaptureSpawn: CaptureSpawnFn = (exe, argv, opts) =>
  nodeSpawn(exe, [...argv], {
    env: opts.env,
    stdio: opts.stdio as Array<"ignore" | "pipe" | "pipe">,
    shell: false,
    windowsHide: true,
  }) as unknown as SpawnedCapture;

export interface CaptureOptions {
  readonly spawnImpl?: CaptureSpawnFn;
  /** Trusted test override for the duration bound (production: 30 s). */
  readonly maxRecordingMs?: number;
}

function childEnv(): Record<string, string> {
  return { LC_ALL: "C" };
}

/** Raw-PCM validation: non-empty, even byte count (int16 samples),
 *  within the audio bound. Format (16 kHz mono s16le) is guaranteed
 *  by the first-party helper contract, not parsed here — no format
 *  parsing means no format-parser attack surface. */
export function isValidRawPcm(bytes: Buffer): boolean {
  if (bytes.length === 0) {
    return false;
  }
  if (bytes.length % 2 !== 0) {
    return false;
  }
  if (bytes.length > VOICE_LIMITS.MAX_AUDIO_BYTES) {
    return false;
  }
  return true;
}

/**
 * Start capture. Resolves when the helper exits; rejects nothing —
 * every outcome is a typed value. Caller owns teardown via handle.
 */
export function startCapture(
  helperPath: string,
  opts?: CaptureOptions,
): { handle: CaptureHandle } {
  const spawnImpl = opts?.spawnImpl ?? defaultCaptureSpawn;
  const maxMs = opts?.maxRecordingMs ?? VOICE_LIMITS.MAX_RECORDING_SECONDS * 1000;
  let child: SpawnedCapture;
  try {
    // Fixed argv: none. The helper's contract is compiled in.
    child = spawnImpl(helperPath, [], { env: childEnv(), stdio: ["ignore", "pipe", "pipe"] });
  } catch {
    return {
      handle: {
        kill: () => false,
        done: Promise.resolve({ ok: false, reason: "capture spawn failed" } as const),
      },
    };
  }
  let chunks: Array<Buffer> = [];
  let buffered = 0;
  let overCap = false;
  const killChild = (signal?: string): boolean => {
    try {
      return child.kill(signal ?? "SIGTERM");
    } catch {
      return false;
    }
  };
  child.stdout?.on("data", (chunk: Buffer) => {
    if (overCap) {
      return;
    }
    if (buffered + chunk.length > VOICE_LIMITS.MAX_AUDIO_BYTES) {
      overCap = true;
      killChild("SIGTERM");
      setTimeout(() => killChild("SIGKILL"), 1_000);
      return;
    }
    chunks.push(chunk);
    buffered += chunk.length;
  });
  const done: Promise<CaptureOutcome> = new Promise((resolve) => {
    let settled = false;
    const finish = (outcome: CaptureOutcome): void => {
      if (settled) {
        return;
      }
      settled = true;
      if (outcome.ok) {
        resolve(outcome);
        return;
      }
      // Best-effort buffer hygiene on every failure path.
      for (const c of chunks) {
        c.fill(0);
      }
      chunks = [];
      resolve(outcome);
    };
    const watchdog = setTimeout(() => {
      killChild("SIGTERM");
      setTimeout(() => killChild("SIGKILL"), 1_000);
      finish({ ok: false, reason: "recording duration bound exceeded" });
    }, maxMs + Math.min(5_000, maxMs));
    // Pipe-drain safety: resolve on 'close' (stdio drained), not
    // 'exit' (which can precede pending stdout data). The exit code
    // is recorded separately for failure mapping.
    let exitCode: number | undefined;
    let sawExit = false;
    child.on("error", () => {
      clearTimeout(watchdog);
      finish({ ok: false, reason: "capture process error" });
    });
    child.on("exit", (code: unknown) => {
      sawExit = true;
      exitCode = typeof code === "number" ? code : undefined;
    });
    child.on("close", () => {
      clearTimeout(watchdog);
      if (!sawExit) {
        finish({ ok: false, reason: "capture process error" });
        return;
      }
      if (overCap) {
        finish({ ok: false, reason: "audio buffer bound exceeded" });
        return;
      }
      if (exitCode !== 0) {
        finish({ ok: false, reason: "capture failed (microphone unavailable or denied)" });
        return;
      }
      const wav = Buffer.concat(chunks);
      chunks = [];
      if (!isValidRawPcm(wav)) {
        wav.fill(0);
        finish({ ok: false, reason: "malformed capture output" });
        return;
      }
      finish({ ok: true, wav });
    });
  });
  return { handle: { kill: killChild, done } };
}
