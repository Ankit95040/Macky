/**
 * Trusted local STT invocation (M14, native adapter). Fixed binary
 * (first-party stt-adapter) + fixed argv ([modelPath]); the raw PCM
 * buffer is written to stdin, never to disk. Model file is
 * hash-pinned: existence + SHA-256 equality against the trusted
 * expected value BEFORE spawn — missing/corrupt/unverified models
 * refuse without invoking anything. stdout is bounded, decoded
 * UTF-8, and validated (non-empty, ≤2048 code points, no NUL). No
 * repair, no truncation, no fallback. whisper-cli is NOT used: its
 * miniaudio loader cannot consume non-seekable stdin reliably.
 */
import { createHash } from "node:crypto";
import * as fs from "node:fs";
import { spawn as nodeSpawn } from "node:child_process";
import { StringDecoder } from "node:string_decoder";
import { VOICE_LIMITS } from "./limits.js";

export interface SttConfig {
  readonly binaryPath: string;
  readonly modelPath: string;
  readonly modelSha256: string;
}

export type SttOutcome =
  | { readonly ok: true; readonly transcript: string }
  | { readonly ok: false; readonly reason: string };

export interface SpawnedStt {
  readonly stdin: {
    write(chunk: Buffer): boolean;
    end(): void;
    on(event: "error", cb: (err: unknown) => void): void;
  } | null;
  readonly stdout: { on(event: "data", cb: (chunk: Buffer) => void): void } | null;
  readonly stderr: { on(event: "data", cb: (chunk: Buffer) => void): void } | null;
  on(event: "error" | "exit" | "close", cb: (...args: Array<unknown>) => void): void;
  kill(signal?: string): boolean;
}

export type SttSpawnFn = (
  executable: string,
  argv: ReadonlyArray<string>,
  opts: { env: Record<string, string>; stdio: Array<string> },
) => SpawnedStt;

const defaultSttSpawn: SttSpawnFn = (exe, argv, opts) =>
  nodeSpawn(exe, [...argv], {
    env: opts.env,
    stdio: opts.stdio as Array<"ignore" | "pipe" | "pipe" | "pipe">,
    shell: false,
    windowsHide: true,
  }) as unknown as SpawnedStt;

export interface SttOptions {
  readonly spawnImpl?: SttSpawnFn;
  /** Trusted test override for the STT budget (production: 60 s). */
  readonly timeoutMs?: number;
}

/** Hash-pin verification: existence + exact SHA-256 match. */
export function verifyModel(modelPath: string, expectedSha256: string): boolean {
  let data: Buffer;
  try {
    data = fs.readFileSync(modelPath);
  } catch {
    return false;
  }
  if (!/^[0-9a-f]{64}$/.test(expectedSha256)) {
    return false;
  }
  const actual = createHash("sha256").update(data).digest("hex");
  data.fill(0);
  return actual === expectedSha256;
}

/** Strip whisper-cli `[00:00:00.000 --> 00:00:05.000]` segment prefixes. */
export function normalizeTranscript(raw: string): string {
  return raw
    .split("\n")
    .map((line) => line.replace(/^\[[^\]]*\]\s*/, "").trim())
    .filter((line) => line.length > 0)
    .join("\n")
    .trim();
}

export async function transcribeAudio(
  config: SttConfig,
  wav: Buffer,
  opts?: SttOptions,
): Promise<SttOutcome> {
  const timeoutMs = opts?.timeoutMs ?? VOICE_LIMITS.STT_TIMEOUT_MS;
  if (!verifyModel(config.modelPath, config.modelSha256)) {
    return { ok: false, reason: "model missing, corrupt, or unverified" };
  }
  let statOk = false;
  try {
    const st = fs.statSync(config.binaryPath);
    statOk = st.isFile();
  } catch {
    statOk = false;
  }
  if (!statOk) {
    return { ok: false, reason: "transcriber binary unavailable" };
  }
  try {
    fs.accessSync(config.binaryPath, fs.constants.X_OK);
  } catch {
    return { ok: false, reason: "transcriber binary not executable" };
  }
  const spawnImpl = opts?.spawnImpl ?? defaultSttSpawn;
  let child: SpawnedStt;
  try {
    // Adapter argv is exactly [modelPath]: the adapter takes no flags
    // ( whisper-cli-style "-m/-f/-l" flags are NOT its contract —
    // passing them yields usage exit 2, caught by integration test).
    child = spawnImpl(config.binaryPath, [config.modelPath], {
      env: { LC_ALL: "C" },
      stdio: ["pipe", "pipe", "pipe"],
    });
  } catch {
    return { ok: false, reason: "transcriber spawn failed" };
  }
  const decoder = new StringDecoder("utf8");
  let text = "";
  let truncated = false;
  // Bound well above any valid transcript (2048 chars ≈ 8 KiB UTF-8).
  const CAP = 16 * 1024;
  let bytes = 0;
  child.stdout?.on("data", (chunk: Buffer) => {
    if (bytes >= CAP) {
      truncated = true;
      return;
    }
    const slice = chunk.subarray(0, CAP - bytes);
    bytes += slice.length;
    text += decoder.write(slice);
    if (chunk.length > slice.length) {
      truncated = true;
    }
  });
  try {
    // The child may exit before draining stdin (notably when input is
    // rejected): swallow async stdin errors here — process outcome is
    // decided by the exit/close handlers below, never by a throw.
    try {
      child.stdin?.on("error", () => {});
    } catch {
      // No error channel; exit handlers still decide the outcome.
    }
    child.stdin?.write(wav);
    child.stdin?.end();
  } catch {
    return { ok: false, reason: "transcriber input failed" };
  }
  let timedOut = false;
  let settled = false;
  const outcome = await new Promise<{ exitCode: number | undefined; spawnError: boolean }>((resolve) => {
    const finish = (exitCode: number | undefined, spawnError: boolean): void => {
      if (settled) {
        return;
      }
      settled = true;
      resolve({ exitCode, spawnError });
    };
    const timer = setTimeout(() => {
      timedOut = true;
      try {
        child.kill("SIGTERM");
      } catch {
        finish(undefined, true);
        return;
      }
      setTimeout(() => {
        try {
          child.kill("SIGKILL");
        } catch {
          // Already gone; exit below still settles.
        }
      }, 1_000);
    }, timeoutMs);
    child.on("error", () => {
      clearTimeout(timer);
      finish(undefined, true);
    });
    // Pipe-drain safety (see capture.ts): the exit code is recorded
    // on 'exit', but resolution waits for 'close' so trailing stdout
    // can never be lost to an early exit event.
    let recordedCode: number | undefined;
    let sawExit = false;
    child.on("exit", (code: unknown) => {
      sawExit = true;
      recordedCode = typeof code === "number" ? code : undefined;
    });
    child.on("close", () => {
      clearTimeout(timer);
      if (!sawExit) {
        finish(undefined, true);
        return;
      }
      finish(recordedCode, false);
    });
  });
  text += decoder.end();
  if (timedOut) {
    return { ok: false, reason: "transcription timeout" };
  }
  if (outcome.spawnError || outcome.exitCode !== 0) {
    return { ok: false, reason: "transcriber failed" };
  }
  if (truncated) {
    return { ok: false, reason: "transcriber output exceeded bound" };
  }
  const transcript = normalizeTranscript(text);
  if (transcript.length === 0 || transcript.includes("\0")) {
    return { ok: false, reason: "malformed or empty transcription" };
  }
  if (Array.from(transcript).length > VOICE_LIMITS.MAX_TRANSCRIPT_CHARS) {
    return { ok: false, reason: "transcript exceeds size bound" };
  }
  return { ok: true, transcript };
}
