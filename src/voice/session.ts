/**
 * Trusted audio-session controller (M14). Push-to-talk state machine:
 * idle → recording → transcribed/cancelled/failed. Single use per
 * handle; buffers owned by exactly one session and zeroed after use.
 *
 * Gates (sleep/kill) are checked at begin AND re-checked before
 * transcription — a transition mid-recording terminates and discards.
 * The session holds NO task, grant, epoch, policy, or planner
 * reference; its only product is an untrusted transcript string the
 * caller routes into handleUserMessage. Reboot leaves nothing: all
 * state is in-memory, no files, no persistence.
 */
import { startCapture, type CaptureHandle, type CaptureSpawnFn } from "./capture.js";
import { transcribeAudio, type SttSpawnFn } from "./stt.js";
import { VOICE_LIMITS } from "./limits.js";
import type { VoiceResult } from "./results.js";

export interface VoiceGate {
  readonly asleep: boolean;
  readonly killEngaged: boolean;
}

export interface VoiceSessionConfig {
  readonly helperPath: string;
  readonly binaryPath: string;
  readonly modelPath: string;
  readonly modelSha256: string;
  readonly gate: () => VoiceGate;
}

export interface VoiceSessionOptions {
  readonly maxRecordingMs?: number;
  readonly sttTimeoutMs?: number;
  readonly spawnCaptureImpl?: CaptureSpawnFn;
  readonly spawnSttImpl?: SttSpawnFn;
}

interface LiveSession {
  readonly id: number;
  readonly capture: CaptureHandle;
  readonly startedAt: number;
  consumed: boolean;
}

let voiceInFlight = 0;
let nextSessionId = 1;
const liveSessions = new Map<number, LiveSession>();

export function tryAcquireVoiceSlot(): boolean {
  if (voiceInFlight >= VOICE_LIMITS.MAX_CONCURRENT_SESSIONS) {
    return false;
  }
  voiceInFlight += 1;
  return true;
}

export function releaseVoiceSlot(): void {
  voiceInFlight = Math.max(0, voiceInFlight - 1);
}

function validPath(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.startsWith("/") && !value.includes("\0");
}

/** Begin recording. Refuses asleep/killed/busy/invalid config before any audio API. */
export function beginVoiceSession(
  config: VoiceSessionConfig,
  opts?: VoiceSessionOptions,
): { readonly ok: true; readonly sessionId: number } | { readonly ok: false; readonly reason: string } {
  const gate = config.gate();
  if (gate.asleep) {
    return { ok: false, reason: "system is asleep" };
  }
  if (gate.killEngaged) {
    return { ok: false, reason: "kill switch engaged" };
  }
  if (!validPath(config.helperPath) || !validPath(config.binaryPath) || !validPath(config.modelPath)) {
    return { ok: false, reason: "invalid voice configuration" };
  }
  if (!tryAcquireVoiceSlot()) {
    return { ok: false, reason: "another voice session is active" };
  }
  const { handle } = startCapture(config.helperPath, {
    ...(opts?.spawnCaptureImpl !== undefined ? { spawnImpl: opts.spawnCaptureImpl } : {}),
    ...(opts?.maxRecordingMs !== undefined ? { maxRecordingMs: opts.maxRecordingMs } : {}),
  });
  const id = nextSessionId;
  nextSessionId += 1;
  liveSessions.set(id, { id, capture: handle, startedAt: Date.now(), consumed: false });
  void opts;
  return { ok: true, sessionId: id };
}

function takeSession(sessionId: number): LiveSession | undefined {
  const live = liveSessions.get(sessionId);
  if (live === undefined || live.consumed) {
    return undefined;
  }
  live.consumed = true;
  liveSessions.delete(sessionId);
  return live;
}

/** End recording, transcribe, return the transcript. Consumes the session. */
export async function endVoiceSession(
  config: VoiceSessionConfig,
  sessionId: number,
  opts?: VoiceSessionOptions,
): Promise<VoiceResult> {
  const live = takeSession(sessionId);
  if (live === undefined) {
    return { v: 1, status: "refused", durationMs: 0, reason: "unknown or consumed voice session" };
  }
  const durationMs = Date.now() - live.startedAt;
  // Release means stop NOW: terminate capture (the helper finalizes
  // whatever was recorded), then collect. Never await natural
  // completion — the key release IS the stop signal.
  live.capture.kill("SIGTERM");
  setTimeout(() => live.capture.kill("SIGKILL"), 1_000);
  const captured = await live.capture.done;
  // Gate first: an asleep/killed system refuses regardless of what
  // capture produced. A broken capture under a healthy gate fails.
  const gate = config.gate();
  if (gate.asleep || gate.killEngaged) {
    if (captured.ok) {
      captured.wav.fill(0);
    }
    releaseVoiceSlot();
    return { v: 1, status: "refused", durationMs, reason: gate.asleep ? "system fell asleep" : "kill switch engaged" };
  }
  if (!captured.ok) {
    releaseVoiceSlot();
    return { v: 1, status: "failed", durationMs, reason: captured.reason };
  }
  const transcribed = await transcribeAudio(
    { binaryPath: config.binaryPath, modelPath: config.modelPath, modelSha256: config.modelSha256 },
    captured.wav,
    {
      ...(opts?.spawnSttImpl !== undefined ? { spawnImpl: opts.spawnSttImpl } : {}),
      ...(opts?.sttTimeoutMs !== undefined ? { timeoutMs: opts.sttTimeoutMs } : {}),
    },
  );
  captured.wav.fill(0);
  releaseVoiceSlot();
  if (!transcribed.ok) {
    return { v: 1, status: "failed", durationMs, reason: transcribed.reason };
  }
  // Post-transcription gate: sleep/kill that engaged DURING the
  // transcribe await discards the result. The transcript is inert,
  // but a killed/asleep system must not produce new work output.
  const after = config.gate();
  if (after.asleep || after.killEngaged) {
    return { v: 1, status: "refused", durationMs, reason: after.asleep ? "system fell asleep" : "kill switch engaged" };
  }
  return {
    v: 1,
    status: "completed",
    transcript: transcribed.transcript,
    audioBytes: captured.wav.length,
    durationMs,
  };
}

/** Cancel: terminate capture, discard everything, consume the session. */
export function cancelVoiceSession(sessionId: number): VoiceResult {
  const live = liveSessions.get(sessionId);
  if (live === undefined || live.consumed) {
    return { v: 1, status: "refused", durationMs: 0, reason: "unknown or consumed voice session" };
  }
  live.consumed = true;
  liveSessions.delete(sessionId);
  live.capture.kill("SIGTERM");
  setTimeout(() => live.capture.kill("SIGKILL"), 1_000);
  releaseVoiceSlot();
  return { v: 1, status: "cancelled", durationMs: Date.now() - live.startedAt };
}
