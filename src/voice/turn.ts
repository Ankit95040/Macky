/**
 * Voice-to-conversation turn adapter (M15). Pure sequencing, zero
 * authority: run one M14 push-to-talk session, and if it yields a
 * validated non-blank transcript, pass that EXACT string to the
 * EXISTING handleUserMessage() as if typed. Every other outcome
 * (refused/failed/cancelled/blank) returns without invoking the
 * planner at all.
 *
 * What this layer CANNOT do by construction (it holds no such
 * references): mint taskIds (taskId arrives via trusted opts, same
 * as the typed path), attach grants, set tiers, confirm anything,
 * wake the system, touch sleep/kill state, reach the audit sink, or
 * call any executor/authorize path directly. Sleep/kill/epoch/
 * confirmation remain enforced by M14's gates and the unchanged
 * M6/M2 chain downstream. Voice output (speech.announce) is NEVER
 * produced here — vocalizing a result requires the separate,
 * digest-confirmed M13 flow.
 */
import {
  beginVoiceSession,
  endVoiceSession,
  type VoiceSessionConfig,
  type VoiceSessionOptions,
} from "./session.js";
import {
  handleUserMessage,
  type AssistantResult,
  type OrchestratorContext,
} from "../conversation/orchestrator.js";
import type { VoiceResult } from "./results.js";

export interface VoiceTurnOptions {
  readonly taskId?: string;
  readonly maxRecordingMs?: number;
  readonly sttTimeoutMs?: number;
  readonly spawnCaptureImpl?: VoiceSessionOptions["spawnCaptureImpl"];
  readonly spawnSttImpl?: VoiceSessionOptions["spawnSttImpl"];
}

export interface VoiceTurnResult {
  readonly voice: VoiceResult;
  /** Absent unless a transcript was actually routed to conversation. */
  readonly assistant?: AssistantResult;
}

export async function handleVoiceTurn(
  orchCtx: OrchestratorContext,
  voiceConfig: VoiceSessionConfig,
  opts?: VoiceTurnOptions,
): Promise<VoiceTurnResult> {
  const started = beginVoiceSession(voiceConfig, {
    ...(opts?.maxRecordingMs !== undefined ? { maxRecordingMs: opts.maxRecordingMs } : {}),
    ...(opts?.spawnCaptureImpl !== undefined ? { spawnCaptureImpl: opts.spawnCaptureImpl } : {}),
  });
  if (!started.ok) {
    return {
      voice: { v: 1, status: "refused", durationMs: 0, reason: started.reason },
    };
  }
  const done = await endVoiceSession(voiceConfig, started.sessionId, {
    ...(opts?.sttTimeoutMs !== undefined ? { sttTimeoutMs: opts.sttTimeoutMs } : {}),
    ...(opts?.spawnSttImpl !== undefined ? { spawnSttImpl: opts.spawnSttImpl } : {}),
  });
  if (done.status !== "completed" || done.transcript === undefined) {
    return { voice: done };
  }
  // Blank transcripts never reach the planner: an empty/whitespace
  // utterance is inert, not a conversation message.
  if (done.transcript.trim().length === 0) {
    return { voice: done };
  }
  const assistant = await handleUserMessage(
    orchCtx,
    done.transcript,
    opts?.taskId !== undefined ? { taskId: opts.taskId } : undefined,
  );
  return { voice: done, assistant };
}
