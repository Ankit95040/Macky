/**
 * M14 centralized voice limits. Security limits, never planner-,
 * transcript-, or model-controlled. Push-to-talk audio is bounded in
 * duration, bytes, and resulting text; over-limit input refuses,
 * never truncates into a new meaning.
 */
export const VOICE_LIMITS = {
  /** Hard recording cap per session (helper enforces too). */
  MAX_RECORDING_SECONDS: 30,
  /** 16 kHz × 2 bytes × 30 s = 960,000; hard buffer cap with margin. */
  MAX_AUDIO_BYTES: 1_048_576,
  /** Transcript bound in Unicode code points. Refuse beyond. */
  MAX_TRANSCRIPT_CHARS: 2048,
  /** STT wall-clock budget per utterance. */
  STT_TIMEOUT_MS: 60_000,
  /** Capture watchdog margin over the recording cap. */
  CAPTURE_TIMEOUT_MS: 35_000,
  /** One voice session per process. No queue, no background work. */
  MAX_CONCURRENT_SESSIONS: 1,
  /** Trusted audio contract with the capture helper. */
  SAMPLE_RATE: 16000,
  CHANNELS: 1,
  BYTES_PER_SAMPLE: 2,
} as const;
