/**
 * Typed bounded LLM outcomes (M12 results). Failures are codes, never
 * secrets: no API key, headers, credentials, raw HTTP, or unbounded
 * model output ever leaves this layer.
 */
export type LlmFailureCode =
  | "provider-unavailable"
  | "provider-timeout"
  | "provider-invalid-response"
  | "provider-response-too-large"
  | "provider-network-error";

export type LlmOutcome =
  | { readonly status: "ok"; readonly proposal: unknown; readonly bytes: number; readonly durationMs: number }
  | { readonly status: "error"; readonly code: LlmFailureCode };

export class LlmPlannerError extends Error {
  readonly code: LlmFailureCode | "planner-input-too-large" | "slot-busy" | "session-not-ready";
  constructor(code: LlmPlannerError["code"], message: string) {
    super(message);
    this.name = "LlmPlannerError";
    this.code = code;
  }
}
