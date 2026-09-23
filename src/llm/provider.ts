/**
 * Narrow provider abstraction (M12). The provider receives ONLY
 * validated inert data (prompt text, token budget, abort signal) and
 * returns raw text or a typed transport error. It never sees grants,
 * capabilities, epoch, kill state, secrets (except the API key it
 * reads itself at call time), paths, registries, audit, decisions,
 * or policy.
 */
export interface LlmGenerateRequest {
  readonly prompt: string;
  readonly maxOutputTokens: number;
  readonly signal?: AbortSignal;
}

export type LlmRawResponse =
  | { readonly status: "ok"; readonly bodyText: string }
  | { readonly status: "error"; readonly code: "network-error" | "http-error" | "unavailable" };

export interface LlmProvider {
  generate(request: LlmGenerateRequest): Promise<LlmRawResponse>;
}
