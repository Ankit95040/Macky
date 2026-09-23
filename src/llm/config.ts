/**
 * Trusted provider configuration (M12). Administrator/runtime
 * controlled ONLY: explicit constructor argument or the LLM_*
 * environment variables below. Planner input cannot select endpoint,
 * model, credentials, headers, proxy, TLS, timeout, or permissions.
 * The API key VALUE is never stored here — only the variable NAME;
 * the value is read at call time inside the provider and never
 * logged, returned, or embedded anywhere.
 */
import { LLM_LIMITS } from "./limits.js";

export interface LlmConfigInput {
  readonly endpoint?: string;
  readonly model?: string;
  readonly apiKeyEnvVar?: string;
  readonly timeoutMs?: number;
  readonly maxOutputTokens?: number;
  /** Opt-in for documented local-provider development. Default false. */
  readonly allowLocalEndpoint?: boolean;
}

export interface LlmConfig {
  readonly endpoint: string;
  readonly model: string;
  readonly apiKeyEnvVar: string;
  readonly timeoutMs: number;
  readonly maxOutputTokens: number;
  readonly allowLocalEndpoint: boolean;
}

export type ConfigResult =
  | { readonly ok: true; readonly config: LlmConfig }
  | { readonly ok: false; readonly reason: string };

function invalid(reason: string): ConfigResult {
  return { ok: false, reason };
}

/** Trusted endpoint policy: HTTPS, no creds/fragments, no local by default. */
export function validateEndpoint(raw: string, allowLocal: boolean): boolean {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    return false;
  }
  if (parsed.protocol !== "https:") {
    return false;
  }
  if (parsed.username.length > 0 || parsed.password.length > 0 || parsed.hash.length > 0) {
    return false;
  }
  if (parsed.port !== "" ) {
    // Explicit ports only via trusted config; still require allowLocal-style
    // deliberateness — M12 refuses them outright (documented).
    return false;
  }
  const host = parsed.hostname.toLowerCase().replace(/\.$/, "");
  if (host.length === 0 || host === "localhost" || host.endsWith(".localhost")) {
    return allowLocal;
  }
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
    const octets = host.split(".").map(Number);
    const first = octets[0] ?? 256;
    const second = octets[1] ?? 0;
    const isPrivate =
      first === 127 || first === 10 || first === 0 ||
      (first === 172 && second >= 16 && second <= 31) ||
      (first === 192 && second === 168) ||
      (first === 169 && second === 254);
    return allowLocal ? true : !isPrivate;
  }
  return true;
}

const MODEL_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

export function resolveLlmConfig(input?: LlmConfigInput): ConfigResult {
  const endpoint = input?.endpoint ?? process.env["LLM_ENDPOINT"] ?? "";
  const model = input?.model ?? process.env["LLM_MODEL"] ?? "";
  const apiKeyEnvVar = input?.apiKeyEnvVar ?? process.env["LLM_API_KEY_ENV"] ?? "LLM_API_KEY";
  const allowLocalEndpoint = input?.allowLocalEndpoint ?? false;
  if (endpoint === "" || model === "") {
    return invalid("provider endpoint/model unconfigured");
  }
  if (!validateEndpoint(endpoint, allowLocalEndpoint)) {
    return invalid("provider endpoint violates trusted URL policy");
  }
  if (!MODEL_PATTERN.test(model)) {
    return invalid("model identifier malformed");
  }
  if (!/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(apiKeyEnvVar)) {
    return invalid("api key variable name malformed");
  }
  const timeoutMs = input?.timeoutMs ?? LLM_LIMITS.REQUEST_TIMEOUT_MS;
  const maxOutputTokens = input?.maxOutputTokens ?? LLM_LIMITS.MAX_OUTPUT_TOKENS;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 60000) {
    return invalid("timeout outside trusted range");
  }
  if (!Number.isInteger(maxOutputTokens) || maxOutputTokens < 1 || maxOutputTokens > 4096) {
    return invalid("output token budget outside trusted range");
  }
  return {
    ok: true,
    config: { endpoint, model, apiKeyEnvVar, timeoutMs, maxOutputTokens, allowLocalEndpoint },
  };
}
