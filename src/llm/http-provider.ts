/**
 * Real HTTPS provider (M12 network boundary). The ONLY place in
 * Macky that performs an external network request. Fixed POST to the
 * trusted configured endpoint, fixed headers built by trusted code
 * (content-type + bearer key read at call time — never logged,
 * never returned), no cookies, no redirects (fail closed), no proxy
 * configuration, no planner influence on URL/method/headers/body
 * shape. fetch is injectable so header/body discipline is unit-testable
 * without network.
 */
import type { LlmConfig } from "./config.js";
import type { LlmProvider, LlmRawResponse } from "./provider.js";
import { SYSTEM_PROMPT } from "./system-prompt.js";

export type FetchImpl = (
  url: string,
  init: {
    method: string;
    headers: Record<string, string>;
    body: string;
    redirect: "error";
    signal: AbortSignal | undefined;
  },
) => Promise<{ ok: boolean; status: number; text(): Promise<string> }>;

async function readBodyText(res: { text(): Promise<string> }): Promise<string> {
  // Byte caps are enforced by the planner adapter, not here: this
  // helper only transports text. Failures become network errors.
  return res.text();
}

export interface HttpProviderOptions {
  readonly fetchImpl?: FetchImpl;
}

export function createHttpLlmProvider(config: LlmConfig, opts?: HttpProviderOptions): LlmProvider {
  const fetchImpl: FetchImpl = opts?.fetchImpl ?? (async (url, init) => {
    const res = await fetch(url, {
      method: init.method,
      headers: init.headers,
      body: init.body,
      redirect: init.redirect,
      signal: init.signal ?? null,
    });
    return { ok: res.ok, status: res.status, text: () => res.text() };
  });
  return {
    async generate(request): Promise<LlmRawResponse> {
      const apiKey = process.env[config.apiKeyEnvVar];
      if (typeof apiKey !== "string" || apiKey.length === 0) {
        return { status: "error", code: "unavailable" };
      }
      // Fixed mainstream chat-completions shape. No tools/function-
      // calling fields — the provider can never become an executor.
      // max_tokens comes from TRUSTED config, never the request.
      const body = JSON.stringify({
        model: config.model,
        messages: [
          { role: "system", content: SYSTEM_PROMPT },
          { role: "user", content: request.prompt },
        ],
        max_tokens: config.maxOutputTokens,
        temperature: 0,
        stream: false,
      });
      let res: { ok: boolean; status: number; text(): Promise<string> };
      try {
        res = await fetchImpl(config.endpoint, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            authorization: `Bearer ${apiKey}`,
          },
          body,
          redirect: "error",
          signal: request.signal,
        });
      } catch {
        return { status: "error", code: "network-error" };
      }
      if (!res.ok) {
        return { status: "error", code: "http-error" };
      }
      let text: string;
      try {
        text = await readBodyText(res);
      } catch {
        return { status: "error", code: "network-error" };
      }
      return { status: "ok", bodyText: text };
    },
  };
}
