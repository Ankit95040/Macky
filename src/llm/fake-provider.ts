/**
 * Deterministic fake LLM provider (M12 tests). ZERO network: canned
 * raw response strings served in order, scriptable hang/failure,
 * invocation counting (proves sleep/kill/concurrency gates). Same
 * input sequence → same outputs (AT).
 */
import type { LlmProvider, LlmRawResponse } from "./provider.js";

export interface FakeLlmScript {
  readonly responses: ReadonlyArray<string>;
  readonly hang?: boolean;
  readonly fail?: boolean;
}

export class FakeLlmProvider implements LlmProvider {
  private readonly script: FakeLlmScript;
  public calls = 0;
  public prompts: Array<string> = [];

  constructor(script: FakeLlmScript) {
    this.script = script;
  }

  async generate(request: { prompt: string; maxOutputTokens: number; signal?: AbortSignal }): Promise<LlmRawResponse> {
    this.calls += 1;
    this.prompts.push(request.prompt);
    if (this.script.fail === true) {
      throw new Error("fake provider failure");
    }
    if (this.script.hang === true) {
      await new Promise<never>(() => {});
    }
    const index = Math.min(this.calls - 1, this.script.responses.length - 1);
    const body = this.script.responses[index] ?? "";
    return { status: "ok", bodyText: body };
  }
}

export const VALID_FILESYSTEM_READ_JSON = JSON.stringify({
  plannerVersion: 1,
  family: "filesystem",
  operation: "read",
  resource: "/tmp/macky-m12-probe.txt",
});

export const VALID_SYSTEM_INFO_JSON = JSON.stringify({
  plannerVersion: 1,
  family: "system",
  operation: "info",
});
