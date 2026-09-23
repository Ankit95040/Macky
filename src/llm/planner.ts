/**
 * Real LLM planner adapter (M12 conversation integration). Implements
 * the existing ConversationPlanner interface so it replaces the mock
 * with zero orchestrator/kernel changes — and zero new authority:
 * output is unknown, always M5-bound downstream.
 *
 * Exactly ONE inference per instance (a second propose() throws):
 * one user message → one inference → one proposal → at most one tool
 * op. No retries, no loop, no self-correction. Post-tool `final`
 * responses are synthesized locally without inference.
 *
 * The adapter holds no session, sink, grants, or keys — only a
 * sleep/kill gate closure (refuses BEFORE any provider call), the
 * provider, and an optional audit-metadata callback (bounded,
 * secret-free; the app persists it).
 */
import { LLM_LIMITS } from "./limits.js";
import type { LlmProvider } from "./provider.js";
import { hasDuplicateTopLevelKeys, parseLlmResponse } from "./response.js";
import { LlmPlannerError } from "./results.js";
import type {
  ConversationPlanner,
  ConversationPlannerInput,
} from "../conversation/mock-conversation-planner.js";

export interface LlmGateState {
  readonly asleep: boolean;
  readonly killEngaged: boolean;
}

export interface LlmAuditMeta {
  readonly op: "llm.infer";
  readonly status: "ok" | "error" | "refused";
  readonly code?: string;
  readonly bytes: number;
  readonly durationMs: number;
}

export interface RealLlmPlannerOptions {
  readonly timeoutMs?: number;
  readonly onEvent?: (meta: LlmAuditMeta) => void;
}

let llmInFlight = 0;

export function tryAcquireLlmSlot(): boolean {
  if (llmInFlight >= 1) {
    return false;
  }
  llmInFlight += 1;
  return true;
}

export function releaseLlmSlot(): void {
  llmInFlight = Math.max(0, llmInFlight - 1);
}

/**
 * Build the bounded prompt from untrusted conversation text. Contains
 * ONLY user text + recent history — never taskId, grants, epoch,
 * sleep/kill, secrets, paths registries, or decisions. Oldest history
 * drops first when the cap binds (documented context window).
 */
export function buildLlmPrompt(
  userText: string,
  history: ReadonlyArray<{ role: string; content: string }>,
): string {
  const lines: Array<string> = [];
  const recent = history.slice(-LLM_LIMITS.MAX_CONTEXT_MESSAGES);
  for (const item of recent) {
    const clipped = Array.from(item.content).slice(0, LLM_LIMITS.MAX_CONTEXT_MESSAGE_CHARS).join("");
    lines.push(`${item.role}: ${clipped}`);
  }
  lines.push(`user: ${userText}`);
  let prompt = lines.join("\n");
  // Drop oldest history lines until the prompt fits (user text kept whole).
  while (Array.from(prompt).length > LLM_LIMITS.MAX_PROMPT_CHARS && lines.length > 1) {
    lines.shift();
    prompt = lines.join("\n");
  }
  return prompt;
}

export class RealLlmPlannerAdapter implements ConversationPlanner {
  private readonly provider: LlmProvider;
  private readonly gate: () => LlmGateState;
  private readonly timeoutMs: number;
  private readonly onEvent: ((meta: LlmAuditMeta) => void) | undefined;
  private inferenceUsed = false;

  constructor(provider: LlmProvider, gate: () => LlmGateState, opts?: RealLlmPlannerOptions) {
    this.provider = provider;
    this.gate = gate;
    this.timeoutMs = opts?.timeoutMs ?? LLM_LIMITS.REQUEST_TIMEOUT_MS;
    this.onEvent = opts?.onEvent;
  }

  async propose(input: ConversationPlannerInput): Promise<unknown> {
    const state = this.gate();
    if (state.asleep || state.killEngaged) {
      throw new LlmPlannerError("session-not-ready", "planner gated: session not ready");
    }
    const last = input.history[input.history.length - 1];
    if (last !== undefined && last.role === "tool") {
      return { type: "final", text: "done." };
    }
    if (this.inferenceUsed) {
      throw new LlmPlannerError("session-not-ready", "single inference per adapter instance");
    }
    if (Array.from(input.userText).length > LLM_LIMITS.MAX_USER_TEXT_CHARS) {
      throw new LlmPlannerError("planner-input-too-large", "user text exceeds bound");
    }
    if (!tryAcquireLlmSlot()) {
      throw new LlmPlannerError("slot-busy", "another inference is active");
    }
    const started = Date.now();
    const emit = (status: LlmAuditMeta["status"], code: string | undefined, bytes: number): void => {
      try {
        if (code === undefined) {
          this.onEvent?.({ op: "llm.infer", status, bytes, durationMs: Date.now() - started });
        } else {
          this.onEvent?.({ op: "llm.infer", status, code, bytes, durationMs: Date.now() - started });
        }
      } catch {
        // Audit callbacks must never break planning.
      }
    };
    try {
      const prompt = buildLlmPrompt(input.userText, input.history);
      if (Array.from(prompt).length > LLM_LIMITS.MAX_PROMPT_CHARS) {
        throw new LlmPlannerError("planner-input-too-large", "prompt exceeds bound");
      }
      const controller = new AbortController();
      let timer: ReturnType<typeof setTimeout> | undefined;
      try {
        const raced = await Promise.race([
          this.provider.generate({ prompt, maxOutputTokens: LLM_LIMITS.MAX_OUTPUT_TOKENS, signal: controller.signal }),
          new Promise<never>((_, reject) => {
            timer = setTimeout(() => {
              try {
                controller.abort();
              } catch {
                // Best effort.
              }
              reject(new LlmPlannerError("provider-timeout", "provider timeout"));
            }, this.timeoutMs);
          }),
        ]);
        clearTimeout(timer);
        this.inferenceUsed = true;
        if (raced.status !== "ok") {
          const code = raced.code === "unavailable" ? "provider-unavailable" : "provider-network-error";
          emit("error", code, 0);
          throw new LlmPlannerError(code, `provider ${raced.code}`);
        }
        const parsed = parseLlmResponse(raced.bodyText);
        if (!parsed.ok) {
          const code = parsed.reason.includes("size limit") ? "provider-response-too-large" : "provider-invalid-response";
          emit("error", code, Buffer.byteLength(raced.bodyText, "utf8"));
          throw new LlmPlannerError(code, parsed.reason);
        }
        emit("ok", undefined, Buffer.byteLength(raced.bodyText, "utf8"));
        return parsed.value;
      } finally {
        if (timer !== undefined) {
          clearTimeout(timer);
        }
      }
    } catch (error) {
      if (error instanceof LlmPlannerError) {
        if (error.code !== "provider-timeout" && error.code !== "provider-invalid-response" && error.code !== "provider-response-too-large") {
          emit("error", error.code, 0);
        }
        throw error;
      }
      emit("error", "provider-network-error", 0);
      throw new LlmPlannerError("provider-network-error", "provider failure");
    } finally {
      releaseLlmSlot();
    }
  }
}

export { hasDuplicateTopLevelKeys };
