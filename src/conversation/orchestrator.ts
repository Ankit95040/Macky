/**
 * Deterministic conversation orchestrator (M6 sections 4/7/8/13).
 * Orchestration ONLY — never a security layer, never an executor.
 *
 * Per user message: validate → append → mint a trusted taskId →
 * bounded planner/tool loop where EVERY action crosses M5
 * handleProposal() (hence M2→M3→M4 with sleep/kill/epoch re-checked
 * each iteration) → bounded assistant/tool messages → result.
 *
 * The orchestrator never executes OS operations, never interprets
 * planner/tool text as authorization, never persists conversation
 * into the security audit, and never exposes kernel internals in
 * user-facing text. Dependency direction (enforced by test):
 * conversation → planner-boundary → M4/M2/M3. Never conversation → OS.
 */
import { randomUUID } from "node:crypto";
import { z } from "zod";
import { handleProposal } from "../planner/boundary.js";
import type { SecureSession } from "../persistence/session.js";
import { CONVERSATION_LIMITS, TOOL_TRUNCATION_MARKER } from "./limits.js";
import {
  conversationChars,
  nextSeq,
  type ConversationMessage,
  type ConversationState,
} from "./messages.js";
import type {
  ConversationPlanner,
  PlannerHistoryItem,
} from "./mock-conversation-planner.js";

export interface OrchestratorContext {
  readonly session: SecureSession;
  readonly conversation: ConversationState;
  readonly planner: ConversationPlanner;
}

export function createOrchestratorContext(
  session: SecureSession,
  planner: ConversationPlanner,
): OrchestratorContext {
  return { session, conversation: { messages: [] }, planner };
}

export type AssistantCode =
  | "responded"
  | "refused-input"
  | "refused-conversation-full"
  | "refused-proposal"
  | "refused-authorization"
  | "refused-sleep"
  | "refused-kill"
  | "refused-epoch"
  | "refused-audit"
  | "refused-oversized-output"
  | "failed-planner"
  | "failed-execution"
  | "stopped-loop-limit";

export interface AssistantResult {
  readonly status: "responded" | "refused" | "failed" | "stopped";
  readonly code: AssistantCode;
  /** Bounded user-facing text. Generic on refusal — no kernel internals. */
  readonly text: string;
  readonly iterations: number;
  readonly taskId: string | undefined;
}

const FinalResponseSchema = z
  .object({ type: z.literal("final"), text: z.string().max(CONVERSATION_LIMITS.MAX_MESSAGE_CHARS) })
  .strict();

function appendMessage(
  ctx: OrchestratorContext,
  role: ConversationMessage["role"],
  content: string,
): boolean {
  if (ctx.conversation.messages.length >= CONVERSATION_LIMITS.MAX_MESSAGES) {
    return false;
  }
  if (
    conversationChars(ctx.conversation) + content.length >
    CONVERSATION_LIMITS.MAX_CONVERSATION_CHARS
  ) {
    return false;
  }
  ctx.conversation.messages.push({
    v: 1,
    id: randomUUID(),
    role,
    content,
    seq: nextSeq(ctx.conversation),
  });
  return true;
}

function assistantText(code: AssistantCode): string {
  switch (code) {
    case "responded":
      return "done.";
    case "stopped-loop-limit":
      return "Stopped after the maximum number of steps.";
    default:
      return "I can't do that.";
  }
}

function toAssistant(
  code: AssistantCode,
  iterations: number,
  taskId: string | undefined,
  text?: string,
): AssistantResult {
  const status =
    code === "responded"
      ? "responded"
      : code === "stopped-loop-limit"
        ? "stopped"
        : code === "failed-planner" || code === "failed-execution"
          ? "failed"
          : "refused";
  const bounded = (text ?? assistantText(code)).slice(0, CONVERSATION_LIMITS.MAX_MESSAGE_CHARS);
  return { status, code, text: bounded, iterations, taskId };
}

function stageToCode(stage: string): AssistantCode {
  switch (stage) {
    case "sleep":
      return "refused-sleep";
    case "kill-switch":
      return "refused-kill";
    case "epoch":
    case "envelope":
      return "refused-epoch";
    case "audit":
      return "refused-audit";
    case "proposal":
      return "refused-proposal";
    default:
      return "refused-authorization";
  }
}

function toolTextFor(result: unknown): string {
  let text: string;
  try {
    text = typeof result === "string" ? result : JSON.stringify(result);
  } catch {
    text = "[unrepresentable result]";
  }
  if (text.length > CONVERSATION_LIMITS.MAX_TOOL_RESULT_CHARS) {
    return `${text.slice(0, CONVERSATION_LIMITS.MAX_TOOL_RESULT_CHARS)}${TOOL_TRUNCATION_MARKER}`;
  }
  return text;
}

/**
 * Handle one user message. Pure orchestration around the trusted path;
 * the only side effects reachable are the M5→M2→M3→M4 chain's own.
 *
 * The trusted task id is minted here by default. A trusted caller may
 * supply one (continuity); it is validated but NEVER taken from
 * planner output.
 */
export async function handleUserMessage(
  ctx: OrchestratorContext,
  rawMessage: unknown,
  opts?: { taskId?: string },
): Promise<AssistantResult> {
  if (typeof rawMessage !== "string" || rawMessage.length === 0) {
    return toAssistant("refused-input", 0, undefined);
  }
  if (rawMessage.length > CONVERSATION_LIMITS.MAX_MESSAGE_CHARS) {
    return toAssistant("refused-input", 0, undefined);
  }
  // Trusted task ownership (§5): minted here via stdlib crypto, never
  // by the planner. The M5 envelope uses THIS id; planner claims must
  // match it or die at the boundary.
  const supplied = opts?.taskId;
  if (supplied !== undefined && (typeof supplied !== "string" || supplied.length === 0 || supplied.length > 128)) {
    return toAssistant("refused-input", 0, undefined);
  }
  const taskId = supplied ?? randomUUID();
  if (!appendMessage(ctx, "user", rawMessage)) {
    return toAssistant("refused-conversation-full", 0, taskId);
  }

  for (let iteration = 0; iteration < CONVERSATION_LIMITS.MAX_TOOL_ITERATIONS; iteration += 1) {
    const history: Array<PlannerHistoryItem> = ctx.conversation.messages
      .slice(-CONVERSATION_LIMITS.HISTORY_TO_PLANNER)
      .map((m) => ({ role: m.role, content: m.content }));
    let output: unknown;
    try {
      output = await ctx.planner.propose({ taskId, userText: rawMessage, history });
    } catch {
      return toAssistant("failed-planner", iteration, taskId);
    }
    let outputSize = 0;
    try {
      outputSize = JSON.stringify(output)?.length ?? 0;
    } catch {
      return toAssistant("refused-proposal", iteration, taskId);
    }
    if (outputSize > CONVERSATION_LIMITS.MAX_PLANNER_OUTPUT_CHARS) {
      return toAssistant("refused-oversized-output", iteration, taskId);
    }
    const final = FinalResponseSchema.safeParse(output);
    if (final.success) {
      if (!appendMessage(ctx, "assistant", final.data.text)) {
        return toAssistant("refused-conversation-full", iteration, taskId);
      }
      return toAssistant("responded", iteration, taskId, final.data.text);
    }
    const handled = handleProposal(ctx.session, { epoch: ctx.session.epoch, taskId, output });
    if (handled.outcome.status === "completed") {
      if (!appendMessage(ctx, "tool", toolTextFor(handled.outcome.result))) {
        return toAssistant("refused-conversation-full", iteration + 1, taskId);
      }
      continue;
    }
    if (handled.outcome.status === "failed") {
      return toAssistant("failed-execution", iteration, taskId);
    }
    return toAssistant(stageToCode(handled.outcome.stage), iteration, taskId);
  }
  appendMessage(ctx, "assistant", assistantText("stopped-loop-limit"));
  return toAssistant("stopped-loop-limit", CONVERSATION_LIMITS.MAX_TOOL_ITERATIONS, taskId);
}
