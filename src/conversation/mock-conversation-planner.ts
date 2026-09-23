/**
 * Deterministic mock conversational planner (M6 sections 7/11).
 * Test-only NLU stand-in: parses a tiny documented command language
 * (`info`, `read <abs>`, `list <abs>`, `git status|log|diff <abs>`)
 * from the latest user text. Everything else yields non-proposal data
 * that the M5 boundary rejects. A `final` response is returned only
 * when the last history message is a tool result.
 *
 * UNTRUSTED like any planner: output always crosses M5 validation.
 * Imports NOTHING executable — data in, data out. Malicious modes
 * (`loop-grab`, `task-grab`, `garbage`) exercise orchestrator armor.
 */
import { PLANNER_CONTRACT_VERSION } from "../planner/proposal.js";

export interface PlannerHistoryItem {
  readonly role: "user" | "assistant" | "tool";
  readonly content: string;
}

export interface ConversationPlannerInput {
  readonly taskId: string;
  readonly userText: string;
  readonly history: ReadonlyArray<PlannerHistoryItem>;
}

export interface ConversationPlanner {
  propose(input: ConversationPlannerInput): Promise<unknown>;
}

export type MockConversationMode = "helpful" | "stubborn" | "loop-grab" | "task-grab" | "garbage";

export class MockConversationPlanner implements ConversationPlanner {
  private readonly mode: MockConversationMode;

  constructor(mode: MockConversationMode = "helpful") {
    this.mode = mode;
  }

  async propose(input: ConversationPlannerInput): Promise<unknown> {
    if (this.mode === "garbage") {
      return { nonsense: [1, 2, 3] };
    }
    if (this.mode === "loop-grab") {
      return { maxIterations: 99, loopLimit: 1_000_000, family: "filesystem", operation: "read" };
    }
    const last = input.history[input.history.length - 1];
    if (this.mode === "stubborn") {
      return this.commandOrFallback(input, input.taskId);
    }
    if (last !== undefined && last.role === "tool" && this.mode === "helpful") {
      return { type: "final", text: "done." };
    }
    return this.commandOrFallback(input, this.mode === "task-grab" ? "task-STOLEN" : input.taskId);
  }

  private commandOrFallback(
    input: ConversationPlannerInput,
    taskId: string,
  ): unknown {
    const text = input.userText.trim();
    const base = { plannerVersion: PLANNER_CONTRACT_VERSION, taskId };
    if (/^info$/i.test(text)) {
      return { ...base, family: "system", operation: "info", rationale: "mock" };
    }
    const read = /^(read|list)\s+(\S+)\s*$/i.exec(text);
    if (read !== null) {
      const op = read[1];
      const target = read[2];
      if (op !== undefined && target !== undefined) {
        return { ...base, family: "filesystem", operation: op.toLowerCase(), resource: target, rationale: "mock" };
      }
      return { note: "no actionable command" };
    }
    const git = /^git\s+(status|log|diff)\s+(\S+)\s*$/i.exec(text);
    if (git !== null) {
      const op = git[1];
      const target = git[2];
      if (op !== undefined && target !== undefined) {
        return { ...base, family: "git", operation: op.toLowerCase(), resource: target, rationale: "mock" };
      }
      return { note: "no actionable command" };
    }
    return { note: "no actionable command" };
  }
}
