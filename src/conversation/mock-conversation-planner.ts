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
  /** Trusted app context: which workspace the user means (not authority). */
  readonly workspaceId?: string;
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
    // M7 workspace commands (relative paths + present workspaceId).
    // Output is an M7 workspace proposal — still untrusted, still
    // validated + bound + translated downstream.
    const workspace = this.workspaceCommand(input);
    if (workspace !== undefined) {
      return workspace;
    }
    return this.commandOrFallback(input, this.mode === "task-grab" ? "task-STOLEN" : input.taskId);
  }

  /**
   * M7 workspace micro-language. Only when trusted workspace context
   * is present, and only for workspace-RELATIVE targets. Absolute
   * targets fall through to the legacy M5 absolute handling below.
   * Output shape {v, workspaceId, op, …} is validated, bound, and
   * translated downstream — untrusted like everything else.
   */
  private workspaceCommand(input: ConversationPlannerInput): unknown {
    const workspaceId = input.workspaceId;
    if (workspaceId === undefined) {
      return undefined;
    }
    const text = input.userText.trim();
    // Contract version literal (not imported: conversation must not
    // import the workspace layer — frozen M6 import boundary).
    const base = { v: 1, workspaceId };
    const read = /^(read|list)\s+(\S+)\s*$/i.exec(text);
    if (read !== null) {
      const op = read[1];
      const target = read[2];
      if (op === undefined || target === undefined || target.startsWith("/")) {
        return undefined;
      }
      return { ...base, op: op.toLowerCase() === "read" ? "file-read" : "dir-list", path: target };
    }
    const find = /^find\s+(\S+)(?:\s+(\S+))?\s*$/i.exec(text);
    if (find !== null) {
      const pattern = find[1];
      const rel = find[2] ?? ".";
      if (pattern === undefined || rel.startsWith("/")) {
        return undefined;
      }
      return { ...base, op: "file-find", pattern, path: rel };
    }
    const searchQuoted = /^search\s+"([^"]+)"(?:\s+(\S+))?\s*$/i.exec(text);
    const searchBare = searchQuoted === null ? /^search\s+(\S+)(?:\s+(\S+))?\s*$/i.exec(text) : null;
    const search = searchQuoted ?? searchBare;
    if (search !== null) {
      const query = search[1];
      const rel = search[2] ?? ".";
      if (query === undefined || rel.startsWith("/")) {
        return undefined;
      }
      return { ...base, op: "content-search", query, path: rel };
    }
    const tree = /^tree(?:\s+(\S+))?\s*$/i.exec(text);
    if (tree !== null) {
      const rel = tree[1] ?? ".";
      if (rel.startsWith("/")) {
        return undefined;
      }
      return { ...base, op: "tree", path: rel };
    }
    const git = /^git\s+(status|log|diff)(?:\s+(\S+))?\s*$/i.exec(text);
    if (git !== null) {
      const op = git[1];
      const rel = git[2] ?? ".";
      if (op === undefined || rel.startsWith("/")) {
        return undefined;
      }
      return { ...base, op: `git-${op.toLowerCase()}`, path: rel };
    }
    return undefined;
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
