import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import { boot } from "../src/bootstrap/boot.js";
import { grantToSession, wakeSession } from "../src/persistence/session.js";
import type { SecureSession } from "../src/persistence/session.js";
import { CONVERSATION_LIMITS } from "../src/conversation/limits.js";
import {
  createOrchestratorContext,
  handleUserMessage,
} from "../src/conversation/orchestrator.js";
import { MockConversationPlanner } from "../src/conversation/mock-conversation-planner.js";

function tmpDir(): string {
  return fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "macky-m6-")));
}

interface Rig {
  dir: string;
  work: string;
  session: SecureSession;
  cleanup: () => void;
}

function rigged(mode: "helpful" | "stubborn" = "helpful"): Rig & { ask: typeof ask } {
  const dir = tmpDir();
  const work = tmpDir();
  const booted = boot(dir);
  if (!booted.ok) throw new Error("boot failed");
  fs.writeFileSync(path.join(work, "a.txt"), "hello m6");
  grantToSession(booted.session, {
    grantId: "g-a",
    taskId: "task-TEST",
    capability: "filesystem.read",
    scope: work,
  });
  wakeSession(booted.session, { kind: "ui-action" });
  const ctx = createOrchestratorContext(booted.session, new MockConversationPlanner(mode));
  const ask = (msg: unknown, taskId = "task-TEST") => handleUserMessage(ctx, msg, { taskId });
  return { dir, work, session: booted.session, cleanup: () => { fs.rmSync(dir, { recursive: true, force: true }); fs.rmSync(work, { recursive: true, force: true }); }, ask };
}

describe("M6 conversation: happy path, bounds, ownership, errors", () => {
  it("read → tool → final response, all bounded", async () => {
    const rig = rigged();
    try {
      const r = await rig.ask(`read ${rig.work}/a.txt`);
      expect(r.status).toBe("responded");
      expect(r.iterations).toBe(1);
      expect(r.taskId).toBe("task-TEST");
    } finally {
      rig.cleanup();
    }
  });

  it("conversation holds user/tool/assistant messages with gapless seq", async () => {
    const rig = rigged();
    try {
      const ctx = createOrchestratorContext(rig.session, new MockConversationPlanner("helpful"));
      await handleUserMessage(ctx, `read ${rig.work}/a.txt`, { taskId: "task-TEST" });
      const msgs = ctx.conversation.messages;
      expect(msgs.map((m) => m.role)).toEqual(["user", "tool", "assistant"]);
      expect(msgs.map((m) => m.seq)).toEqual([1, 2, 3]);
    } finally {
      rig.cleanup();
    }
  });

  it("invalid user input refused without appending", async () => {
    const rig = rigged();
    try {
      const ctx = createOrchestratorContext(rig.session, new MockConversationPlanner("helpful"));
      for (const bad of [null, 42, {}, "", `x`.repeat(CONVERSATION_LIMITS.MAX_MESSAGE_CHARS + 1)]) {
        const r = await handleUserMessage(ctx, bad, { taskId: "task-TEST" });
        expect(r.code).toBe("refused-input");
      }
      expect(ctx.conversation.messages).toHaveLength(0);
    } finally {
      rig.cleanup();
    }
  });

  it("message-count and conversation-size caps fail closed", async () => {
    const rig = rigged();
    try {
      const ctx = createOrchestratorContext(rig.session, new MockConversationPlanner("helpful"));
      for (let i = 0; i < CONVERSATION_LIMITS.MAX_MESSAGES; i += 1) {
        ctx.conversation.messages.push({ v: 1, id: `m-${i}`, role: "user", content: "hi", seq: i + 1 });
      }
      const r = await handleUserMessage(ctx, "info", { taskId: "task-TEST" });
      expect(r.code).toBe("refused-conversation-full");
    } finally {
      rig.cleanup();
    }
  });

  it("trusted task ids: minted by default, unique, grant nothing alone", async () => {
    const rig = rigged();
    try {
      const ctx = createOrchestratorContext(rig.session, new MockConversationPlanner("helpful"));
      const a = await handleUserMessage(ctx, "info");
      expect(a.taskId).toMatch(/^[0-9a-f-]{36}$/);
      // Minted id has no grants: a proposal cannot authorize.
      expect(a.status).toBe("refused");
      const ctx2 = createOrchestratorContext(rig.session, new MockConversationPlanner("helpful"));
      const c = await handleUserMessage(ctx2, "info");
      expect(c.taskId).not.toBe(a.taskId);
      // Invalid supplied id refused.
      const d = await handleUserMessage(ctx2, "info", { taskId: "" });
      expect(d.code).toBe("refused-input");
    } finally {
      rig.cleanup();
    }
  });

  it("stubborn planner hits the hard loop limit and stops", async () => {
    const rig = rigged("stubborn");
    try {
      const r = await rig.ask(`read ${rig.work}/a.txt`);
      expect(r.status).toBe("stopped");
      expect(r.code).toBe("stopped-loop-limit");
      expect(r.iterations).toBe(CONVERSATION_LIMITS.MAX_TOOL_ITERATIONS);
      expect(CONVERSATION_LIMITS.MAX_TOOL_ITERATIONS).toBe(3);
    } finally {
      rig.cleanup();
    }
  });

  it("planner failure and garbage fail closed", async () => {
    const rig = rigged();
    try {
      const throwing = { propose: async () => { throw new Error("planner down"); } };
      const ctx = createOrchestratorContext(rig.session, throwing);
      expect((await handleUserMessage(ctx, "info", { taskId: "task-TEST" })).code).toBe("failed-planner");
      const ctx2 = createOrchestratorContext(rig.session, new MockConversationPlanner("garbage"));
      expect((await handleUserMessage(ctx2, "info", { taskId: "task-TEST" })).code).toBe("refused-proposal");
    } finally {
      rig.cleanup();
    }
  });

  it("oversized planner output refused", async () => {
    const rig = rigged();
    try {
      const huge = { propose: async () => "z".repeat(CONVERSATION_LIMITS.MAX_PLANNER_OUTPUT_CHARS + 1) };
      const ctx = createOrchestratorContext(rig.session, huge);
      expect((await handleUserMessage(ctx, "info", { taskId: "task-TEST" })).code).toBe("refused-oversized-output");
    } finally {
      rig.cleanup();
    }
  });

  it("oversized tool result truncates with marker, stays bounded", async () => {
    const rig = rigged();
    try {
      fs.writeFileSync(path.join(rig.work, "big.txt"), "q".repeat(CONVERSATION_LIMITS.MAX_TOOL_RESULT_CHARS + 500));
      // File exceeds fs read cap? 4.6KiB < 64KiB: readable, tool-truncated.
      const ctx = createOrchestratorContext(rig.session, new MockConversationPlanner("helpful"));
      const r = await handleUserMessage(ctx, `read ${rig.work}/big.txt`, { taskId: "task-TEST" });
      expect(r.status).toBe("responded");
      const tool = ctx.conversation.messages.find((m) => m.role === "tool");
      expect(tool).toBeDefined();
      expect(tool?.content.endsWith("[truncated: result exceeded bounded size]")).toBe(true);
      expect(tool ? tool.content.length : 0).toBeLessThanOrEqual(
        CONVERSATION_LIMITS.MAX_TOOL_RESULT_CHARS + "[truncated: result exceeded bounded size]".length,
      );
    } finally {
      rig.cleanup();
    }
  });
});

describe("M6 structural: conversation can never reach the OS", () => {
  it("import direction is conversation → planner-boundary only", () => {
    const dir = new URL("../src/conversation/", import.meta.url);
    const files = fs.readdirSync(dir).filter((f) => f.endsWith(".ts"));
    expect(files.length).toBeGreaterThan(0);
    for (const file of files) {
      const src = fs.readFileSync(new URL(file, dir), "utf8");
      for (const line of src.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed.startsWith("import ") || !trimmed.includes("from")) continue;
        const isTypeOnly = trimmed.startsWith("import type");
        const target = trimmed.split("from")[1] ?? "";
        // Value imports: local conversation modules, planner boundary/contract, stdlib crypto, zod.
        if (!isTypeOnly) {
          const ok =
            target.includes("./limits") || target.includes("./messages") ||
            target.includes("./mock-conversation-planner") || target.includes("./orchestrator") ||
            target.includes("../planner/") || target.includes("node:crypto") ||
            target.includes("zod");
          expect(ok, `${file}: ${trimmed}`).toBe(true);
        }
        // Nothing executable, ever — not even as types.
        for (const forbidden of ["../executor", "node:fs", "child_process", "node:net", "node:http", "eval("]) {
          expect(target.includes(forbidden), `${file}: ${trimmed}`).toBe(false);
        }
      }
      expect(src.includes("process.env")).toBe(false);
    }
  });
});
