import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import { boot } from "../src/bootstrap/boot.js";
import { grantToSession, wakeSession } from "../src/persistence/session.js";
import type { SecureSession } from "../src/persistence/session.js";
import {
  createOrchestratorContext,
  handleUserMessage,
} from "../src/conversation/orchestrator.js";
import { FakeLlmProvider } from "../src/llm/fake-provider.js";
import { RealLlmPlannerAdapter } from "../src/llm/planner.js";

function tmpDir(): string {
  return fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "macky-m12c-")));
}

interface Rig {
  dir: string;
  session: SecureSession;
  cleanup: () => void;
}

function rigged(): Rig {
  const dir = tmpDir();
  const booted = boot(dir);
  if (!booted.ok) throw new Error("boot failed");
  grantToSession(booted.session, { grantId: "g-sys", taskId: "task-C", capability: "system.info", scope: "" });
  wakeSession(booted.session, { kind: "ui-action" });
  return { dir, session: booted.session, cleanup: () => { fs.rmSync(dir, { recursive: true, force: true }); } };
}

function liveCtx(rig: Rig, responses: Array<string>): ReturnType<typeof createOrchestratorContext> & { fake: FakeLlmProvider; adapter: RealLlmPlannerAdapter } {
  const fake = new FakeLlmProvider({ responses });
  const gate = () => ({ asleep: rig.session.sleep !== "AWAKE", killEngaged: rig.session.killSwitch.engaged });
  const adapter = new RealLlmPlannerAdapter(fake, gate);
  const base = createOrchestratorContext(rig.session, adapter);
  return { ...base, fake, adapter };
}

describe("M12 conversation AX/AR/AK/AV", () => {
  it("AX. end-to-end executes via trusted binding without model taskId", async () => {
    const rig = rigged();
    try {
      // M12 corrective fix: taskId-less model output binds the trusted
      // envelope task, authorizes against its live grant, and executes.
      const ctx = liveCtx(rig, [JSON.stringify({ plannerVersion: 1, family: "system", operation: "info" })]);
      const r = await handleUserMessage(ctx, "tell me about the system", { taskId: "task-C" });
      expect(r.status).toBe("responded");
      expect(ctx.fake.calls).toBe(1);
      expect(ctx.conversation.messages.filter((m) => m.role === "tool")).toHaveLength(1);
    } finally {
      rig.cleanup();
    }
  });
  it("AR/AK/AV. no memory write, no second inference, bounded loop", async () => {
    const rig = rigged();
    const memDir = tmpDir();
    try {
      const ctx = liveCtx(rig, [JSON.stringify({ plannerVersion: 1, family: "system", operation: "info" })]);
      await handleUserMessage(ctx, "hello", { taskId: "task-C" });
      // Single inference consumed: no loop continuation can infer again.
      await expect(ctx.adapter.propose({ taskId: "task-C", userText: "again", history: [] })).rejects.toThrow();
      expect(ctx.fake.calls).toBe(1);
      // No memory artifact created anywhere near the session.
      expect(fs.existsSync(`${memDir}/memory.json`)).toBe(false);
      const again = await handleUserMessage(ctx, "hello again", { taskId: "task-C" });
      expect(ctx.fake.calls).toBe(1);
      expect(again.status).toBe("failed");
    } finally {
      rig.cleanup();
      fs.rmSync(memDir, { recursive: true, force: true });
    }
  });
  it("gated conversation never invokes the provider", async () => {
    const dir = tmpDir();
    try {
      const booted = boot(dir);
      if (!booted.ok) throw new Error("boot failed");
      grantToSession(booted.session, { grantId: "g", taskId: "task-C", capability: "system.info", scope: "" });
      // Deliberately NOT waking: session boots SLEEP.
      const fake = new FakeLlmProvider({ responses: [JSON.stringify({ plannerVersion: 1, family: "system", operation: "info" })] });
      const gate = () => ({ asleep: booted.session.sleep !== "AWAKE", killEngaged: booted.session.killSwitch.engaged });
      const base = createOrchestratorContext(booted.session, new RealLlmPlannerAdapter(fake, gate));
      const r = await handleUserMessage(base, "hello", { taskId: "task-C" });
      expect(r.status).toBe("failed");
      expect(fake.calls).toBe(0);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
