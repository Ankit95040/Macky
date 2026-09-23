/**
 * M17 command implementations (trusted presentation + sequencing).
 * Each command boots a fresh one-shot session, funnels through M16
 * (status/audit) or M14+M15 (talk), renders bounded text, and exits.
 * No authority is created here: grants/confirmations can only arrive
 * pre-existing in tests via trusted setup, never via argv.
 *
 * - status/audit read durable state through the M16 funnel only.
 * - talk refuses while asleep (fresh boots sleep; no implicit wake),
 *   needs an injected planner (no default provider construction —
 *   raw LLM providers stay out of this layer), and voice paths from
 *   trusted MACKY_* runtime env (never argv), else refuses.
 */
import {
  createOrchestratorContext,
  type OrchestratorContext,
} from "../conversation/orchestrator.js";
import type { ConversationPlanner } from "../conversation/mock-conversation-planner.js";
import { boot } from "../bootstrap/boot.js";
import { getStatus, readAuditTailOp } from "../operator/service.js";
import { handleVoiceTurn } from "../voice/turn.js";
import type { VoiceSessionConfig, VoiceSessionOptions } from "../voice/session.js";
import type { ParsedArgs } from "./args.js";

export interface CommandResult {
  readonly exitCode: 0 | 1 | 2;
  readonly output: string;
}

export interface TalkDeps {
  readonly planner?: ConversationPlanner;
  readonly helperPath?: string;
  readonly binaryPath?: string;
  readonly modelPath?: string;
  readonly modelSha256?: string;
  readonly spawnCaptureImpl?: VoiceSessionOptions["spawnCaptureImpl"];
  readonly spawnSttImpl?: VoiceSessionOptions["spawnSttImpl"];
  readonly taskId?: string;
}

function boundOutput(text: string): string {
  const points = Array.from(text);
  if (points.length <= 8192) {
    return text;
  }
  return `${points.slice(0, 8192).join("")}[truncated]`;
}

function renderStatus(status: ReturnType<typeof getStatus>): string {
  return boundOutput(
    [
      `epoch: ${status.epoch}`,
      `sleep: ${status.sleep}`,
      `kill: ${status.killEngaged ? "engaged" : "clear"}`,
      `grants: ${status.grantCount}`,
      `confirmations: ${status.confirmationCount}`,
      `audit: ${status.auditHealthy ? "healthy" : "degraded"}`,
    ].join("\n"),
  );
}

export function runStatus(stateDir?: string): CommandResult {
  const booted = boot(stateDir);
  if (!booted.ok) {
    return { exitCode: 1, output: "status unavailable: boot refused" };
  }
  return { exitCode: 0, output: renderStatus(getStatus(booted.session)) };
}

export function runAudit(stateDir: string | undefined, limit: number): CommandResult {
  const booted = boot(stateDir);
  if (!booted.ok) {
    return { exitCode: 1, output: "audit unavailable: boot refused" };
  }
  const tail = readAuditTailOp(booted.session, { limit });
  if (!tail.ok) {
    return { exitCode: 1, output: `audit unavailable: ${tail.reason}`.slice(0, 256) };
  }
  return { exitCode: 0, output: boundOutput(tail.events.map((e) => JSON.stringify(e)).join("\n")) };
}

function voicePaths(deps?: TalkDeps): VoiceSessionConfigPaths | undefined {
  const helperPath = deps?.helperPath ?? process.env["MACKY_VOICE_HELPER"];
  const binaryPath = deps?.binaryPath ?? process.env["MACKY_STT_ADAPTER"];
  const modelPath = deps?.modelPath ?? process.env["MACKY_STT_MODEL"];
  const modelSha256 = deps?.modelSha256 ?? process.env["MACKY_STT_MODEL_SHA"];
  if (
    typeof helperPath !== "string" || helperPath.length === 0 ||
    typeof binaryPath !== "string" || binaryPath.length === 0 ||
    typeof modelPath !== "string" || modelPath.length === 0 ||
    typeof modelSha256 !== "string" || modelSha256.length === 0
  ) {
    return undefined;
  }
  return { helperPath, binaryPath, modelPath, modelSha256 };
}

interface VoiceSessionConfigPaths {
  readonly helperPath: string;
  readonly binaryPath: string;
  readonly modelPath: string;
  readonly modelSha256: string;
}

export function runTalk(stateDir?: string, deps?: TalkDeps): Promise<CommandResult> {
  const planner = deps?.planner;
  if (planner === undefined) {
    return Promise.resolve({ exitCode: 1, output: "talk unavailable: no planner configured" });
  }
  const paths = voicePaths(deps);
  if (paths === undefined) {
    return Promise.resolve({ exitCode: 1, output: "talk unavailable: voice binaries not configured" });
  }
  return (async (): Promise<CommandResult> => {
    const booted = boot(stateDir);
    if (!booted.ok) {
      return { exitCode: 1, output: "talk unavailable: boot refused" };
    }
    const session = booted.session;
    const gate = (): { asleep: boolean; killEngaged: boolean } => ({
      asleep: session.sleep !== "AWAKE",
      killEngaged: session.killSwitch.engaged,
    });
    const voiceConfig: VoiceSessionConfig = { ...paths, gate };
    const orchCtx: OrchestratorContext = createOrchestratorContext(session, planner);
    const turned = await handleVoiceTurn(
      orchCtx,
      voiceConfig,
      {
        ...(deps?.taskId !== undefined ? { taskId: deps.taskId } : {}),
        ...(deps?.spawnCaptureImpl !== undefined ? { spawnCaptureImpl: deps.spawnCaptureImpl } : {}),
        ...(deps?.spawnSttImpl !== undefined ? { spawnSttImpl: deps.spawnSttImpl } : {}),
      },
    );
    if (turned.assistant === undefined) {
      return { exitCode: 1, output: `talk refused (${turned.voice.status})` };
    }
    return { exitCode: 0, output: boundOutput(turned.assistant.text) };
  })();
}

export function runCommand(parsed: ParsedArgs, stateDir?: string, deps?: TalkDeps): Promise<CommandResult> | CommandResult {
  switch (parsed.kind) {
    case "status":
      return runStatus(stateDir);
    case "audit":
      return runAudit(stateDir, parsed.limit);
    case "talk":
      return runTalk(stateDir, deps);
  }
}
