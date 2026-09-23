/**
 * Trusted macOS launcher abstraction (M11 launch semantics). The ONLY
 * dynamic value reaching the OS is the registry-owned bundle path —
 * never planner argv, env, cwd, or URLs.
 *
 * Production path: direct spawn of the static trusted launcher
 * /usr/bin/open with argv [bundlePath], shell:false, minimal env.
 * `open <bundle>` asks LaunchServices to launch the app; no -a flag
 * (no app selection), no --args (no arguments), no URL/file operands.
 *
 * Authority boundary (documented): M11 controls the LAUNCHER process
 * (timeout kill, slot release). A launched GUI app persists under
 * macOS ownership — M11 cannot and does not terminate it. No PTY,
 * no stdin, no shell startup files.
 */
import { spawn as nodeSpawn, type ChildProcess } from "node:child_process";
import * as fs from "node:fs";
import { APP_LIMITS } from "./limits.js";

export const TRUSTED_LAUNCHER_PATH = "/usr/bin/open" as const;

export interface LaunchRequest {
  readonly bundlePath: string;
  readonly timeoutMs?: number;
}

export interface LaunchOutcome {
  readonly launched: boolean;
  readonly exitCode?: number;
  readonly signal?: string;
  readonly timedOut?: boolean;
  readonly durationMs: number;
  readonly reason?: string;
}

export interface AppLauncher {
  launch(request: LaunchRequest): Promise<LaunchOutcome>;
}

function childEnv(): Record<string, string> {
  return { LC_ALL: "C" };
}

/** Minimal child surface (Node's ChildProcess satisfies it). */
export interface LaunchedProcess {
  on(event: "error" | "exit" | "close", cb: (...args: Array<unknown>) => void): void;
  kill(signal?: string): boolean;
}

export type SpawnFn = (
  executable: string,
  argv: ReadonlyArray<string>,
  opts: { env: Record<string, string>; stdio: Array<string> },
) => LaunchedProcess;

const defaultSpawn: SpawnFn = (exe, argv, opts) =>
  nodeSpawn(exe, [...argv], {
    env: opts.env,
    stdio: opts.stdio as Array<"ignore" | "pipe" | "pipe">,
    shell: false,
    windowsHide: true,
  }) as unknown as LaunchedProcess;

export interface ProductionLauncherOptions {
  readonly spawnImpl?: SpawnFn;
}

export function createProductionLauncher(opts?: ProductionLauncherOptions): AppLauncher {
  const spawnImpl = opts?.spawnImpl ?? defaultSpawn;
  return {
    launch(request: LaunchRequest): Promise<LaunchOutcome> {
      const started = Date.now();
      const timeoutMs = request.timeoutMs ?? APP_LIMITS.LAUNCH_TIMEOUT_MS;
      let child: LaunchedProcess;
      try {
        fs.accessSync(TRUSTED_LAUNCHER_PATH, fs.constants.X_OK);
        const stat = fs.statSync(TRUSTED_LAUNCHER_PATH);
        if (!stat.isFile()) {
          return Promise.resolve({ launched: false, durationMs: 0, reason: "launcher unavailable" });
        }
        // Fixed argv: the registry bundle path only. No flags, no operands.
        child = spawnImpl(TRUSTED_LAUNCHER_PATH, [request.bundlePath], {
          env: childEnv(),
          stdio: ["ignore", "ignore", "ignore"],
        });
      } catch {
        return Promise.resolve({ launched: false, durationMs: Date.now() - started, reason: "launcher spawn failed" });
      }
      let timedOut = false;
      let settled = false;
      return new Promise<LaunchOutcome>((resolve) => {
        const finish = (outcome: LaunchOutcome): void => {
          if (settled) {
            return;
          }
          settled = true;
          resolve(outcome);
        };
        const timer = setTimeout(() => {
          timedOut = true;
          try {
            child.kill("SIGTERM");
          } catch {
            finish({ launched: false, timedOut: true, durationMs: Date.now() - started, reason: "launcher timeout" });
            return;
          }
          setTimeout(() => {
            try {
              child.kill("SIGKILL");
            } catch {
              // Already gone; exit/close below still settles.
            }
          }, 1_000);
        }, timeoutMs);
        child.on("error", () => {
          clearTimeout(timer);
          finish({ launched: false, durationMs: Date.now() - started, reason: "launcher error" });
        });
        child.on("exit", (code: unknown, signal: unknown) => {
          clearTimeout(timer);
          const ms = Date.now() - started;
          if (timedOut) {
            finish(
              typeof signal === "string"
                ? { launched: false, timedOut: true, signal, durationMs: ms, reason: "launcher timeout" }
                : { launched: false, timedOut: true, durationMs: ms, reason: "launcher timeout" },
            );
            return;
          }
          if (typeof code === "number" && code === 0) {
            finish({ launched: true, exitCode: 0, durationMs: ms });
            return;
          }
          if (typeof code === "number" && typeof signal === "string") {
            finish({ launched: false, exitCode: code, signal, durationMs: ms, reason: "launcher reported failure" });
            return;
          }
          if (typeof code === "number") {
            finish({ launched: false, exitCode: code, durationMs: ms, reason: "launcher reported failure" });
            return;
          }
          if (typeof signal === "string") {
            finish({ launched: false, signal, durationMs: ms, reason: "launcher reported failure" });
            return;
          }
          finish({ launched: false, durationMs: ms, reason: "launcher reported failure" });
        });
      });
    },
  };
}

/** Deterministic fake launcher for tests: records + scripted outcomes. */
export type FakeLauncherMode = "ok" | "failure" | "hang";

export interface FakeLauncher extends AppLauncher {
  readonly calls: Array<{ bundlePath: string }>;
  readonly signals: Array<string>;
}

export function createFakeLauncher(mode: FakeLauncherMode = "ok"): FakeLauncher {
  const calls: Array<{ bundlePath: string }> = [];
  const signals: Array<string> = [];
  return {
    calls,
    signals,
    launch(request: LaunchRequest): Promise<LaunchOutcome> {
      calls.push({ bundlePath: request.bundlePath });
      if (mode === "failure") {
        return Promise.resolve({ launched: false, exitCode: 1, durationMs: 0, reason: "fake failure" });
      }
      if (mode === "hang") {
        return new Promise<LaunchOutcome>(() => {});
      }
      return Promise.resolve({ launched: true, exitCode: 0, durationMs: 1 });
    },
  };
}
