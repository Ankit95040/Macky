/**
 * Trusted application-launch service (M11 flow). Strict proposal
 * validation → registry classification (Tier1 only; unknown ids die
 * here) → kill/sleep prechecks → single-flight slot → M2
 * authorize() (SOLE authority; unscoped app.launch against live task
 * grants) → boundary re-check → registry identity re-verification
 * (existence, containment, canonical form, Info.plist — fresh every
 * call) → trusted launcher with the registry bundle path → bounded
 * contract → metadata-only audit.
 *
 * The planner's appId never becomes a path: only a successful
 * registry lookup yields paths, and those are re-verified before
 * use. No execute(decision) bypass exists — authorization is
 * re-checked inside this call immediately before OS launch.
 */
import * as fs from "node:fs";
import { authorize } from "../kernel/authorize.js";
import { isEngaged } from "../kernel/kill-switch.js";
import { appendAuditEvent } from "../persistence/audit-store.js";
import {
  persistLogDelta,
  type DurableResult,
  type SecureSession,
} from "../persistence/session.js";
import { createProductionLauncher, type AppLauncher, type LaunchRequest } from "./launcher.js";
import { APP_LIMITS } from "./limits.js";
import { AppLaunchProposalSchema } from "./proposal.js";
import { AppLaunchResultSchema } from "./results.js";
import { lookupApp, type AppRegistration, type AppRegistry } from "./registry.js";

export interface AppTaskContext {
  readonly taskId: string;
}

export interface AppServiceOptions {
  readonly timeoutMs?: number;
}

let appInFlight = 0;

export function tryAcquireAppSlot(): boolean {
  if (appInFlight >= 1) {
    return false;
  }
  appInFlight += 1;
  return true;
}

export function releaseAppSlot(): void {
  appInFlight = Math.max(0, appInFlight - 1);
}

function appRefusal(
  session: SecureSession,
  reason: string,
  auditPersisted: boolean,
): DurableResult {
  return {
    outcome: { status: "refused", stage: "app", reason },
    auditPersisted,
    log: session.log,
  };
}

function persistOne(session: SecureSession, type: string, detail: string): boolean {
  const r = appendAuditEvent(session.sink, {
    type,
    detail,
    epoch: session.epoch,
    sleep: session.sleep,
  });
  if (!r.ok) {
    session.auditHealthy = false;
    return false;
  }
  return true;
}

export interface AppRouter {
  tryRoute(output: unknown, taskId: string): Promise<DurableResult> | undefined;
}

/** Claims ONLY app-launch outputs; all else falls through. */
export function createAppRouter(
  session: SecureSession,
  registry: AppRegistry,
  launcher?: AppLauncher,
  opts?: AppServiceOptions,
): AppRouter {
  return {
    tryRoute(output: unknown, taskId: string): Promise<DurableResult> | undefined {
      if (typeof output !== "object" || output === null) {
        return undefined;
      }
      if ((output as { operation?: unknown }).operation !== "app-launch") {
        return undefined;
      }
      return handleAppLaunch(session, { taskId }, registry, launcher ?? createProductionLauncher(), output, opts);
    },
  };
}

/**
 * Verify registry identity fresh: absolute canonical paths, both
 * exist, executable is a file inside the bundle (containment),
 * Info.plist present. Code-signing/publisher identity is NOT
 * verified — documented limitation, not a claim.
 */
export function verifyAppIdentity(entry: AppRegistration): { readonly ok: true; readonly bundleReal: string } | { readonly ok: false; readonly reason: string } {
  if (!entry.bundlePath.startsWith("/") || !entry.executablePath.startsWith("/")) {
    return { ok: false, reason: "registry paths must be absolute" };
  }
  let bundleReal: string;
  let exeReal: string;
  try {
    bundleReal = fs.realpathSync(entry.bundlePath);
    exeReal = fs.realpathSync(entry.executablePath);
  } catch {
    return { ok: false, reason: "application paths not resolvable" };
  }
  if (bundleReal !== entry.bundlePath || exeReal !== entry.executablePath) {
    return { ok: false, reason: "registry identity drifted" };
  }
  let exeStat: fs.Stats;
  let bundleStat: fs.Stats;
  try {
    exeStat = fs.statSync(exeReal);
    bundleStat = fs.statSync(bundleReal);
  } catch {
    return { ok: false, reason: "application not accessible" };
  }
  if (!bundleStat.isDirectory() || !exeStat.isFile()) {
    return { ok: false, reason: "application structure invalid" };
  }
  if (exeReal !== bundleReal && !exeReal.startsWith(`${bundleReal}/`)) {
    return { ok: false, reason: "executable escapes bundle" };
  }
  try {
    if (!fs.statSync(`${bundleReal}/Contents/Info.plist`).isFile()) {
      return { ok: false, reason: "bundle identity missing" };
    }
  } catch {
    return { ok: false, reason: "bundle identity missing" };
  }
  try {
    fs.accessSync(exeReal, fs.constants.X_OK);
  } catch {
    return { ok: false, reason: "executable not runnable" };
  }
  return { ok: true, bundleReal };
}

export async function handleAppLaunch(
  session: SecureSession,
  taskCtx: AppTaskContext,
  registry: AppRegistry,
  launcher: AppLauncher,
  output: unknown,
  opts?: AppServiceOptions,
): Promise<DurableResult> {
  if (!session.auditHealthy) {
    return appRefusal(session, "audit persistence unhealthy", false);
  }
  const parsed = AppLaunchProposalSchema.safeParse(output);
  if (!parsed.success) {
    const ok = persistOne(session, "request.validation-failed", "app proposal failed strict validation");
    return appRefusal(session, "app proposal failed strict validation", ok);
  }
  // Classification = registry lookup. Unknown ids (traversal strings,
  // paths, shell text, other capabilities) die here with no path ever
  // derived from planner input.
  const entry = lookupApp(registry, parsed.data.appId);
  if (entry === undefined) {
    const ok = persistOne(session, "request.validation-failed", "unknown application id");
    return appRefusal(session, "unknown application: default deny", ok);
  }
  if (isEngaged(session.killSwitch)) {
    const ok = persistOne(session, "execution.rejected", "app launch refused: kill switch engaged");
    return appRefusal(session, "kill switch engaged", ok);
  }
  if (session.sleep !== "AWAKE") {
    const ok = persistOne(session, "sleep.denied", "app launch refused while asleep");
    return appRefusal(session, "system is asleep", ok);
  }
  if (!tryAcquireAppSlot()) {
    const ok = persistOne(session, "execution.rejected", "app launch refused: another launch in flight");
    return appRefusal(session, "another launch is already running", ok);
  }
  try {
    // THE authorization decision — M2, sole authority. Tier1,
    // unscoped, live task grants; no resource.
    const before = session.log.events.length;
    const authorized = authorize(
      { capability: "app.launch", operation: "launch", taskId: taskCtx.taskId },
      { sleep: session.sleep, grants: session.grants, confirmations: session.confirmations, log: session.log },
    );
    session.log = authorized.log;
    const persistedAuth = persistLogDelta(session, before);
    if (authorized.decision.verdict !== "allow") {
      return appRefusal(session, `authorization did not allow (got ${authorized.decision.verdict})`, persistedAuth);
    }
    if (isEngaged(session.killSwitch) || session.sleep !== "AWAKE") {
      const ok = persistOne(session, "execution.rejected", "app launch stopped at launcher boundary");
      return appRefusal(session, "stopped at launcher boundary", ok);
    }
    const identity = verifyAppIdentity(entry);
    if (!identity.ok) {
      const ok = persistOne(session, "execution.rejected", `app identity refused: ${identity.reason}`);
      return appRefusal(session, `application identity refused: ${identity.reason}`, ok);
    }
    const startedOk = persistOne(session, "execution.started", `started app.launch id=${entry.id} tier=1`);
    if (!startedOk) {
      return appRefusal(session, "audit unhealthy: refused before launcher call", false);
    }
    const launchRequest: LaunchRequest =
      opts?.timeoutMs === undefined
        ? { bundlePath: identity.bundleReal }
        : { bundlePath: identity.bundleReal, timeoutMs: opts.timeoutMs };
    // Service-level timeout race: bounds ANY launcher implementation
    // (including fakes that never settle). The production launcher
    // enforces its own timeout independently.
    const launchTimeoutMs = opts?.timeoutMs ?? APP_LIMITS.LAUNCH_TIMEOUT_MS;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let outcome: Awaited<ReturnType<AppLauncher["launch"]>>;
    try {
      outcome = await Promise.race([
        launcher.launch(launchRequest),
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => reject(new Error("app launch timeout")), launchTimeoutMs);
        }),
      ]);
    } catch {
      persistOne(session, "command.timed-out", `app.launch timeout id=${entry.id}`);
      return {
        outcome: { status: "failed", stage: "adapter", reason: "launcher timeout" },
        auditPersisted: session.auditHealthy,
        log: session.log,
      };
    } finally {
      if (timer !== undefined) {
        clearTimeout(timer);
      }
    }
    if (!outcome.launched) {
      persistOne(
        session,
        outcome.timedOut === true ? "command.timed-out" : "execution.failed",
        `app.launch ${outcome.timedOut === true ? "timeout" : "failed"} id=${entry.id} ms=${outcome.durationMs}`,
      );
      return {
        outcome: { status: "failed", stage: "adapter", reason: outcome.timedOut === true ? "launcher timeout" : (outcome.reason ?? "launcher failure") },
        auditPersisted: session.auditHealthy,
        log: session.log,
      };
    }
    const contract = AppLaunchResultSchema.safeParse({
      v: 1, operation: "app-launch", appId: entry.id, status: "launched", truncated: false,
    });
    if (!contract.success) {
      persistOne(session, "execution.failed", "app.launch result contract failed");
      return {
        outcome: { status: "failed", stage: "adapter", reason: "result contract failed" },
        auditPersisted: session.auditHealthy,
        log: session.log,
      };
    }
    persistOne(session, "execution.completed", `app.launch ok id=${entry.id} ms=${outcome.durationMs}`);
    return {
      outcome: { status: "completed", operation: "app.launch:launch", result: contract.data, redacted: false },
      auditPersisted: session.auditHealthy,
      log: session.log,
    };
  } finally {
    releaseAppSlot();
  }
}
