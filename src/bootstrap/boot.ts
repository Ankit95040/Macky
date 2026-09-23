/**
 * Deterministic safe boot (M4 sections 2/12/13/14).
 *
 * Every boot: resolve trusted config → ensure private dir → load
 * security state (missing = first boot at epoch 1; invalid = fail
 * closed, NO session) → epoch+1 → persist → verify audit chain
 * (corrupt = fail closed, NO session; explicit repair path exists but
 * is never automatic) → fresh session that ALWAYS starts SLEEPING
 * with a fresh disengaged kill switch, zero grants, zero
 * confirmations.
 *
 * Kill rationale (documented, §13): engagement keys are process-local
 * by design, so an engaged switch cannot survive restart usefully —
 * persisting it without a trusted disengage path would brick. Safety
 * is instead carried by SLEEP + the new epoch: a restarted system can
 * execute nothing until a trusted local wake AND fresh trusted grants,
 * which is strictly more restricted than any pre-restart state.
 */
import { ensureStateDir, resolveConfig } from "./config.js";
import {
  createSession,
  type SecureSession,
} from "../persistence/session.js";
import {
  appendAuditEvent,
  openAuditSink,
} from "../persistence/audit-store.js";
import {
  defaultSecurityState,
  loadStateFile,
  nextEpochState,
  saveStateFile,
} from "../persistence/security-state.js";

export type BootResult =
  | { readonly ok: true; readonly session: SecureSession }
  | { readonly ok: false; readonly reason: string };

export function boot(stateDirOverride?: string): BootResult {
  let config;
  try {
    config = resolveConfig(stateDirOverride);
  } catch {
    return { ok: false, reason: "invalid configuration: refuse boot" };
  }
  try {
    ensureStateDir(config);
  } catch {
    return { ok: false, reason: "state directory unavailable: refuse boot" };
  }
  const loaded = loadStateFile(config.statePath);
  if (loaded.status === "invalid") {
    return { ok: false, reason: `invalid security state (${loaded.reason}): refuse boot` };
  }
  let epoch: number;
  try {
    const base = loaded.status === "missing" ? defaultSecurityState() : nextEpochState(loaded.state);
    epoch = base.epoch;
    saveStateFile(config.statePath, base);
  } catch {
    return { ok: false, reason: "security epoch failure: refuse boot" };
  }
  const sinkOpened = openAuditSink(config.auditPath);
  if (!sinkOpened.ok) {
    return { ok: false, reason: `audit sink refused (${sinkOpened.reason}): refuse boot` };
  }
  const session = createSession(config, epoch, sinkOpened.sink);
  const booted = appendAuditEvent(session.sink, {
    type: "sleep.entered",
    detail: `boot complete: epoch ${epoch}, safe defaults (SLEEP)`,
    epoch,
    sleep: "SLEEP",
  });
  if (!booted.ok) {
    return { ok: false, reason: "audit sink unhealthy at boot: refuse boot" };
  }
  return { ok: true, session };
}
