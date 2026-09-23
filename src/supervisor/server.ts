/**
 * Persistent local supervisor (M18, read-only scope). One Node
 * process owns one SecureSession (fresh SLEEP / fresh epoch / zero
 * authority per M4 boot semantics) and serves status/audit over a
 * Unix-domain socket. NOTHING mutating is reachable: the dispatcher
 * has exactly two arms, both delegating to M16 read helpers.
 *
 * Hardening, all deterministic:
 * - socket dir 0700, socket file 0600 (explicit chmod after listen);
 * - per-boot unpredictable socket name (epoch + crypto randomness);
 * - lockfile with stale (dead-PID) takeover and live refusal;
 * - max 8 concurrent clients; one operation globally at a time;
 * - 5-minute idle timeout per connection; malformed/oversized input
 *   destroys the connection (never a partial state);
 * - responses bounded; error strings fixed (no internals leak).
 *
 * Same-user clients are UNTRUSTED (per corrected threat model): the
 * exposed surface is metadata the posture already treats as
 * user-visible. Mutating operations await a future milestone with
 * real client authentication.
 */
import { randomBytes } from "node:crypto";
import * as fs from "node:fs";
import * as net from "node:net";
import * as path from "node:path";
import { boot } from "../bootstrap/boot.js";
import type { SecureSession } from "../persistence/session.js";
import { getStatus, readAuditTailOp } from "../operator/service.js";
import {
  decodeFrames,
  encodeFrame,
  MAX_FRAME_BYTES,
  MAX_RESPONSE_BYTES,
  SupervisorRequestSchema,
  SUPERVISOR_PROTOCOL_VERSION,
} from "./protocol.js";

export const SUPERVISOR_MAX_CLIENTS = 8;
export const SUPERVISOR_IDLE_TIMEOUT_MS = 5 * 60 * 1000;
export const SUPERVISOR_LOCK_FILENAME = "supervisor.lock" as const;

export interface SupervisorHandle {
  readonly socketPath: string;
  readonly epoch: number;
  close(): Promise<void>;
}

export type SupervisorStartResult =
  | { readonly ok: true; readonly supervisor: SupervisorHandle }
  | { readonly ok: false; readonly reason: string };

interface LockContent {
  readonly pid: number;
  readonly socketName: string;
  readonly startedAt: string;
}

function pidAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) {
    return false;
  }
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function readLock(lockPath: string): LockContent | undefined {
  let raw: string;
  try {
    raw = fs.readFileSync(lockPath, "utf8");
  } catch {
    return undefined;
  }
  try {
    const parsed = JSON.parse(raw) as Partial<LockContent>;
    if (typeof parsed.pid !== "number" || typeof parsed.socketName !== "string") {
      return undefined;
    }
    return { pid: parsed.pid, socketName: parsed.socketName, startedAt: typeof parsed.startedAt === "string" ? parsed.startedAt : "" };
  } catch {
    return undefined;
  }
}

function safeUnlink(target: string): void {
  try {
    fs.unlinkSync(target);
  } catch {
    // Already gone; nothing to do.
  }
}

function boundError(reason: string): Buffer {
  return encodeFrame({ v: SUPERVISOR_PROTOCOL_VERSION, ok: false, error: reason });
}

export async function startSupervisor(stateDir: string): Promise<SupervisorStartResult> {
  const booted = boot(stateDir);
  if (!booted.ok) {
    return { ok: false, reason: "supervisor boot refused" };
  }
  const session: SecureSession = booted.session;
  const lockPath = path.join(stateDir, SUPERVISOR_LOCK_FILENAME);
  const existing = readLock(lockPath);
  if (existing !== undefined && pidAlive(existing.pid)) {
    return { ok: false, reason: "supervisor already running" };
  }
  // Stale or corrupt lock: remove unconditionally, then create ours
  // exclusively. A live rival racing us fails the exclusive create.
  safeUnlink(lockPath);
  // Short unpredictable name: macOS sun_path caps at 104 bytes, and a
  // listen() beyond it "succeeds" with NO socket file created (verified
  // empirically) — which would silently void the 0600 guarantee. The
  // existence assertion below turns that platform quirk into fail-closed.
  const socketName = `m-${session.epoch}-${randomBytes(8).toString("hex")}.sock`;
  const socketPath = path.join(stateDir, socketName);
  safeUnlink(socketPath);
  try {
    const fd = fs.openSync(lockPath, "wx", 0o600);
    fs.writeFileSync(fd, JSON.stringify({ pid: process.pid, socketName, startedAt: new Date().toISOString() }));
    fs.closeSync(fd);
  } catch {
    return { ok: false, reason: "supervisor lock unavailable" };
  }

  let busy = false;
  let clients = 0;
  const sockets = new Set<net.Socket>();

  const dispatch = (request: unknown): { body: unknown } => {
    const parsed = SupervisorRequestSchema.safeParse(request);
    if (!parsed.success) {
      return { body: { v: SUPERVISOR_PROTOCOL_VERSION, ok: false, error: "rejected" } };
    }
    if (parsed.data.op === "status") {
      return { body: { v: SUPERVISOR_PROTOCOL_VERSION, ok: true, result: getStatus(session) } };
    }
    const tail = readAuditTailOp(session, { limit: parsed.data.limit ?? 20 });
    if (!tail.ok) {
      return { body: { v: SUPERVISOR_PROTOCOL_VERSION, ok: false, error: "unavailable" } };
    }
    return { body: { v: SUPERVISOR_PROTOCOL_VERSION, ok: true, result: tail.events } };
  };

  const server = net.createServer({ pauseOnConnect: false });
  server.maxConnections = SUPERVISOR_MAX_CLIENTS;
  // Permanent handler: post-listen socket errors (accept failures,
  // resource pressure) must never crash the supervisor. Listen-time
  // failure is handled separately below via once().
  server.on("error", () => {
    // Transport noise; audit-worthy events come only from M16 helpers.
  });

  server.on("connection", (socket: net.Socket) => {
    clients += 1;
    sockets.add(socket);
    socket.setTimeout(SUPERVISOR_IDLE_TIMEOUT_MS);
    let pending: Buffer = Buffer.alloc(0);
    const destroy = (): void => {
      try {
        socket.destroy();
      } catch {
        // Already gone.
      }
    };
    socket.on("timeout", destroy);
    socket.on("error", () => {
      // Socket errors are transport noise, never trusted events.
    });
    socket.on("close", () => {
      clients -= 1;
      sockets.delete(socket);
    });
    socket.on("data", (chunk: Buffer) => {
      pending = Buffer.concat([pending, chunk]);
      if (pending.length > MAX_FRAME_BYTES + 4) {
        destroy();
        return;
      }
      const decoded = decodeFrames(pending);
      if (decoded.error !== undefined) {
        destroy();
        return;
      }
      pending = decoded.rest;
      for (const frame of decoded.frames) {
        if (busy) {
          try {
            socket.write(boundError("busy"));
          } catch {
            // Write failed; connection is unusable.
          }
          continue;
        }
        busy = true;
        try {
          const { body } = dispatch(frame);
          let encoded: Buffer;
          try {
            encoded = encodeFrame(body);
          } catch {
            try {
              socket.write(boundError("response too large"));
            } catch {
              // Write failed; connection is unusable.
            }
            continue;
          }
          if (encoded.length > MAX_RESPONSE_BYTES) {
            try {
              socket.write(boundError("response too large"));
            } catch {
              // Write failed; connection is unusable.
            }
            continue;
          }
          try {
            socket.write(encoded);
          } catch {
            destroy();
            return;
          }
        } finally {
          busy = false;
        }
      }
    });
  });

  try {
    await new Promise<void>((resolve, reject) => {
      server.once("error", (error: unknown) => {
        reject(error instanceof Error ? error : new Error("listen failed"));
      });
      server.listen(socketPath, () => {
        resolve();
      });
    });
  } catch {
    safeUnlink(lockPath);
    safeUnlink(socketPath);
    try {
      server.close();
    } catch {
      // Already closed.
    }
    return { ok: false, reason: "supervisor listen failed" };
  }

  try {
    fs.chmodSync(socketPath, 0o600);
    // The file MUST exist: without it there is no permission boundary
    // at all (see note above). Absence fails the whole startup.
    fs.statSync(socketPath);
  } catch {
    try {
      server.close();
    } catch {
      // Already closed.
    }
    safeUnlink(lockPath);
    safeUnlink(socketPath);
    return { ok: false, reason: "socket file unavailable" };
  }

  const handle: SupervisorHandle = {
    socketPath,
    epoch: session.epoch,
    close: async (): Promise<void> => {
      for (const socket of [...sockets]) {
        try {
          socket.destroy();
        } catch {
          // Already gone.
        }
      }
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
      });
      safeUnlink(socketPath);
      safeUnlink(lockPath);
    },
  };
  return { ok: true, supervisor: handle };
}
