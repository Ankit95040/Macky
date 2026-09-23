import * as fs from "node:fs";
import * as net from "node:net";
import * as os from "node:os";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import { decodeFrames, encodeFrame } from "../src/supervisor/protocol.js";
import { startSupervisor } from "../src/supervisor/server.js";

function tmpDir(): string {
  return fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "macky-m18-")));
}

interface Client {
  socket: net.Socket;
  received: Array<unknown>;
  closed: boolean;
  sendRaw(data: Buffer): void;
  sendJson(value: unknown): void;
  waitFor(count: number, ms?: number): Promise<void>;
  destroy(): void;
}

function connect(socketPath: string): Promise<Client> {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(socketPath);
    const received: Array<unknown> = [];
    let buffer: Buffer<ArrayBufferLike> = Buffer.alloc(0);
    let waiting: Array<() => void> = [];
    const client: Client = {
      socket,
      received,
      closed: false,
      sendRaw: (data: Buffer): void => {
        socket.write(data);
      },
      sendJson: (value: unknown): void => {
        socket.write(encodeFrame(value));
      },
      waitFor: (count: number, ms = 5000): Promise<void> => {
        if (received.length >= count) {
          return Promise.resolve();
        }
        return new Promise((res, rej) => {
          const timer = setTimeout(() => rej(new Error("wait timeout")), ms);
          waiting.push(() => {
            if (received.length >= count) {
              clearTimeout(timer);
              res();
            }
          });
        });
      },
      destroy: (): void => {
        try {
          socket.destroy();
        } catch {
          // Already gone.
        }
      },
    };
    socket.on("connect", () => resolve(client));
    socket.on("error", () => {
      client.closed = true;
    });
    socket.on("close", () => {
      client.closed = true;
      for (const w of waiting) {
        w();
      }
      waiting = [];
    });
    socket.on("data", (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
      const decoded = decodeFrames(buffer);
      buffer = decoded.rest;
      for (const frame of decoded.frames) {
        received.push(frame);
      }
      for (const w of waiting) {
        w();
      }
      if (decoded.error !== undefined) {
        socket.destroy();
      }
    });
    setTimeout(() => reject(new Error("connect timeout")), 5000);
  });
}

async function withSupervisor(
  body: (socketPath: string, dir: string) => Promise<void>,
): Promise<void> {
  const dir = tmpDir();
  try {
    const started = await startSupervisor(dir);
    expect(started.ok).toBe(true);
    if (!started.ok) {
      return;
    }
    try {
      await body(started.supervisor.socketPath, dir);
    } finally {
      await started.supervisor.close();
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

describe("M18 framing", () => {
  it("partial frames assemble; multiple frames dispatch in order", async () => {
    await withSupervisor(async (socketPath) => {
      const client = await connect(socketPath);
      try {
        const raw = encodeFrame({ v: 1, op: "status" });
        client.sendRaw(raw.subarray(0, 2));
        await new Promise((r) => setTimeout(r, 50));
        client.sendRaw(raw.subarray(2, 5));
        await new Promise((r) => setTimeout(r, 50));
        client.sendRaw(raw.subarray(5));
        client.sendJson({ v: 1, op: "status" });
        await client.waitFor(2);
        expect((client.received[0] as { ok: boolean }).ok).toBe(true);
        expect((client.received[1] as { ok: boolean }).ok).toBe(true);
      } finally {
        client.destroy();
      }
    });
  });
  it("oversized and malformed frames destroy the connection", async () => {
    await withSupervisor(async (socketPath) => {
      const badLength = Buffer.alloc(4);
      badLength.writeUInt32BE(10 * 1024 * 1024, 0);
      const c1 = await connect(socketPath);
      try {
        c1.sendRaw(Buffer.concat([badLength, Buffer.from("x")]));
        await new Promise((r) => setTimeout(r, 300));
        expect(c1.closed).toBe(true);
      } finally {
        c1.destroy();
      }
      const c2 = await connect(socketPath);
      try {
        const garbage = Buffer.from("not-json-at-all-padded!!");
        const header = Buffer.alloc(4);
        header.writeUInt32BE(garbage.length, 0);
        c2.sendRaw(Buffer.concat([header, garbage]));
        await new Promise((r) => setTimeout(r, 300));
        expect(c2.closed).toBe(true);
      } finally {
        c2.destroy();
      }
    });
  });
});

describe("M18 schema + authority rejection", () => {
  it("unknown ops, unknown fields, and malformed shapes refuse", async () => {
    await withSupervisor(async (socketPath) => {
      const cases: Array<unknown> = [
        { v: 1, op: "wake" },
        { v: 1, op: "grant", capability: "x" },
        { v: 1, op: "status", epoch: 123 },
        { v: 2, op: "status" },
        { op: "status" },
        { v: 1 },
        "status",
        null,
        { v: 1, op: "audit", limit: 0 },
        { v: 1, op: "audit", limit: 101 },
        { v: 1, op: "audit", limit: "many" },
      ];
      for (const bad of cases) {
        const client = await connect(socketPath);
        try {
          client.sendJson(bad);
          await client.waitFor(1);
          expect((client.received[0] as { ok: boolean }).ok, JSON.stringify(bad)).toBe(false);
        } finally {
          client.destroy();
        }
      }
    });
  });
  it("mutating and authority-bearing ops are not routable", async () => {
    await withSupervisor(async (socketPath, dir) => {
      for (const op of ["wake", "sleep", "kill", "talk", "grant", "revoke", "confirm", "execute"]) {
        const client = await connect(socketPath);
        try {
          client.sendJson({ v: 1, op });
          await client.waitFor(1);
          expect((client.received[0] as { ok: boolean }).ok, op).toBe(false);
        } finally {
          client.destroy();
        }
      }
      // Session untouched: still asleep, zero grants.
      const client = await connect(socketPath);
      try {
        client.sendJson({ v: 1, op: "status" });
        await client.waitFor(1);
        const status = (client.received[0] as { ok: boolean; result: { sleep: string } });
        expect(status.result.sleep).toBe("SLEEP");
      } finally {
        client.destroy();
      }
      void dir;
    });
  });
  it("authority-field injection is rejected at the schema", async () => {
    await withSupervisor(async (socketPath) => {
      const client = await connect(socketPath);
      try {
        client.sendJson({ v: 1, op: "status", taskId: "t", grant: {}, tier: 3, confirmed: true, epoch: 1 });
        await client.waitFor(1);
        expect((client.received[0] as { ok: boolean }).ok).toBe(false);
      } finally {
        client.destroy();
      }
    });
  });
});

describe("M18 status/audit behavior", () => {
  it("status is metadata-only; audit tail bounded and clean", async () => {
    await withSupervisor(async (socketPath) => {
      const client = await connect(socketPath);
      try {
        client.sendJson({ v: 1, op: "status" });
        await client.waitFor(1);
        const status = client.received[0] as { ok: boolean; result: Record<string, unknown> };
        expect(status.ok).toBe(true);
        expect(Object.keys(status.result).sort()).toEqual([
          "auditHealthy", "confirmationCount", "epoch", "grantCount", "killEngaged", "sleep",
        ]);
        const blob = JSON.stringify(status.result);
        expect(blob).not.toContain("controlKey");
        expect(blob).not.toContain("token");
        client.sendJson({ v: 1, op: "audit", limit: 5 });
        await client.waitFor(2);
        const audit = client.received[1] as { ok: boolean; result: Array<unknown> };
        expect(audit.ok).toBe(true);
        expect(audit.result.length).toBeLessThanOrEqual(5);
        const auditBlob = JSON.stringify(audit.result);
        expect(auditBlob).not.toContain("controlKey");
      } finally {
        client.destroy();
      }
    });
  });
  it("fresh boot is SLEEP with zero authority; restart re-epochs safely", async () => {
    const dir = tmpDir();
    try {
      const first = await startSupervisor(dir);
      expect(first.ok).toBe(true);
      if (!first.ok) {
        return;
      }
      const epoch1 = first.supervisor.epoch;
      await first.supervisor.close();
      const second = await startSupervisor(dir);
      expect(second.ok).toBe(true);
      if (!second.ok) {
        return;
      }
      expect(second.supervisor.epoch).toBe(epoch1 + 1);
      expect(second.supervisor.socketPath).not.toBe(first.supervisor.socketPath);
      const client = await connect(second.supervisor.socketPath);
      try {
        client.sendJson({ v: 1, op: "status" });
        await client.waitFor(1);
        const status = client.received[0] as { ok: boolean; result: { sleep: string; grantCount: number } };
        expect(status.result.sleep).toBe("SLEEP");
        expect(status.result.grantCount).toBe(0);
      } finally {
        client.destroy();
      }
      await second.supervisor.close();
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("M18 endpoint hygiene + concurrency", () => {
  it("socket path randomized; perms 0600 dir 0700; stale lock takeover", async () => {
    const dirA = tmpDir();
    const dirB = tmpDir();
    try {
      const first = await startSupervisor(dirA);
      expect(first.ok).toBe(true);
      if (!first.ok) {
        return;
      }
      expect(first.supervisor.socketPath).toMatch(/m-\d+-[0-9a-f]{16}\.sock$/);
      expect(fs.statSync(first.supervisor.socketPath).mode & 0o777).toBe(0o600);
      expect(fs.statSync(dirA).mode & 0o777).toBe(0o700);
      // Live lock blocks a second supervisor.
      const rival = await startSupervisor(dirA);
      expect(rival.ok).toBe(false);
      await first.supervisor.close();
      // Dead-PID lockfile is taken over on next start.
      fs.writeFileSync(
        `${dirB}/supervisor.lock`,
        JSON.stringify({ pid: 987654321, socketName: "macky-stale.sock", startedAt: "" }),
      );
      const recovered = await startSupervisor(dirB);
      expect(recovered.ok).toBe(true);
      if (recovered.ok) {
        await recovered.supervisor.close();
      }
    } finally {
      fs.rmSync(dirA, { recursive: true, force: true });
      fs.rmSync(dirB, { recursive: true, force: true });
    }
  });
  it("concurrent clients serialize; all responses correct", async () => {
    await withSupervisor(async (socketPath) => {
      const clients = await Promise.all([connect(socketPath), connect(socketPath), connect(socketPath)]);
      try {
        for (const client of clients) {
          for (let i = 0; i < 5; i += 1) {
            client.sendJson(i % 2 === 0 ? { v: 1, op: "status" } : { v: 1, op: "audit", limit: 3 });
          }
        }
        for (const client of clients) {
          await client.waitFor(5);
          expect(client.received).toHaveLength(5);
          for (const response of client.received) {
            expect((response as { ok: boolean }).ok).toBe(true);
          }
        }
      } finally {
        for (const client of clients) {
          client.destroy();
        }
      }
    });
  });
  it("max client guard is configured", async () => {
    const { SUPERVISOR_MAX_CLIENTS } = await import("../src/supervisor/server.js");
    expect(SUPERVISOR_MAX_CLIENTS).toBe(8);
  });
});

describe("M18 static scans", () => {
  it("no network/executor/authority surface in supervisor sources", () => {
    // NOTE: node:net is intentionally allowed: Unix-domain sockets
    // are the transport. What is forbidden is TCP/HTTP/fetch, process
    // execution, and any authority-mutating helper.
    const dir = new URL("../src/supervisor/", import.meta.url);
    for (const file of fs.readdirSync(dir).filter((f) => f.endsWith(".ts"))) {
      const src = fs.readFileSync(new URL(file, dir), "utf8");
      for (const forbidden of [
        "node:http", "fetch(", "WebSocket", "child_process",
        "spawn(", "execFile", "MCP", "mcp", "openai", "anthropic",
        "grantToSession", "recordConfirmation", "confirmInSession",
        "engageSessionKill", "wakeSession", "sleepSession",
        "127.0.0.1", "localhost",
      ]) {
        expect(src.includes(forbidden), `supervisor/${file}: ${forbidden}`).toBe(false);
      }
    }
  });
  it("supervisor imports only session/boot/operator-reads/stdlib", () => {
    const valueAllowedPrefixes = [
      "./protocol.js",
      "./server.js",
      "../bootstrap/boot.js",
      "../operator/service.js",
      "node:crypto",
      "node:fs",
      "node:net",
      "node:path",
      "zod",
    ];
    for (const file of ["protocol.ts", "server.ts", "index.ts"]) {
      const src = fs.readFileSync(new URL(`../src/supervisor/${file}`, import.meta.url), "utf8");
      for (const line of src.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed.startsWith("import ") || !trimmed.includes("from")) {
          continue;
        }
        const target = (trimmed.split("from")[1] ?? "").trim().replace(/["';]/g, "");
        if (trimmed.startsWith("import type")) {
          // Type-only imports erase at runtime; the single exception is
          // the session shape. Any other type import is still flagged.
          expect(
            target === "../persistence/session.js" || valueAllowedPrefixes.some((prefix) => target === prefix),
            `supervisor/${file} type-imports ${target}`,
          ).toBe(true);
          continue;
        }
        expect(
          valueAllowedPrefixes.some((prefix) => target === prefix || target.startsWith(prefix)),
          `supervisor/${file}: ${target}`,
        ).toBe(true);
      }
    }
  });
});
