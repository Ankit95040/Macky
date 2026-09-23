import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import { repairAuditToPrefix } from "../src/persistence/audit-store.js";

/**
 * Genuine process-boundary restart test: the project is compiled with
 * the existing tsc toolchain, then a probe process is launched twice
 * against the same state dir. Epoch bump + safe sleep are observed
 * across real execs, not in-memory simulation.
 */
const ROOT = process.cwd();
const PROBE = path.join(ROOT, "dist", "tests", "m4-probe.js");

interface ProbeOut {
  ok: boolean;
  epoch?: number;
  sleep?: string;
  killEngaged?: boolean;
  grants?: number;
  reason?: string;
}

function bootProc(stateDir: string): ProbeOut {
  const out = execFileSync(process.execPath, [PROBE, "boot", stateDir], {
    timeout: 30_000,
    encoding: "utf8",
  });
  return JSON.parse(out.trim()) as ProbeOut;
}

function tmpDir(): string {
  return fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "macky-m4-int-")));
}

describe("M4 restart integration: two real processes, one state dir", () => {
  beforeAll(() => {
    execFileSync(
      process.execPath,
      [path.join(ROOT, "node_modules", "typescript", "bin", "tsc")],
      { cwd: ROOT, timeout: 120_000, stdio: "pipe" },
    );
    expect(fs.existsSync(PROBE)).toBe(true);
  }, 150_000);

  it("epoch 1 → 2 across processes; always sleeping, never authorized", () => {
    const dir = tmpDir();
    try {
      const first = bootProc(dir);
      expect(first.ok).toBe(true);
      expect(first.epoch).toBe(1);
      expect(first.sleep).toBe("SLEEP");
      expect(first.grants).toBe(0);
      const second = bootProc(dir);
      expect(second.ok).toBe(true);
      expect(second.epoch).toBe(2);
      expect(second.sleep).toBe("SLEEP");
      expect(second.killEngaged).toBe(false);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("forged state file fails the real boot closed", () => {
    const dir = tmpDir();
    try {
      expect(bootProc(dir).ok).toBe(true);
      fs.writeFileSync(
        path.join(dir, "security-state.json"),
        '{"schemaVersion":1,"epoch":2,"sleep":"AWAKE","admin":true}',
      );
      const forged = bootProc(dir);
      expect(forged.ok).toBe(false);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("corrupt audit fails boot; explicit repair recovers (never automatic)", () => {
    const dir = tmpDir();
    try {
      expect(bootProc(dir).ok).toBe(true);
      const audit = path.join(dir, "audit.jsonl");
      const before = fs.readFileSync(audit, "utf8").split("\n").filter((l) => l.length > 0).length;
      expect(before).toBeGreaterThan(0);
      fs.appendFileSync(audit, "CRASH-MID-WRITE");
      expect(bootProc(dir).ok).toBe(false);
      repairAuditToPrefix(audit, before);
      const recovered = bootProc(dir);
      expect(recovered.ok).toBe(true);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
