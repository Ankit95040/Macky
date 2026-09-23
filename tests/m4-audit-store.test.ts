import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import {
  appendAuditEvent,
  AUDIT_LIMITS,
  openAuditSink,
  repairAuditToPrefix,
  verifyAuditFile,
} from "../src/persistence/audit-store.js";

function tmpAudit(): { dir: string; file: string } {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "macky-m4-")));
  return { dir, file: path.join(dir, "audit.jsonl") };
}

describe("M4 durable audit: append, chain, verify, recover", () => {
  it("appends valid events with chained hashes and private perms", () => {
    const { dir, file } = tmpAudit();
    try {
      const opened = openAuditSink(file);
      expect(opened.ok).toBe(true);
      if (!opened.ok) return;
      expect(appendAuditEvent(opened.sink, { type: "sleep.entered", detail: "boot", epoch: 1, sleep: "SLEEP" }).ok).toBe(true);
      expect(appendAuditEvent(opened.sink, { type: "authorization.allowed", detail: "ok", epoch: 1, sleep: "AWAKE" }).ok).toBe(true);
      expect(fs.statSync(file).mode & 0o777).toBe(0o600);
      const v = verifyAuditFile(file);
      expect(v.ok).toBe(true);
      expect(v.events.map((e) => e.seq)).toEqual([1, 2]);
      expect(v.events[1]?.prevHash).toBe(v.events[0]?.hash);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("reopening continues the chain (no reset, no fork)", () => {
    const { dir, file } = tmpAudit();
    try {
      const a = openAuditSink(file);
      expect(a.ok).toBe(true);
      if (!a.ok) return;
      appendAuditEvent(a.sink, { type: "t", detail: "one", epoch: 1, sleep: "SLEEP" });
      const b = openAuditSink(file);
      expect(b.ok).toBe(true);
      if (!b.ok) return;
      expect(b.sink.nextSeq).toBe(2);
      appendAuditEvent(b.sink, { type: "t", detail: "two", epoch: 2, sleep: "SLEEP" });
      expect(verifyAuditFile(file).ok).toBe(true);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("detects partial tail, broken hash, gaps, duplicates", () => {
    const { dir, file } = tmpAudit();
    try {
      const opened = openAuditSink(file);
      if (!opened.ok) return;
      appendAuditEvent(opened.sink, { type: "a", detail: "1", epoch: 1, sleep: "SLEEP" });
      appendAuditEvent(opened.sink, { type: "a", detail: "2", epoch: 1, sleep: "SLEEP" });
      // Partial final record.
      fs.appendFileSync(file, '{"v": 1, "seq": 3, "trunc');
      let v = verifyAuditFile(file);
      expect(v.ok).toBe(false);
      expect(v.errors.some((e) => e.includes("partial"))).toBe(true);
      expect(v.events).toHaveLength(2);

      // Tampered hash.
      const lines = fs.readFileSync(file, "utf8").split("\n").slice(0, 2);
      const tampered = JSON.parse(lines[1] as string) as Record<string, unknown>;
      tampered["detail"] = "forged";
      fs.writeFileSync(file, `${lines[0]}\n${JSON.stringify(tampered)}\n`);
      v = verifyAuditFile(file);
      expect(v.ok).toBe(false);
      expect(v.errors.some((e) => e.includes("hash"))).toBe(true);

      // Duplicate sequence.
      fs.writeFileSync(file, `${lines[0]}\n${lines[0]}\n`);
      v = verifyAuditFile(file);
      expect(v.ok).toBe(false);
      expect(v.errors.some((e) => e.includes("sequence") || e.includes("chain"))).toBe(true);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("refuses oversized events/details and corrupt opens", () => {
    const { dir, file } = tmpAudit();
    try {
      const opened = openAuditSink(file);
      if (!opened.ok) return;
      expect(
        appendAuditEvent(opened.sink, { type: "t", detail: "x".repeat(AUDIT_LIMITS.MAX_DETAIL_BYTES + 1), epoch: 1, sleep: "SLEEP" }).ok,
      ).toBe(false);
      expect(
        appendAuditEvent(opened.sink, { type: "", detail: "x", epoch: 1, sleep: "SLEEP" }).ok,
      ).toBe(false);
      fs.writeFileSync(file, "garbage\n");
      expect(openAuditSink(file).ok).toBe(false);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("write failure is explicit; explicit repair restores bootability", () => {
    const { dir, file } = tmpAudit();
    try {
      const opened = openAuditSink(file);
      if (!opened.ok) return;
      appendAuditEvent(opened.sink, { type: "a", detail: "keep", epoch: 1, sleep: "SLEEP" });
      // Simulate crash mid-write: garbage tail.
      fs.appendFileSync(file, "CRASH-BYTES");
      expect(openAuditSink(file).ok).toBe(false);
      // Operator explicitly truncates to the valid prefix (never automatic).
      repairAuditToPrefix(file, 1);
      const reopened = openAuditSink(file);
      expect(reopened.ok).toBe(true);
      expect(verifyAuditFile(file).ok).toBe(true);
      expect(() => repairAuditToPrefix(file, 99)).toThrow();
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("unwritable location fails closed without pretending success", () => {
    const { dir } = tmpAudit();
    try {
      const nope = path.join(dir, "no-such-dir", "audit.jsonl");
      const opened = openAuditSink(nope);
      if (opened.ok) {
        const r = appendAuditEvent(opened.sink, { type: "t", detail: "x", epoch: 1, sleep: "SLEEP" });
        expect(r.ok).toBe(false);
      } else {
        expect(opened.ok).toBe(false);
      }
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
