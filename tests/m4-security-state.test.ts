import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import {
  defaultSecurityState,
  loadStateFile,
  nextEpochState,
  parseSecurityState,
  saveStateFile,
  SECURITY_STATE_VERSION,
} from "../src/persistence/security-state.js";

function tmpFile(): { dir: string; file: string } {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "macky-m4-")));
  return { dir, file: path.join(dir, "security-state.json") };
}

describe("M4 security-state model: strict, versioned, fail-closed", () => {
  it("accepts exactly the schema and nothing else", () => {
    expect(parseSecurityState({ schemaVersion: 1, epoch: 7 })?.epoch).toBe(7);
    for (const bad of [
      null,
      {},
      { schemaVersion: 1 },
      { epoch: 1 },
      { schemaVersion: 1, epoch: 0 },
      { schemaVersion: 1, epoch: -3 },
      { schemaVersion: 1, epoch: 1.5 },
      { schemaVersion: 2, epoch: 1 },
      { schemaVersion: "1", epoch: 1 },
      { schemaVersion: 1, epoch: 1, sleep: "AWAKE" },
      { schemaVersion: 1, epoch: 1, approved: true },
      { schemaVersion: 1, epoch: Number.MAX_SAFE_INTEGER + 1 },
      [],
      "sleeping",
    ]) {
      expect(parseSecurityState(bad), JSON.stringify(bad)).toBeUndefined();
    }
    expect(SECURITY_STATE_VERSION).toBe(1);
  });

  it("missing file reports missing (first boot), never throws", () => {
    const { dir, file } = tmpFile();
    try {
      expect(loadStateFile(file)).toEqual({ status: "missing" });
      expect(defaultSecurityState()).toEqual({ schemaVersion: 1, epoch: 1 });
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("malformed/truncated/wrong-version files report invalid", () => {
    const { dir, file } = tmpFile();
    try {
      for (const [name, content] of [
        ["garbage", "not json at all"],
        ["truncated", '{"schemaVersion": 1, "epo'],
        ["empty", ""],
        ["version", '{"schemaVersion": 999, "epoch": 1}'],
        ["enum", '{"schemaVersion": 1, "epoch": "awake"}'],
        ["extra", '{"schemaVersion": 1, "epoch": 1, "killSwitch": false}'],
        ["array", "[]"],
      ] as Array<[string, string]>) {
        fs.writeFileSync(file, content);
        const r = loadStateFile(file);
        expect(r.status, name).toBe("invalid");
      }
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("save/load round-trips atomically with private permissions", () => {
    const { dir, file } = tmpFile();
    try {
      saveStateFile(file, { schemaVersion: 1, epoch: 42 });
      expect(loadStateFile(file)).toEqual({
        status: "loaded",
        state: { schemaVersion: 1, epoch: 42 },
      });
      expect(fs.statSync(file).mode & 0o777).toBe(0o600);
      expect(fs.existsSync(`${file}.tmp-${process.pid}`)).toBe(false);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("epochs increase; exhaustion refuses instead of wrapping", () => {
    expect(nextEpochState({ schemaVersion: 1, epoch: 17 }).epoch).toBe(18);
    expect(() =>
      nextEpochState({ schemaVersion: 1, epoch: Number.MAX_SAFE_INTEGER }),
    ).toThrow();
  });
});
