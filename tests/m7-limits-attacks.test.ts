import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import { boot } from "../src/bootstrap/boot.js";
import { grantToSession, wakeSession } from "../src/persistence/session.js";
import type { SecureSession } from "../src/persistence/session.js";
import { LIMITS } from "../src/executor/limits.js";
import {
  createWorkspaceRegistry,
  registerWorkspace,
} from "../src/workspace/registry.js";
import { handleWorkspaceProposal } from "../src/workspace/service.js";
import { truncateText, TRUNCATION_MARKER } from "../src/workspace/text.js";

function tmpDir(): string {
  return fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "macky-m7-")));
}

interface Rig {
  dir: string;
  work: string;
  session: SecureSession;
  cleanup: () => void;
}

function rigged(): Rig {
  const dir = tmpDir();
  const work = tmpDir();
  const booted = boot(dir);
  if (!booted.ok) throw new Error("boot failed");
  const registry = createWorkspaceRegistry();
  if (!registerWorkspace(registry, "ws-test", work).ok) throw new Error("register failed");
  for (const [grantId, capability] of [
    ["g-read", "filesystem.read"],
    ["g-find", "filesystem.find"],
    ["g-search", "filesystem.search"],
    ["g-tree", "filesystem.tree"],
    ["g-git", "git.read"],
  ] as Array<[string, string]>) {
    grantToSession(booted.session, { grantId, taskId: "task-W", capability, scope: work });
  }
  wakeSession(booted.session, { kind: "ui-action" });
  (booted.session as unknown as { __registry: unknown }).__registry = registry;
  return { dir, work, session: booted.session, cleanup: () => { fs.rmSync(dir, { recursive: true, force: true }); fs.rmSync(work, { recursive: true, force: true }); } };
}

function registryOf(rig: Rig): ReturnType<typeof createWorkspaceRegistry> {
  return (rig.session as unknown as { __registry: ReturnType<typeof createWorkspaceRegistry> }).__registry;
}

function ask(rig: Rig, output: unknown): ReturnType<typeof handleWorkspaceProposal> {
  return handleWorkspaceProposal(rig.session, { taskId: "task-W", workspaceIds: ["ws-test"] }, registryOf(rig), output);
}

function ws(op: string, extra?: Record<string, unknown>): Record<string, unknown> {
  return { v: 1, workspaceId: "ws-test", op, ...extra };
}

describe("M7 limits R–U, V + overflow Y–AA", () => {
  it("R. oversized directory refused", () => {
    const rig = rigged();
    try {
      for (let i = 0; i < LIMITS.MAX_DIR_ENTRIES + 1; i += 1) {
        fs.writeFileSync(path.join(rig.work, `f-${i}.txt`), "x");
      }
      const r = ask(rig, ws("dir-list", { path: "." }));
      expect(r.outcome.status).toBe("refused");
    } finally {
      rig.cleanup();
    }
  });
  it("S. deep tree truncates explicitly", () => {
    const rig = rigged();
    try {
      let deep = rig.work;
      for (let i = 0; i < LIMITS.MAX_TREE_DEPTH + 2; i += 1) {
        deep = path.join(deep, `d${i}`);
        fs.mkdirSync(deep);
      }
      fs.writeFileSync(path.join(deep, "leaf.txt"), "x");
      const r = ask(rig, ws("tree", { path: "." }));
      expect(r.outcome.status).toBe("completed");
      if (r.outcome.status === "completed") {
        expect((r.outcome.result as { truncated: boolean }).truncated).toBe(true);
      }
    } finally {
      rig.cleanup();
    }
  });
  it("T. excessive entries truncate find", () => {
    const rig = rigged();
    try {
      for (let i = 0; i < 250; i += 1) {
        const sub = path.join(rig.work, `s${i}`);
        fs.mkdirSync(sub);
        for (let j = 0; j < 10; j += 1) {
          fs.writeFileSync(path.join(sub, `f${j}.ts`), "x");
        }
      }
      const r = ask(rig, ws("file-find", { path: ".", pattern: "*.ts" }));
      expect(r.outcome.status).toBe("completed");
      if (r.outcome.status === "completed") {
        const c = r.outcome.result as { entries: unknown[]; truncated: boolean };
        expect(c.entries.length).toBeLessThanOrEqual(LIMITS.MAX_FIND_RESULTS);
        expect(c.truncated).toBe(true);
      }
    } finally {
      rig.cleanup();
    }
  });
  it("U. huge file refused (single M3 size policy)", () => {
    const rig = rigged();
    try {
      fs.writeFileSync(path.join(rig.work, "huge.bin"), "x".repeat(LIMITS.MAX_FILE_BYTES + 1));
      expect(ask(rig, ws("file-read", { path: "huge.bin" })).outcome.status).toBe("refused");
    } finally {
      rig.cleanup();
    }
  });
  it("V. binary file refused", () => {
    const rig = rigged();
    try {
      fs.writeFileSync(path.join(rig.work, "b.bin"), Buffer.from([0x41, 0x00, 0x42]));
      expect(ask(rig, ws("file-read", { path: "b.bin" })).outcome.status).toBe("refused");
    } finally {
      rig.cleanup();
    }
  });
  it("Y/Z. match explosion truncates at the cap", () => {
    const rig = rigged();
    try {
      const lines = Array.from({ length: 300 }, (_, i) => `needle ${i}`).join("\n");
      fs.writeFileSync(path.join(rig.work, "hay.txt"), lines);
      const r = ask(rig, ws("content-search", { path: ".", query: "needle" }));
      expect(r.outcome.status).toBe("completed");
      if (r.outcome.status === "completed") {
        const c = r.outcome.result as { matches: unknown[]; truncated: boolean };
        expect(c.matches.length).toBeLessThanOrEqual(LIMITS.MAX_SEARCH_MATCHES);
        expect(c.truncated).toBe(true);
      }
    } finally {
      rig.cleanup();
    }
  });
  it("AA. node explosion truncates tree", () => {
    const rig = rigged();
    try {
      for (let i = 0; i < 60; i += 1) {
        const sub = path.join(rig.work, `n${i}`);
        fs.mkdirSync(sub);
        for (let j = 0; j < 6; j += 1) {
          fs.writeFileSync(path.join(sub, `f${j}.txt`), "x");
        }
      }
      const r = ask(rig, ws("tree", { path: "." }));
      expect(r.outcome.status).toBe("completed");
      if (r.outcome.status === "completed") {
        expect((r.outcome.result as { truncated: boolean }).truncated).toBe(true);
      }
    } finally {
      rig.cleanup();
    }
  });
});

describe("M7 unicode W–X (shared truncation utility)", () => {
  it("W. emoji/CJK survive truncation intact", () => {
    const text = `😀${"汉".repeat(10)}🎉tail`;
    const r = truncateText(text, 5, TRUNCATION_MARKER);
    expect(r.truncated).toBe(true);
    expect(r.text).toBe(`😀${"汉".repeat(4)}${TRUNCATION_MARKER}`);
    expect(Array.from(r.text).length).toBe(5 + Array.from(TRUNCATION_MARKER).length);
  });
  it("X. boundary exactness, combining marks, determinism", () => {
    expect(truncateText("abc", 3, TRUNCATION_MARKER)).toEqual({ text: "abc", truncated: false });
    expect(truncateText("abcd", 3, TRUNCATION_MARKER)).toEqual({ text: `abc${TRUNCATION_MARKER}`, truncated: true });
    // Combining mark splits are cosmetic but never lone surrogates.
    const combined = "éx"; // e + U+0301
    const r = truncateText(combined, 1, TRUNCATION_MARKER);
    expect(r.truncated).toBe(true);
    expect(() => encodeURIComponent(r.text)).not.toThrow();
    expect(truncateText("😀😀", 2, TRUNCATION_MARKER)).toEqual({ text: "😀😀", truncated: false });
    expect(truncateText("😀😀😀", 2, TRUNCATION_MARKER).text).toBe(`😀😀${TRUNCATION_MARKER}`);
  });
  it("W2. emoji file content completes valid end-to-end", () => {
    const rig = rigged();
    try {
      fs.writeFileSync(path.join(rig.work, "emoji.txt"), "😀 hello 汉语 🎉\n");
      const r = ask(rig, ws("file-read", { path: "emoji.txt" }));
      expect(r.outcome.status).toBe("completed");
      if (r.outcome.status === "completed") {
        expect((r.outcome.result as { content: string }).content).toContain("😀");
      }
    } finally {
      rig.cleanup();
    }
  });
});

describe("M7 pattern/argv attacks AB–AF + capability denials AG–AL", () => {
  it("AB/AC/AD. hostile patterns refused", () => {
    const rig = rigged();
    try {
      for (const pattern of ["../*.ts", "*.ts; rm -rf /", "$(whoami)", "**/*.ts", "?.ts", "[a-z].ts", "*.ts|cat", "a b"]) {
        const r = ask(rig, ws("file-find", { path: ".", pattern }));
        expect(r.outcome.status, pattern).toBe("refused");
      }
    } finally {
      rig.cleanup();
    }
  });
  it("AF. git stays fixed-argv; extra fields refused", () => {
    const rig = rigged();
    try {
      const repo = path.join(rig.work, "repo");
      fs.mkdirSync(repo);
      const env = { ...process.env, GIT_CONFIG_NOSYSTEM: "1", HOME: rig.work };
      execFileSync("/usr/bin/git", ["init", "-b", "main"], { cwd: repo, env });
      execFileSync("/usr/bin/git", ["config", "user.email", "m7@t"], { cwd: repo, env });
      execFileSync("/usr/bin/git", ["config", "user.name", "m7"], { cwd: repo, env });
      fs.writeFileSync(path.join(repo, "a.txt"), "v1\n");
      execFileSync("/usr/bin/git", ["add", "."], { cwd: repo, env });
      execFileSync("/usr/bin/git", ["commit", "-m", "first"], { cwd: repo, env });
      const ok = ask(rig, ws("git-status", { path: "repo" }));
      expect(ok.outcome.status).toBe("completed");
      expect(ask(rig, { ...ws("git-status", { path: "repo" }), pattern: "*.ts" }).outcome.status).toBe("refused");
      expect(ask(rig, { ...ws("git-log", { path: "repo" }), args: ["--upload-pack=x"] }).outcome.status).toBe("refused");
    } finally {
      rig.cleanup();
    }
  });
  it("AG/AH/AI. write/shell/network ops have no vocabulary", () => {
    const rig = rigged();
    try {
      for (const op of ["file-write", "file-delete", "shell-exec", "terminal-run", "network-fetch", "mkdir"]) {
        expect(ask(rig, { v: 1, workspaceId: "ws-test", op, path: "." }).outcome.status, op).toBe("refused");
      }
    } finally {
      rig.cleanup();
    }
  });
  it("AJ/AK. registration + policy fields refused", () => {
    const rig = rigged();
    try {
      expect(ask(rig, { ...ws("dir-list", { path: "." }), root: "/tmp" }).outcome.status).toBe("refused");
      expect(ask(rig, { ...ws("dir-list", { path: "." }), policy: "allow-all" }).outcome.status).toBe("refused");
      expect(ask(rig, { ...ws("dir-list", { path: "." }), riskTier: 0 }).outcome.status).toBe("refused");
    } finally {
      rig.cleanup();
    }
  });
});

describe("M7 sensitive files (section 7 battery)", () => {
  it("blocks credential filenames inside the workspace", () => {
    const rig = rigged();
    try {
      for (const name of [".env.local", "id_rsa", "creds.pem", ".npmrc", ".netrc", "notes.key"]) {
        fs.writeFileSync(path.join(rig.work, name), "secret=1\n");
      }
      for (const name of [".env.local", "id_rsa", "creds.pem", ".npmrc", ".netrc", "notes.key"]) {
        expect(ask(rig, ws("file-read", { path: name })).outcome.status, name).toBe("refused");
      }
      // Discovery prunes them too: find-all must not surface sensitive names.
      const found = ask(rig, ws("file-find", { path: ".", pattern: "*" }));
      expect(found.outcome.status).toBe("completed");
      if (found.outcome.status === "completed") {
        const names = (found.outcome.result as { entries: Array<{ path: string }> }).entries.map((e) => e.path);
        expect(names).not.toContain(".env.local");
        expect(names).not.toContain("id_rsa");
      }
      // …and search skips their contents.
      const searched = ask(rig, ws("content-search", { path: ".", query: "secret" }));
      expect(searched.outcome.status).toBe("completed");
      if (searched.outcome.status === "completed") {
        const blob = JSON.stringify(searched.outcome.result);
        expect(blob).not.toContain(".env.local");
      }
    } finally {
      rig.cleanup();
    }
  });
});
