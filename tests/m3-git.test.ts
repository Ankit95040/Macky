import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import { run } from "../src/executor/executor.js";
import { makeExecCtx, makeSandbox, reachedOs } from "./m3-fixtures.js";

const GIT = "/usr/bin/git";

/** Build a tiny real repo inside the sandbox. Test-only git usage. */
function initRepo(root: string): string {
  const repo = path.join(root, "repo");
  fs.mkdirSync(repo, { recursive: true });
  const opts = { cwd: repo, env: { ...process.env, GIT_CONFIG_NOSYSTEM: "1", HOME: root } };
  execFileSync(GIT, ["init", "-b", "main"], opts);
  execFileSync(GIT, ["config", "user.email", "m3@test"], opts);
  execFileSync(GIT, ["config", "user.name", "m3"], opts);
  fs.writeFileSync(path.join(repo, "a.txt"), "v1\n");
  execFileSync(GIT, ["add", "."], opts);
  execFileSync(GIT, ["commit", "-m", "first"], opts);
  fs.writeFileSync(path.join(repo, "a.txt"), "v2\n");
  return fs.realpathSync(repo);
}

function gitReq(repo: string, operation: string): Record<string, string> {
  return { capability: "git.read", operation, resource: repo, taskId: "task-M3" };
}

describe("M3 git adapter: fixed operations, no shell, no injection", () => {
  it("runs status/log/diff on a real repo", () => {
    const sb = makeSandbox();
    try {
      const repo = initRepo(sb.root);
      const { ctx } = makeExecCtx(sb.root);
      expect(run(gitReq(repo, "status"), ctx).outcome.status).toBe("completed");
      const log = run(gitReq(repo, "log"), ctx);
      expect(log.outcome.status).toBe("completed");
      if (log.outcome.status === "completed") {
        const entries = log.outcome.result as Array<{ subject: string }>;
        expect(entries.length).toBe(1);
        expect(entries[0]?.subject).toBe("first");
      }
      expect(run(gitReq(repo, "diff"), ctx).outcome.status).toBe("completed");
    } finally {
      sb.cleanup();
    }
  });

  it("rejects operation smuggling (no shell syntax reaches git)", () => {
    const sb = makeSandbox();
    try {
      const repo = initRepo(sb.root);
      const { ctx } = makeExecCtx(sb.root);
      for (const evilOp of [
        "status && rm -rf /",
        "status; touch PWNED",
        "--upload-pack=evil",
        "log | cat /etc/passwd",
      ]) {
        const r = run(gitReq(repo, evilOp), ctx);
        expect(r.outcome.status, evilOp).toBe("refused");
        expect(reachedOs(r.log)).toBe(false);
      }
      expect(fs.existsSync(path.join(repo, "PWNED"))).toBe(false);
    } finally {
      sb.cleanup();
    }
  });

  it("treats hostile filenames literally (no shell interpretation)", () => {
    const sb = makeSandbox();
    try {
      const repo = initRepo(sb.root);
      fs.writeFileSync(path.join(repo, "$(touch LITERALLY).txt"), "x");
      fs.writeFileSync(path.join(repo, "a;touch SEMI.txt"), "y");
      const { ctx } = makeExecCtx(sb.root);
      const r = run(gitReq(repo, "status"), ctx);
      expect(r.outcome.status).toBe("completed");
      expect(fs.existsSync(path.join(repo, "LITERALLY"))).toBe(false);
      expect(fs.existsSync(path.join(repo, "SEMI.txt"))).toBe(false);
      expect(fs.existsSync(path.join(sb.root, "PWNED"))).toBe(false);
      if (r.outcome.status === "completed") {
        const entries = r.outcome.result as Array<{ path: string }>;
        expect(entries.some((e) => e.path.includes("touch"))).toBe(true);
      }
    } finally {
      sb.cleanup();
    }
  });

  it("refuses non-repos and repos outside the grant root", () => {
    const sb = makeSandbox({ "plain.txt": "x" });
    const elsewhere = makeSandbox();
    try {
      const { ctx } = makeExecCtx(sb.root);
      expect(run(gitReq(sb.root, "status"), ctx).outcome.status).toBe("refused");
      const repo = initRepo(elsewhere.root);
      expect(run(gitReq(repo, "status"), ctx).outcome.status).toBe("refused");
    } finally {
      sb.cleanup();
      elsewhere.cleanup();
    }
  });

  it("never offers mutating git operations", () => {
    const sb = makeSandbox();
    try {
      const repo = initRepo(sb.root);
      const { ctx } = makeExecCtx(sb.root);
      for (const op of ["commit", "push", "reset", "clean", "checkout"]) {
        const r = run(gitReq(repo, op), ctx);
        expect(r.outcome.status, op).toBe("refused");
        expect(reachedOs(r.log)).toBe(false);
      }
    } finally {
      sb.cleanup();
    }
  });
});
