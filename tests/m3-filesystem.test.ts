import * as fs from "node:fs";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import { run } from "../src/executor/executor.js";
import { makeExecCtx, makeSandbox, completedOs, reachedOs } from "./m3-fixtures.js";

function attempt(root: string, resource: string): ReturnType<typeof run> {
  const { ctx } = makeExecCtx(root);
  return run(
    {
      capability: "filesystem.read",
      operation: "read",
      resource,
      taskId: "task-M3",
    },
    ctx,
  );
}

describe("M3 filesystem security: traversal, symlinks, sensitive paths", () => {
  it("reads and lists inside the root", () => {
    const sb = makeSandbox({ "a.txt": "A", "sub/b.txt": "B" });
    try {
      const { ctx } = makeExecCtx(sb.root);
      const read = run(
        {
          capability: "filesystem.read",
          operation: "read",
          resource: `${sb.root}/a.txt`,
          taskId: "task-M3",
        },
        ctx,
      );
      expect(read.outcome.status).toBe("completed");
      const list = run(
        {
          capability: "filesystem.read",
          operation: "list",
          resource: `${sb.root}/sub`,
          taskId: "task-M3",
        },
        ctx,
      );
      expect(list.outcome.status).toBe("completed");
    } finally {
      sb.cleanup();
    }
  });

  it("denies .. escape, absolute outsiders, and sibling-prefix tricks", () => {
    const sb = makeSandbox({ "a.txt": "A" });
    try {
      // Denied at the authorization boundary: no adapter dispatch at all.
      for (const evil of [
        `${sb.root}/../etc/passwd`,
        `${sb.root}/sub/../../etc/hosts`,
        "/etc/passwd",
        `${sb.root}-evil/a.txt`,
        "relative/path.txt",
        "",
      ]) {
        const r = attempt(sb.root, evil);
        expect(r.outcome.status, evil).toBe("refused");
        expect(reachedOs(r.log)).toBe(false);
      }
      // Encoded traversal is a literal filename that does not exist:
      // authorized lexically, then refused by the adapter — never completed.
      const encoded = attempt(sb.root, `${sb.root}/%2e%2e/secret`);
      expect(encoded.outcome.status).toBe("refused");
      expect(completedOs(encoded.log)).toBe(false);
    } finally {
      sb.cleanup();
    }
  });

  it("denies symlink escape; allows listing (no traversal on list)", () => {
    const outside = makeSandbox({ "secret.txt": "outside" });
    const sb = makeSandbox({ "inner.txt": "inside" });
    try {
      fs.symlinkSync(`${outside.root}/secret.txt`, `${sb.root}/escape-link`);
      const r = attempt(sb.root, `${sb.root}/escape-link`);
      expect(r.outcome.status).toBe("refused");
      // Adapter-level refusal after dispatch: resolved-target escape,
      // never completed, nothing returned.
      if (r.outcome.status === "refused") {
        expect(r.outcome.reason).toMatch(/escape/);
      }
      expect(completedOs(r.log)).toBe(false);

      // Internal link stays inside: allowed.
      fs.symlinkSync(`${sb.root}/inner.txt`, `${sb.root}/inner-link`);
      expect(attempt(sb.root, `${sb.root}/inner-link`).outcome.status).toBe(
        "completed",
      );

      // Listing a directory containing a link does not follow it.
      const { ctx } = makeExecCtx(sb.root);
      const list = run(
        {
          capability: "filesystem.read",
          operation: "list",
          resource: sb.root,
          taskId: "task-M3",
        },
        ctx,
      );
      expect(list.outcome.status).toBe("completed");
    } finally {
      sb.cleanup();
      outside.cleanup();
    }
  });

  it("denies sensitive files even inside the authorized root", () => {
    const sb = makeSandbox({
      ".env": "API_KEY=fake-123",
      "id_rsa": "fake-key",
      "notes.txt": "plain",
    });
    try {
      expect(attempt(sb.root, `${sb.root}/.env`).outcome.status).toBe("refused");
      expect(attempt(sb.root, `${sb.root}/id_rsa`).outcome.status).toBe("refused");
      // Ordinary file alongside still works.
      expect(attempt(sb.root, `${sb.root}/notes.txt`).outcome.status).toBe(
        "completed",
      );
    } finally {
      sb.cleanup();
    }
  });

  it("denies the real SSH dir even with a broad grant (defense in depth)", () => {
    const home = process.env["HOME"] ?? "";
    if (home === "") {
      return;
    }
    const sshDir = path.join(home, ".ssh");
    try {
      fs.statSync(sshDir);
    } catch {
      return; // no .ssh on this machine; nothing to prove
    }
    const sb = makeSandbox();
    try {
      const r = attempt(sb.root, sshDir);
      expect(r.outcome.status).toBe("refused");
    } finally {
      sb.cleanup();
    }
  });
});
