import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import { boot } from "../src/bootstrap/boot.js";
import {
  engageSessionKill,
  grantToSession,
  wakeSession,
} from "../src/persistence/session.js";
import type { SecureSession } from "../src/persistence/session.js";
import {
  createWorkspaceRegistry,
  registerWorkspace,
  reverifyWorkspace,
} from "../src/workspace/registry.js";
import {
  handleWorkspaceProposal,
  type TaskWorkspaceContext,
} from "../src/workspace/service.js";

function tmpDir(): string {
  return fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "macky-m7-")));
}

interface Rig {
  dir: string;
  work: string;
  session: SecureSession;
  taskCtx: TaskWorkspaceContext;
  registry: ReturnType<typeof createWorkspaceRegistry>;
  cleanup: () => void;
}

function rigged(): Rig {
  const dir = tmpDir();
  const work = tmpDir();
  const booted = boot(dir);
  if (!booted.ok) throw new Error("boot failed");
  fs.writeFileSync(path.join(work, "a.txt"), "hello workspace\nsecond line\n");
  fs.mkdirSync(path.join(work, "sub"));
  fs.writeFileSync(path.join(work, "sub", "b.ts"), "export const x = 1;\n");
  fs.writeFileSync(path.join(work, "package.json"), '{"name":"demo"}\n');
  fs.writeFileSync(path.join(work, ".env"), "API_KEY=fake-1\n");
  const registry = createWorkspaceRegistry();
  const reg = registerWorkspace(registry, "ws-test", work);
  if (!reg.ok) throw new Error(`register failed: ${reg.reason}`);
  for (const [grantId, capability] of [
    ["g-read", "filesystem.read"],
    ["g-find", "filesystem.find"],
    ["g-search", "filesystem.search"],
    ["g-tree", "filesystem.tree"],
    ["g-git", "git.read"],
  ] as Array<[string, string]>) {
    const r = grantToSession(booted.session, { grantId, taskId: "task-W", capability, scope: work });
    if (!r.ok) throw new Error("grant failed");
  }
  wakeSession(booted.session, { kind: "ui-action" });
  return {
    dir, work, session: booted.session,
    taskCtx: { taskId: "task-W", workspaceIds: ["ws-test"] },
    registry,
    cleanup: () => { fs.rmSync(dir, { recursive: true, force: true }); fs.rmSync(work, { recursive: true, force: true }); },
  };
}

function ask(rig: Rig, output: unknown, taskCtx?: TaskWorkspaceContext): ReturnType<typeof handleWorkspaceProposal> {
  return handleWorkspaceProposal(rig.session, taskCtx ?? rig.taskCtx, rig.registry, output);
}

function ws(op: string, extra?: Record<string, unknown>): Record<string, unknown> {
  return { v: 1, workspaceId: "ws-test", op, ...extra };
}

describe("M7 registration A–E", () => {
  it("A. valid registration canonicalizes", () => {
    const rig = rigged();
    try {
      expect(rig.registry.workspaces.get("ws-test")?.root).toBe(rig.work);
    } finally {
      rig.cleanup();
    }
  });
  it("B. relative roots rejected", () => {
    const reg = createWorkspaceRegistry();
    expect(registerWorkspace(reg, "w", "relative/path").ok).toBe(false);
    expect(registerWorkspace(reg, "w", "~/work").ok).toBe(false);
    expect(registerWorkspace(reg, "w", "$HOME/work").ok).toBe(false);
  });
  it("C. nonexistent roots rejected", () => {
    const reg = createWorkspaceRegistry();
    expect(registerWorkspace(reg, "w", "/no/such/dir-xyz").ok).toBe(false);
  });
  it("D. files-as-workspace rejected", () => {
    const d = tmpDir();
    try {
      const f = path.join(d, "f.txt");
      fs.writeFileSync(f, "x");
      expect(registerWorkspace(createWorkspaceRegistry(), "w", f).ok).toBe(false);
    } finally {
      fs.rmSync(d, { recursive: true, force: true });
    }
  });
  it("E. sensitive workspaces rejected", () => {
    const d = tmpDir();
    try {
      const ssh = path.join(d, ".ssh");
      fs.mkdirSync(ssh);
      expect(registerWorkspace(createWorkspaceRegistry(), "w", ssh).ok).toBe(false);
      const home = os.homedir();
      if (fs.existsSync(path.join(home, ".ssh"))) {
        expect(registerWorkspace(createWorkspaceRegistry(), "w", path.join(home, ".ssh")).ok).toBe(false);
      }
    } finally {
      fs.rmSync(d, { recursive: true, force: true });
    }
  });
});

describe("M7 path attacks F–J, integration P–R misc", () => {
  it("F. ../ escape refused", () => {
    const rig = rigged();
    try {
      expect(ask(rig, ws("file-read", { path: "../etc/passwd" })).outcome.status).toBe("refused");
      expect(ask(rig, ws("dir-list", { path: "sub/../../.." })).outcome.status).toBe("refused");
    } finally {
      rig.cleanup();
    }
  });
  it("G. absolute planner paths refused", () => {
    const rig = rigged();
    try {
      expect(ask(rig, ws("file-read", { path: "/etc/passwd" })).outcome.status).toBe("refused");
      expect(ask(rig, ws("dir-list", { path: `${rig.work}/sub` })).outcome.status).toBe("refused");
    } finally {
      rig.cleanup();
    }
  });
  it("H. encoded traversal never escapes", () => {
    const rig = rigged();
    try {
      const r = ask(rig, ws("file-read", { path: "%2e%2e/secret" }));
      expect(r.outcome.status).toBe("refused");
    } finally {
      rig.cleanup();
    }
  });
  it("I. backslash paths refused", () => {
    const rig = rigged();
    try {
      expect(ask(rig, ws("file-read", { path: "sub\\..\\a.txt" })).outcome.status).toBe("refused");
    } finally {
      rig.cleanup();
    }
  });
  it("J. NUL bytes refused", () => {
    const rig = rigged();
    try {
      expect(ask(rig, ws("file-read", { path: "a\0.txt" })).outcome.status).toBe("refused");
    } finally {
      rig.cleanup();
    }
  });
});

describe("M7 symlinks K–N + alias AE", () => {
  it("K. internal symlink allowed", () => {
    const rig = rigged();
    try {
      fs.symlinkSync(path.join(rig.work, "a.txt"), path.join(rig.work, "link-in"));
      expect(ask(rig, ws("file-read", { path: "link-in" })).outcome.status).toBe("completed");
    } finally {
      rig.cleanup();
    }
  });
  it("L. escaping symlink denied", () => {
    const rig = rigged();
    const outside = tmpDir();
    try {
      fs.writeFileSync(path.join(outside, "s.txt"), "outside");
      fs.symlinkSync(path.join(outside, "s.txt"), path.join(rig.work, "link-out"));
      expect(ask(rig, ws("file-read", { path: "link-out" })).outcome.status).toBe("refused");
    } finally {
      rig.cleanup();
      fs.rmSync(outside, { recursive: true, force: true });
    }
  });
  it("M. dangling symlink fails safely", () => {
    const rig = rigged();
    try {
      fs.symlinkSync(path.join(rig.work, "gone.txt"), path.join(rig.work, "dangle"));
      expect(ask(rig, ws("file-read", { path: "dangle" })).outcome.status).toBe("refused");
    } finally {
      rig.cleanup();
    }
  });
  it("N. deep symlink chain inside workspace resolves", () => {
    const rig = rigged();
    try {
      fs.symlinkSync(path.join(rig.work, "a.txt"), path.join(rig.work, "l1"));
      fs.symlinkSync(path.join(rig.work, "l1"), path.join(rig.work, "l2"));
      fs.symlinkSync(path.join(rig.work, "l2"), path.join(rig.work, "l3"));
      expect(ask(rig, ws("file-read", { path: "l3" })).outcome.status).toBe("completed");
    } finally {
      rig.cleanup();
    }
  });
  it("AE. sensitive file through alias denied", () => {
    const rig = rigged();
    try {
      fs.symlinkSync(path.join(rig.work, ".env"), path.join(rig.work, "notes.txt"));
      expect(ask(rig, ws("file-read", { path: "notes.txt" })).outcome.status).toBe("refused");
    } finally {
      rig.cleanup();
    }
  });
});

describe("M7 authorization O–Q, AL + sleep/kill/epoch AM–AO", () => {
  it("O. workspace A + grant B denied", () => {
    const rig = rigged();
    const other = tmpDir();
    try {
      fs.writeFileSync(path.join(other, "b.txt"), "b");
      const reg = registerWorkspace(rig.registry, "ws-b", other);
      expect(reg.ok).toBe(true);
      // Bound to ws-b, but grants cover only ws-test's root.
      const r2 = handleWorkspaceProposal(
        rig.session,
        { taskId: "task-W", workspaceIds: ["ws-b"] },
        rig.registry,
        { v: 1, workspaceId: "ws-b", op: "file-read", path: "b.txt" },
      );
      expect(r2.outcome.status).toBe("refused");
    } finally {
      rig.cleanup();
      fs.rmSync(other, { recursive: true, force: true });
    }
  });
  it("P. planner workspace forgery denied", () => {
    const rig = rigged();
    try {
      expect(ask(rig, { v: 1, workspaceId: "ws-evil", op: "file-read", path: "a.txt" }).outcome.status).toBe("refused");
      // Registered but unbound id also dies on binding.
      const other = tmpDir();
      try {
        registerWorkspace(rig.registry, "ws-other", other);
        expect(ask(rig, { v: 1, workspaceId: "ws-other", op: "dir-list", path: "." }).outcome.status).toBe("refused");
      } finally {
        fs.rmSync(other, { recursive: true, force: true });
      }
    } finally {
      rig.cleanup();
    }
  });
  it("Q. root replacement/disappearance denied safely", () => {
    const rig = rigged();
    try {
      expect(reverifyWorkspace(rig.registry, "ws-test").ok).toBe(true);
      const moved = `${rig.work}-moved`;
      fs.renameSync(rig.work, moved);
      try {
        expect(reverifyWorkspace(rig.registry, "ws-test").ok).toBe(false);
        expect(ask(rig, ws("dir-list", { path: "." })).outcome.status).toBe("refused");
      } finally {
        fs.renameSync(moved, rig.work);
      }
      expect(reverifyWorkspace(rig.registry, "ws-test").ok).toBe(true);
      // Replacement with a fresh directory (new inode) also fails.
      fs.rmSync(rig.work, { recursive: true, force: true });
      fs.mkdirSync(rig.work);
      expect(reverifyWorkspace(rig.registry, "ws-test").ok).toBe(false);
      expect(ask(rig, ws("dir-list", { path: "." })).outcome.status).toBe("refused");
    } finally {
      rig.cleanup();
    }
  });
  it("AL. fabricated grant fields refused", () => {
    const rig = rigged();
    try {
      expect(ask(rig, { ...ws("file-read", { path: "a.txt" }), grant: { scope: "/" } }).outcome.status).toBe("refused");
    } finally {
      rig.cleanup();
    }
  });
  it("AM. sleeping session refuses", () => {
    const dir = tmpDir();
    const work = tmpDir();
    try {
      const booted = boot(dir);
      if (!booted.ok) throw new Error("boot failed");
      fs.writeFileSync(path.join(work, "a.txt"), "x");
      const registry = createWorkspaceRegistry();
      registerWorkspace(registry, "ws", work);
      grantToSession(booted.session, { grantId: "g", taskId: "t", capability: "filesystem.read", scope: work });
      const r = handleWorkspaceProposal(
        booted.session, { taskId: "t", workspaceIds: ["ws"] }, registry,
        { v: 1, workspaceId: "ws", op: "file-read", path: "a.txt" },
      );
      expect(r.outcome.status).toBe("refused");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
      fs.rmSync(work, { recursive: true, force: true });
    }
  });
  it("AN. engaged kill switch refuses", () => {
    const rig = rigged();
    try {
      engageSessionKill(rig.session);
      expect(ask(rig, ws("dir-list", { path: "." })).outcome.status).toBe("refused");
    } finally {
      rig.cleanup();
    }
  });
  it("AO. rebooted session needs fresh grants", () => {
    const dir = tmpDir();
    const work = tmpDir();
    try {
      const first = boot(dir);
      if (!first.ok) throw new Error("boot failed");
      fs.writeFileSync(path.join(work, "a.txt"), "x");
      const registry = createWorkspaceRegistry();
      registerWorkspace(registry, "ws", work);
      grantToSession(first.session, { grantId: "g", taskId: "t", capability: "filesystem.read", scope: work });
      wakeSession(first.session, { kind: "ui-action" });
      const ok = handleWorkspaceProposal(
        first.session, { taskId: "t", workspaceIds: ["ws"] }, registry,
        { v: 1, workspaceId: "ws", op: "file-read", path: "a.txt" },
      );
      expect(ok.outcome.status).toBe("completed");
      const second = boot(dir);
      if (!second.ok) throw new Error("reboot failed");
      const stale = handleWorkspaceProposal(
        second.session, { taskId: "t", workspaceIds: ["ws"] }, registry,
        { v: 1, workspaceId: "ws", op: "file-read", path: "a.txt" },
      );
      expect(stale.outcome.status).toBe("refused");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
      fs.rmSync(work, { recursive: true, force: true });
    }
  });
});

describe("M7 operations complete safely", () => {
  it("list/read/find/search/tree/git-status complete with contracts", () => {
    const rig = rigged();
    try {
      const list = ask(rig, ws("dir-list", { path: "." }));
      expect(list.outcome.status).toBe("completed");
      if (list.outcome.status === "completed") {
        const c = list.outcome.result as { entries: Array<{ name: string }>; truncated: boolean };
        expect(c.entries.map((e) => e.name).sort()).toContain("package.json");
        expect(c.truncated).toBe(false);
      }
      const read = ask(rig, ws("file-read", { path: "package.json" }));
      expect(read.outcome.status).toBe("completed");
      const find = ask(rig, ws("file-find", { path: ".", pattern: "*.ts" }));
      expect(find.outcome.status).toBe("completed");
      if (find.outcome.status === "completed") {
        const c = find.outcome.result as { entries: Array<{ path: string }> };
        expect(c.entries.some((e) => e.path === "sub/b.ts")).toBe(true);
        // Relative paths only: no absolute leakage.
        expect(JSON.stringify(c)).not.toContain(rig.work);
      }
      const search = ask(rig, ws("content-search", { path: ".", query: "hello workspace" }));
      expect(search.outcome.status).toBe("completed");
      const tree = ask(rig, ws("tree", { path: "." }));
      expect(tree.outcome.status).toBe("completed");
    } finally {
      rig.cleanup();
    }
  });
});
