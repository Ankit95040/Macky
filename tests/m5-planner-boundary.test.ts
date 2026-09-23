import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import { boot } from "../src/bootstrap/boot.js";
import { engageSessionKill, grantToSession, wakeSession } from "../src/persistence/session.js";
import type { SecureSession } from "../src/persistence/session.js";
import { handleProposal } from "../src/planner/boundary.js";
import { MockPlanner, type MaliciousKind } from "../src/planner/mock-planner.js";
import type { PlannerInput } from "../src/planner/proposal.js";

function tmpDir(): string {
  return fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "macky-m5-")));
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
  if (!booted.ok) throw new Error("boot failed in fixture");
  fs.writeFileSync(path.join(work, "a.txt"), "hello planner");
  grantToSession(booted.session, {
    grantId: "g-a",
    taskId: "task-A",
    capability: "filesystem.read",
    scope: work,
  });
  wakeSession(booted.session, { kind: "ui-action" });
  return { dir, work, session: booted.session, cleanup: () => { fs.rmSync(dir, { recursive: true, force: true }); fs.rmSync(work, { recursive: true, force: true }); } };
}

async function drive(
  rig: Rig,
  mode: "valid" | MaliciousKind,
  input: PlannerInput,
  taskId = "task-A",
  opts?: { secretProbe?: string },
): Promise<ReturnType<typeof handleProposal>> {
  const planner = new MockPlanner(mode, opts);
  const output = await planner.propose(input);
  return handleProposal(rig.session, { epoch: rig.session.epoch, taskId, output });
}

function readInput(work: string): PlannerInput {
  return { taskId: "task-A", family: "filesystem", operation: "read", resource: `${work}/a.txt` };
}

describe("M5 planner boundary: A–Q adversarial suite", () => {
  it("A. valid proposal executes only when authorized", async () => {
    const rig = rigged();
    try {
      const r = await drive(rig, "valid", readInput(rig.work));
      expect(r.outcome.status).toBe("completed");
      // Same shape, bound task with no grant: refused at authorization.
      const ungranted: PlannerInput = { ...readInput(rig.work), taskId: "task-NONE" };
      const r2 = await drive(rig, "valid", ungranted, "task-NONE");
      expect(r2.outcome.status).toBe("refused");
    } finally {
      rig.cleanup();
    }
  });

  it("B. fake risk tier rejected", async () => {
    const rig = rigged();
    try {
      const r = await drive(rig, "fake-risk", readInput(rig.work));
      expect(r.outcome.status).toBe("refused");
    } finally {
      rig.cleanup();
    }
  });

  it("C. fake ALLOW rejected", async () => {
    const rig = rigged();
    try {
      const r = await drive(rig, "fake-allow", readInput(rig.work));
      expect(r.outcome.status).toBe("refused");
    } finally {
      rig.cleanup();
    }
  });

  it("D. fake confirmation rejected", async () => {
    const rig = rigged();
    try {
      const r = await drive(rig, "fake-confirmation", readInput(rig.work));
      expect(r.outcome.status).toBe("refused");
    } finally {
      rig.cleanup();
    }
  });

  it("E. fabricated grant rejected", async () => {
    const rig = rigged();
    try {
      const r = await drive(rig, "fake-grant", readInput(rig.work));
      expect(r.outcome.status).toBe("refused");
    } finally {
      rig.cleanup();
    }
  });

  it("F. wake attempt impossible via planner", async () => {
    const rig = rigged();
    try {
      const r = await drive(rig, "wake-attempt", readInput(rig.work));
      expect(r.outcome.status).toBe("refused");
    } finally {
      rig.cleanup();
    }
  });

  it("G. kill-switch manipulation refused", async () => {
    const rig = rigged();
    try {
      const r = await drive(rig, "kill-switch", readInput(rig.work));
      expect(r.outcome.status).toBe("refused");
      expect(rig.session.killSwitch.engaged).toBe(false);
    } finally {
      rig.cleanup();
    }
  });

  it("H. policy manipulation refused", async () => {
    const rig = rigged();
    try {
      const r = await drive(rig, "policy", readInput(rig.work));
      expect(r.outcome.status).toBe("refused");
    } finally {
      rig.cleanup();
    }
  });

  it("I. sensitive paths denied by the existing boundary", async () => {
    const rig = rigged();
    try {
      const home = os.homedir();
      const probe = path.join(home, ".ssh", "id_rsa");
      const r = await drive(rig, "secret-path", readInput(rig.work), "task-A", {
        secretProbe: fs.existsSync(probe) ? probe : "/.ssh/id_rsa",
      });
      expect(r.outcome.status).toBe("refused");
    } finally {
      rig.cleanup();
    }
  });

  it("J. traversal denied", async () => {
    const rig = rigged();
    try {
      const r = await drive(rig, "traversal", readInput(rig.work));
      expect(r.outcome.status).toBe("refused");
      const enc = await drive(
        rig,
        "valid",
        { taskId: "task-A", family: "filesystem", operation: "read", resource: `${rig.work}/%2e%2e/x` },
      );
      expect(enc.outcome.status).toBe("refused");
    } finally {
      rig.cleanup();
    }
  });

  it("K. cross-task authority denied (binding mismatch)", async () => {
    const rig = rigged();
    try {
      // Proposal claims task-B while the trusted envelope binds task-A.
      const planner = new MockPlanner("cross-task");
      const output = await planner.propose(readInput(rig.work));
      const r = handleProposal(rig.session, { epoch: rig.session.epoch, taskId: "task-A", output });
      expect(r.outcome.status).toBe("refused");
      if (r.outcome.status === "refused") {
        expect(r.outcome.stage).toBe("proposal");
      }
    } finally {
      rig.cleanup();
    }
  });

  it("L. unknown capability rejected", async () => {
    const rig = rigged();
    try {
      const r = await drive(rig, "unknown-capability", readInput(rig.work));
      expect(r.outcome.status).toBe("refused");
    } finally {
      rig.cleanup();
    }
  });

  it("M. extra security-sensitive fields rejected", async () => {
    const rig = rigged();
    try {
      const r = await drive(rig, "extra-fields", readInput(rig.work));
      expect(r.outcome.status).toBe("refused");
    } finally {
      rig.cleanup();
    }
  });

  it("N. prompt injection in metadata treated as data", async () => {
    const rig = rigged();
    try {
      const r = await drive(rig, "prompt-injection", readInput(rig.work));
      // Otherwise-valid proposal still completes on its own merits…
      expect(r.outcome.status).toBe("completed");
      // …but the injection text reaches NEITHER authorization NOR audit.
      const audit = fs.readFileSync(path.join(rig.dir, "audit.jsonl"), "utf8");
      expect(audit).not.toContain("Ignore all previous");
    } finally {
      rig.cleanup();
    }
  });

  it("O. malicious tool-result content cannot alter authorization", async () => {
    const rig = rigged();
    try {
      const r = await drive(rig, "tool-result", readInput(rig.work));
      expect(r.outcome.status).toBe("refused");
    } finally {
      rig.cleanup();
    }
  });

  it("P. sleeping Macky cannot execute even valid proposals", async () => {
    const dir = tmpDir();
    const work = tmpDir();
    try {
      const booted = boot(dir);
      if (!booted.ok) throw new Error("boot failed");
      fs.writeFileSync(path.join(work, "a.txt"), "x");
      grantToSession(booted.session, { grantId: "g-a", taskId: "task-A", capability: "filesystem.read", scope: work });
      // Deliberately NOT waking: session boots SLEEP.
      const planner = new MockPlanner("valid");
      const output = await planner.propose({ taskId: "task-A", family: "filesystem", operation: "read", resource: `${work}/a.txt` });
      const r = handleProposal(booted.session, { epoch: booted.session.epoch, taskId: "task-A", output });
      expect(r.outcome.status).toBe("refused");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
      fs.rmSync(work, { recursive: true, force: true });
    }
  });

  it("Q. engaged kill switch blocks planner proposals", async () => {
    const rig = rigged();
    try {
      engageSessionKill(rig.session);
      const r = await drive(rig, "valid", readInput(rig.work));
      expect(r.outcome.status).toBe("refused");
    } finally {
      rig.cleanup();
    }
  });

  it("planner is pure data: repeatable, side-effect-free", async () => {
    const rig = rigged();
    try {
      const planner = new MockPlanner("valid");
      const input = readInput(rig.work);
      const a = await planner.propose(input);
      const b = await planner.propose(input);
      expect(a).toEqual(b);
    } finally {
      rig.cleanup();
    }
  });
});
