import { describe, expect, it } from "vitest";
import { evaluateProposal } from "../src/kernel/policy.js";

describe("policy engine: default-deny + fail-closed (S1/S4/S5/S14)", () => {
  it("denies unknown capabilities (S1/S3)", () => {
    expect(
      evaluateProposal(
        { action: "read-files", capability: "fs.read-all" },
        { sleep: "AWAKE" },
      ).verdict,
    ).toBe("deny");
    expect(
      evaluateProposal(
        { action: "x", capability: "shell.exec" },
        { sleep: "AWAKE" },
      ).verdict,
    ).toBe("deny");
  });

  it("denies schema-invalid planner output (S4/S5)", () => {
    expect(evaluateProposal(null, { sleep: "AWAKE" }).verdict).toBe("deny");
    expect(evaluateProposal({}, { sleep: "AWAKE" }).verdict).toBe("deny");
    expect(
      evaluateProposal(
        { action: "", capability: "system.sleep" },
        { sleep: "AWAKE" },
      ).verdict,
    ).toBe("deny");
  });

  it("rejects planner self-approval smuggled as extra fields (S5/S12)", () => {
    expect(
      evaluateProposal(
        {
          action: "do-risky-thing",
          capability: "system.sleep",
          approved: true,
          responder: "planner",
        },
        { sleep: "AWAKE" },
      ).verdict,
    ).toBe("deny");
  });

  it("sleep gate denies gated categories while asleep (SL1)", () => {
    const d = evaluateProposal(
      {
        action: "listen",
        capability: "system.sleep",
        category: "microphone-capture",
      },
      { sleep: "SLEEP" },
    );
    expect(d.verdict).toBe("deny");
  });

  it("grants only the minimal M1 low-risk set; everything else denies", () => {
    expect(
      evaluateProposal(
        { action: "sleep", capability: "system.sleep" },
        { sleep: "AWAKE" },
      ).verdict,
    ).toBe("allow");
    expect(
      evaluateProposal(
        { action: "log", capability: "audit.append" },
        { sleep: "SLEEP" },
      ).verdict,
    ).toBe("allow");
    expect(
      evaluateProposal(
        { action: "inspect", capability: "audit.read", risk: "high" },
        { sleep: "AWAKE" },
      ).verdict,
    ).toBe("require-confirmation");
  });
});
