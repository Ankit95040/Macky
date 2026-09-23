import { describe, expect, it } from "vitest";
import {
  needsConfirmation,
  resolveConfirmation,
  riskOf,
} from "../src/kernel/confirm.js";

describe("confirmation gate (S12)", () => {
  it("requires confirmation for high/medium/unknown risk", () => {
    expect(needsConfirmation("high")).toBe(true);
    expect(needsConfirmation("medium")).toBe(true);
    expect(needsConfirmation("low")).toBe(false);
    expect(needsConfirmation(undefined)).toBe(true);
    expect(needsConfirmation("critical")).toBe(true);
  });

  it("rejects planner self-approval", () => {
    const pending = {
      verdict: "require-confirmation" as const,
      reason: "test",
    };
    expect(
      resolveConfirmation(pending, { approved: true, responder: "planner" })
        .verdict,
    ).toBe("deny");
    expect(
      resolveConfirmation(pending, { approved: true, responder: "llm" })
        .verdict,
    ).toBe("deny");
  });

  it("honors explicit human approval and decline", () => {
    const pending = {
      verdict: "require-confirmation" as const,
      reason: "test",
    };
    expect(
      resolveConfirmation(pending, { approved: true, responder: "human" })
        .verdict,
    ).toBe("allow");
    expect(
      resolveConfirmation(pending, { approved: false, responder: "human" })
        .verdict,
    ).toBe("deny");
  });

  it("fails closed on malformed responses", () => {
    const pending = {
      verdict: "require-confirmation" as const,
      reason: "test",
    };
    expect(resolveConfirmation(pending, null).verdict).toBe("deny");
    expect(
      resolveConfirmation(pending, { responder: "human" }).verdict,
    ).toBe("deny");
    expect(resolveConfirmation(pending, "yes").verdict).toBe("deny");
  });

  it("passes through non-pending decisions untouched", () => {
    const allowed = { verdict: "allow" as const, reason: "test" };
    expect(resolveConfirmation(allowed, null)).toEqual(allowed);
  });

  it("classifies risk conservatively", () => {
    expect(riskOf("low")).toBe("low");
    expect(riskOf("nonsense")).toBeUndefined();
    expect(riskOf(undefined)).toBeUndefined();
  });
});
