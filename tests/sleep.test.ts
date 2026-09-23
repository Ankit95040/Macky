import { describe, expect, it } from "vitest";
import {
  allGatedCategories,
  enterSleep,
  initialSleepState,
  isCategoryAllowed,
  requestWake,
} from "../src/kernel/sleep.js";

describe("SLEEP state machine (SLEEP_SPEC.md, normative)", () => {
  it("starts in SLEEP — never in an observing state (SL3)", () => {
    expect(initialSleepState()).toBe("SLEEP");
  });

  it("restart is construction: always SLEEP, no auto-wake (SL4)", () => {
    expect(initialSleepState()).toBe("SLEEP");
    expect(initialSleepState()).toBe("SLEEP");
  });

  it("denies ALL 12 gated categories while asleep (SL1/SL2)", () => {
    const cats = allGatedCategories();
    expect(cats).toHaveLength(12);
    for (const c of cats) {
      expect(isCategoryAllowed("SLEEP", c)).toBe(false);
    }
  });

  it("wakes on explicit keyboard shortcut (SL5)", () => {
    expect(requestWake("SLEEP", { kind: "keyboard-shortcut" })).toBe("AWAKE");
  });

  it("wakes on explicit UI action (SL5)", () => {
    expect(requestWake("SLEEP", { kind: "ui-action" })).toBe("AWAKE");
  });

  it("rejects wake-word: no always-listening wake path (SL5)", () => {
    expect(requestWake("SLEEP", { kind: "wake-word" })).toBe("SLEEP");
  });

  it("fails closed on garbage wake input", () => {
    expect(requestWake("SLEEP", undefined)).toBe("SLEEP");
    expect(requestWake("SLEEP", null)).toBe("SLEEP");
    expect(requestWake("SLEEP", "awake")).toBe("SLEEP");
    expect(requestWake("SLEEP", {})).toBe("SLEEP");
    expect(requestWake("SLEEP", { kind: "KEYBOARD-SHORTCUT" })).toBe("SLEEP");
  });

  it("sleep is always available from any state (SL6)", () => {
    expect(enterSleep("AWAKE")).toBe("SLEEP");
    expect(enterSleep("SLEEP")).toBe("SLEEP");
  });

  it("wake is idempotent when already awake", () => {
    expect(requestWake("AWAKE", { kind: "keyboard-shortcut" })).toBe("AWAKE");
  });

  it("awake still denies observation/inference categories (SL7)", () => {
    for (const c of [
      "microphone-capture",
      "screen-capture",
      "screen-recording",
      "keyboard-monitoring",
      "mouse-monitoring",
      "filesystem-watchers",
      "browser-monitoring",
      "llm-inference",
    ] as const) {
      expect(isCategoryAllowed("AWAKE", c)).toBe(false);
    }
  });
});
