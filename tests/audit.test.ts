import { describe, expect, it } from "vitest";
import * as audit from "../src/kernel/audit.js";
import { appendEvent, createLog } from "../src/kernel/audit.js";

describe("audit log: append-only, never disabled (S9)", () => {
  it("exposes no disable/clear/remove/reorder API", () => {
    const names = Object.keys(audit).map((k) => k.toLowerCase());
    for (const forbidden of ["disable", "clear", "remove", "delete", "reset"]) {
      expect(
        names.some((n) => n.includes(forbidden)),
        `must not export anything like "${forbidden}"`,
      ).toBe(false);
    }
  });

  it("appends immutably with monotonic sequence numbers", () => {
    const log0 = createLog();
    const log1 = appendEvent(log0, {
      type: "sleep.enter",
      detail: "entered sleep",
      sleepState: "SLEEP",
    });
    const log2 = appendEvent(log1, {
      type: "wake.request",
      detail: "keyboard-shortcut",
      sleepState: "AWAKE",
    });
    expect(log0.events).toHaveLength(0);
    expect(log1.events).toHaveLength(1);
    expect(log2.events.map((e) => e.seq)).toEqual([1, 2]);
  });

  it("freezes logs and events against mutation", () => {
    const log = appendEvent(createLog(), {
      type: "t",
      detail: "d",
      sleepState: "SLEEP",
    });
    expect(Object.isFrozen(log)).toBe(true);
    expect(Object.isFrozen(log.events)).toBe(true);
  });
});
