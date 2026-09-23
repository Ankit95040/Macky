import { describe, expect, it } from "vitest";
import * as capabilitiesModule from "../src/kernel/capabilities.js";
import { CAPABILITIES, getCapability } from "../src/kernel/capabilities.js";

describe("capabilities: declarations only, no OS surface (S3/S15)", () => {
  it("declares only the minimal M1 set", () => {
    expect(CAPABILITIES.map((c) => c.id).sort()).toEqual([
      "audit.append",
      "audit.read",
      "system.sleep",
    ]);
  });

  it("returns undefined for anything undeclared (caller must deny)", () => {
    expect(getCapability("shell.exec")).toBeUndefined();
    expect(getCapability("fs.read")).toBeUndefined();
    expect(getCapability("network.fetch")).toBeUndefined();
    expect(getCapability("browser.control")).toBeUndefined();
  });

  it("exposes no executable OS surface", () => {
    const names = Object.keys(capabilitiesModule).map((k) => k.toLowerCase());
    for (const forbidden of ["exec", "spawn", "shell", "fetch", "automation"]) {
      expect(
        names.some((n) => n.includes(forbidden)),
        `must not export anything like "${forbidden}"`,
      ).toBe(false);
    }
  });

  it("every declaration carries an explicit boundary (S15)", () => {
    for (const c of CAPABILITIES) {
      expect(c.risk).toMatch(/^(low|medium|high)$/);
      expect(typeof c.requiresConfirmation).toBe("boolean");
      expect(typeof c.sleepGated).toBe("boolean");
      expect(c.description.length).toBeGreaterThan(0);
    }
  });
});
