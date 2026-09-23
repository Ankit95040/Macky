import { describe, expect, it } from "vitest";
import * as executorModule from "../src/executor/executor.js";
import { run } from "../src/executor/executor.js";
import { authorize } from "../src/kernel/authorize.js";
import {
  createKillSwitch,
  disengageKillSwitch,
  engageKillSwitch,
  isEngaged,
} from "../src/kernel/kill-switch.js";
import { enterSleep } from "../src/kernel/sleep.js";
import {
  makeExecCtx,
  makeSandbox,
  reachedOs,
  readReq,
} from "./m3-fixtures.js";

describe("M3 sleep: execution stops even with prior authorization", () => {
  it("valid read → sleep → execution denied", () => {
    const sb = makeSandbox({ "a.txt": "A" });
    try {
      const awake = makeExecCtx(sb.root);
      const req = readReq(`${sb.root}/a.txt`);
      expect(run(req, awake.ctx).outcome.status).toBe("completed");

      const asleep = { ...awake.ctx, sleep: enterSleep(awake.ctx.sleep) };
      const r = run(req, asleep);
      expect(r.outcome.status).toBe("refused");
      if (r.outcome.status === "refused") {
        expect(r.outcome.stage).toBe("authorization");
      }
      expect(reachedOs(r.log)).toBe(false);
    } finally {
      sb.cleanup();
    }
  });

  it("stale standalone authorization cannot execute while asleep", () => {
    const sb = makeSandbox({ "a.txt": "A" });
    try {
      const awake = makeExecCtx(sb.root);
      const req = readReq(`${sb.root}/a.txt`);
      // A prior standalone ALLOW exists...
      const prior = authorize(req, { ...awake.ctx });
      expect(prior.decision.verdict).toBe("allow");
      // ...but the executor re-authorizes at call time: asleep denies.
      const r = run(req, { ...awake.ctx, sleep: "SLEEP" });
      expect(r.outcome.status).toBe("refused");
      expect(reachedOs(r.log)).toBe(false);
    } finally {
      sb.cleanup();
    }
  });

  it("no wake path exists through the executor", () => {
    const sb = makeSandbox({ "a.txt": "A" });
    try {
      const names = Object.keys(executorModule).map((k) => k.toLowerCase());
      expect(names.some((n) => n.includes("wake"))).toBe(false);
      const asleep = makeExecCtx(sb.root, { sleep: "SLEEP" });
      const r = run(readReq(`${sb.root}/a.txt`), asleep.ctx);
      expect(r.outcome.status).toBe("refused");
      // Nothing woke: no wake event, every event still marked SLEEP.
      expect(r.log.events.some((e) => e.type === "sleep.woken")).toBe(false);
      expect(r.log.events.every((e) => e.sleepState === "SLEEP")).toBe(true);
    } finally {
      sb.cleanup();
    }
  });
});

describe("M3 kill switch: engaged denies; planner cannot disengage", () => {
  it("kernel unit: engage/disengage/trusted-key semantics", () => {
    const ks = createKillSwitch();
    expect(isEngaged(ks.state)).toBe(false);
    const engaged = engageKillSwitch(ks.state);
    expect(isEngaged(engaged)).toBe(true);
    // Wrong key fails closed.
    expect(isEngaged(disengageKillSwitch(engaged, { token: -1 }, ks.key))).toBe(
      true,
    );
    expect(isEngaged(disengageKillSwitch(engaged, null, ks.key))).toBe(true);
    // Exact trusted key disengages.
    expect(isEngaged(disengageKillSwitch(engaged, ks.key, ks.key))).toBe(false);
  });

  it("engaged switch denies an otherwise authorized read", () => {
    const sb = makeSandbox({ "a.txt": "A" });
    try {
      const ks = createKillSwitch();
      const off = makeExecCtx(sb.root, { kill: ks.state });
      expect(run(readReq(`${sb.root}/a.txt`), off.ctx).outcome.status).toBe(
        "completed",
      );
      const on = makeExecCtx(sb.root, { kill: engageKillSwitch(ks.state) });
      const r = run(readReq(`${sb.root}/a.txt`), on.ctx);
      expect(r.outcome.status).toBe("refused");
      if (r.outcome.status === "refused") {
        expect(r.outcome.stage).toBe("kill-switch");
      }
      expect(reachedOs(r.log)).toBe(false);
    } finally {
      sb.cleanup();
    }
  });

  it("planner-shaped kill-switch fields have zero authority", () => {
    const sb = makeSandbox({ "a.txt": "A" });
    try {
      const ks = createKillSwitch();
      const on = makeExecCtx(sb.root, { kill: engageKillSwitch(ks.state) });
      for (const forgery of [
        { killSwitch: false },
        { disengage: true },
        { killSwitch: { engaged: false } },
      ]) {
        const r = run(
          { ...readReq(`${sb.root}/a.txt`), ...forgery },
          on.ctx,
        );
        expect(r.outcome.status, JSON.stringify(forgery)).toBe("refused");
      }
    } finally {
      sb.cleanup();
    }
  });
});
