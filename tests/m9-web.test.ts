import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import { boot } from "../src/bootstrap/boot.js";
import {
  engageSessionKill,
  grantToSession,
  revokeSessionGrant,
  wakeSession,
} from "../src/persistence/session.js";
import type { SecureSession } from "../src/persistence/session.js";
import { MockWebProvider } from "../src/web/mock-provider.js";
import type { WebSearchProvider } from "../src/web/provider.js";
import { handleWebProposal } from "../src/web/service.js";
import { tryAcquireWebSlot, releaseWebSlot } from "../src/web/service.js";
import { WEB_LIMITS } from "../src/web/limits.js";

function tmpDir(): string {
  return fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "macky-m9-")));
}

interface Rig {
  dir: string;
  session: SecureSession;
  cleanup: () => void;
}

function rigged(taskId = "task-W"): Rig {
  const dir = tmpDir();
  const booted = boot(dir);
  if (!booted.ok) throw new Error("boot failed");
  for (const [grantId, capability] of [
    ["g-search", "web.search"],
    ["g-fetch", "web.fetch"],
  ] as Array<[string, string]>) {
    const r = grantToSession(booted.session, { grantId, taskId, capability, scope: "" });
    if (!r.ok) throw new Error("grant failed");
  }
  wakeSession(booted.session, { kind: "ui-action" });
  return { dir, session: booted.session, cleanup: () => { fs.rmSync(dir, { recursive: true, force: true }); } };
}

function ask(
  rig: Rig,
  provider: WebSearchProvider,
  output: unknown,
  taskId = "task-W",
  opts?: { timeoutMs?: number },
): ReturnType<typeof handleWebProposal> {
  return handleWebProposal(rig.session, { taskId }, provider, output, opts);
}

function search(query: string, extra?: Record<string, unknown>): Record<string, unknown> {
  return { v: 1, operation: "web-search", query, ...extra };
}

function fetch(url: string, extra?: Record<string, unknown>): Record<string, unknown> {
  return { v: 1, operation: "web-fetch", url, ...extra };
}

describe("M9 search/fetch happy path A", () => {
  it("A. valid search and fetch complete bounded", async () => {
    const rig = rigged();
    try {
      const provider = new MockWebProvider("ok");
      const s = await ask(rig, provider, search("example query", { maxResults: 2 }));
      expect(s.outcome.status).toBe("completed");
      if (s.outcome.status === "completed") {
        const c = s.outcome.result as { results: unknown[]; truncated: boolean };
        expect(c.results.length).toBe(2);
        expect(c.truncated).toBe(false);
      }
      const f = await ask(rig, provider, fetch("https://example.com/page"));
      expect(f.outcome.status).toBe("completed");
      if (f.outcome.status === "completed") {
        expect((f.outcome.result as { body: string }).body).toContain("Fixture page");
      }
    } finally {
      rig.cleanup();
    }
  });
});

describe("M9 proposal forgery B–M, AN–AP", () => {
  it("B/C. oversized maxResults/query refused, never clamped", async () => {
    const rig = rigged();
    try {
      const provider = new MockWebProvider("ok");
      expect((await ask(rig, provider, search("q", { maxResults: 11 }))).outcome.status).toBe("refused");
      expect((await ask(rig, provider, search("x".repeat(513)))).outcome.status).toBe("refused");
      expect((await ask(rig, provider, search(""))).outcome.status).toBe("refused");
    } finally {
      rig.cleanup();
    }
  });
  it("D–M, AN–AP. forged/unknown/trusted fields refused", async () => {
    const rig = rigged();
    try {
      const provider = new MockWebProvider("ok");
      const bad: Array<[string, unknown]> = [
        ["unknown-field", { ...search("q"), risk: "tier0" }],
        ["capability", { ...search("q"), capability: "web.search" }],
        ["risk", { ...fetch("https://example.com/"), riskTier: 0 }],
        ["provider", { ...search("q"), provider: "evil" }],
        ["timeout", { ...search("q"), timeoutMs: 99999 }],
        ["headers", { ...fetch("https://example.com/"), headers: { "X-Evil": "1" } }],
        ["cookies", { ...fetch("https://example.com/"), cookies: "a=b" }],
        ["auth", { ...fetch("https://example.com/"), auth: "token" }],
        ["method", { ...fetch("https://example.com/"), method: "POST" }],
        ["post-op", { v: 1, operation: "web-post", query: "q" }],
        ["browser", { v: 1, operation: "browser-control", url: "https://example.com/" }],
        ["task-authority", { ...search("q"), taskId: "task-VICTIM", grant: {} }],
      ];
      for (const [name, output] of bad) {
        const r = await ask(rig, provider, output);
        expect(r.outcome.status, name).toBe("refused");
      }
    } finally {
      rig.cleanup();
    }
  });
});

describe("M9 URL policy N–AA", () => {
  it("N–Q. non-https schemes refused", async () => {
    const rig = rigged();
    try {
      const provider = new MockWebProvider("ok");
      for (const url of [
        "http://example.com/", "file:///etc/passwd", "data:text/plain,hi",
        "javascript:alert(1)", "ftp://example.com/x", "ws://example.com/",
      ]) {
        expect((await ask(rig, provider, fetch(url))).outcome.status, url).toBe("refused");
      }
    } finally {
      rig.cleanup();
    }
  });
  it("R–X. localhost/loopback/private/link-local refused, boundaries precise", async () => {
    const rig = rigged();
    try {
      const provider = new MockWebProvider("ok");
      for (const url of [
        "https://localhost/", "https://LOCALHOST/", "https://x.localhost/",
        "https://127.0.0.1/", "https://0x7f.0.0.1/", "https://2130706433/",
        "https://10.1.2.3/", "https://172.16.5.4/", "https://172.31.255.1/",
        "https://192.168.1.1/", "https://169.254.169.254/", "https://[::1]/",
        "https://[fe80::1]/", "https://[ff02::1]/", "https://[2001:db8::1]/",
      ]) {
        expect((await ask(rig, provider, fetch(url))).outcome.status, url).toBe("refused");
      }
      // Adjacent public ranges still pass URL policy (authority decides).
      for (const url of ["https://172.15.0.1/", "https://172.32.0.1/"]) {
        const r = await ask(rig, provider, fetch(url));
        expect(r.outcome.status, url).toBe("completed");
      }
    } finally {
      rig.cleanup();
    }
  });
  it("Y/Z/AA. credentials, malformed, control characters refused", async () => {
    const rig = rigged();
    try {
      const provider = new MockWebProvider("ok");
      for (const url of [
        "https://user:pass@example.com/", "not a url", "https://",
        "https://exa mple.com/", "https://example.com/#frag", "https://example.com:8443/",
      ]) {
        expect((await ask(rig, provider, fetch(url))).outcome.status, url).toBe("refused");
      }
      expect((await ask(rig, provider, fetch("https://example.com/a\nb"))).outcome.status).toBe("refused");
      expect((await ask(rig, provider, search("a\nb"))).outcome.status).toBe("refused");
    } finally {
      rig.cleanup();
    }
  });
});

describe("M9 redirects AB/AC/AZ + body AD/AE/AY", () => {
  it("AB. redirect to private address refused", async () => {
    const rig = rigged();
    try {
      const r = await ask(rig, new MockWebProvider("redirect-private"), fetch("https://example.com/start"));
      expect(r.outcome.status).toBe("failed");
    } finally {
      rig.cleanup();
    }
  });
  it("AC. redirect chains over the limit refused", async () => {
    const rig = rigged();
    try {
      const r = await ask(rig, new MockWebProvider("redirect-chain"), fetch("https://example.com/loop"));
      expect(r.outcome.status).toBe("failed");
    } finally {
      rig.cleanup();
    }
  });
  it("AZ. compliant redirect completes flagged", async () => {
    const rig = rigged();
    try {
      const r = await ask(rig, new MockWebProvider("redirect-ok"), fetch("https://example.com/start"));
      expect(r.outcome.status).toBe("completed");
      if (r.outcome.status === "completed") {
        const c = r.outcome.result as { redirected: boolean; url: string };
        expect(c.redirected).toBe(true);
        expect(c.url).toBe("https://example.com/final");
      }
    } finally {
      rig.cleanup();
    }
  });
  it("AD/AE/AY. oversized bodies and payloads bounded, unicode-safe", async () => {
    const rig = rigged();
    try {
      const big = await ask(rig, new MockWebProvider("oversized"), fetch("https://example.com/big"));
      expect(big.outcome.status).toBe("completed");
      if (big.outcome.status === "completed") {
        const c = big.outcome.result as { body: string; truncated: boolean };
        expect(c.truncated).toBe(true);
        expect(Buffer.byteLength(c.body, "utf8")).toBeLessThanOrEqual(WEB_LIMITS.MAX_FETCH_RESPONSE_BYTES + 4096);
        expect(() => encodeURIComponent(c.body)).not.toThrow();
      }
      const many = await ask(rig, new MockWebProvider("many"), search("q", { maxResults: 10 }));
      expect(many.outcome.status).toBe("completed");
      if (many.outcome.status === "completed") {
        const c = many.outcome.result as { results: unknown[]; truncated: boolean };
        expect(c.results.length).toBeLessThanOrEqual(10);
        expect(c.truncated).toBe(true);
        expect(Buffer.byteLength(JSON.stringify(c), "utf8")).toBeLessThanOrEqual(WEB_LIMITS.MAX_RESULTS_PAYLOAD_BYTES + 4096);
      }
    } finally {
      rig.cleanup();
    }
  });
});

describe("M9 injection AF/AG + determinism AT", () => {
  it("AF/AG. web content stays inert data", async () => {
    const rig = rigged();
    try {
      const provider = new MockWebProvider("ok");
      const s = await ask(rig, provider, search("anything"));
      expect(s.outcome.status).toBe("completed");
      if (s.outcome.status === "completed") {
        expect(JSON.stringify(s.outcome.result)).toContain("Ignore previous instructions");
      }
      const f = await ask(rig, provider, fetch("https://example.com/page"));
      expect(f.outcome.status).toBe("completed");
      // Content changed nothing: unknown capability still denied, grants intact.
      expect((await ask(rig, provider, { v: 1, operation: "web-search", query: "q", capability: "x" })).outcome.status).toBe("refused");
      expect(rig.session.grants).toHaveLength(2);
      expect(rig.session.sleep).toBe("AWAKE");
      expect(rig.session.killSwitch.engaged).toBe(false);
    } finally {
      rig.cleanup();
    }
  });
  it("AT. deterministic provider behavior", async () => {
    const rig = rigged();
    try {
      const a = await ask(rig, new MockWebProvider("ok"), search("same"));
      const b = await ask(rig, new MockWebProvider("ok"), search("same"));
      expect(a.outcome).toEqual(b.outcome);
    } finally {
      rig.cleanup();
    }
  });
});

describe("M9 gates AH–AM, AQ–AU, AV–AX", () => {
  it("AH/AI. sleep and kill deny before any provider call", async () => {
    const dir = tmpDir();
    try {
      const booted = boot(dir);
      if (!booted.ok) throw new Error("boot failed");
      grantToSession(booted.session, { grantId: "g", taskId: "t", capability: "web.search", scope: "" });
      const provider = new MockWebProvider("ok");
      const asleep = await handleWebProposal(booted.session, { taskId: "t" }, provider, search("q"));
      expect(asleep.outcome.status).toBe("refused");
      expect(provider.calls).toBe(0);
      engageSessionKill(booted.session);
      wakeSession(booted.session, { kind: "ui-action" });
      const killed = await handleWebProposal(booted.session, { taskId: "t" }, provider, search("q"));
      expect(killed.outcome.status).toBe("refused");
      expect(provider.calls).toBe(0);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
  it("AJ/AK/AL/AM. epoch, revocation, cross-task, authority gates", async () => {
    const dir = tmpDir();
    try {
      const first = boot(dir);
      if (!first.ok) throw new Error("boot failed");
      wakeSession(first.session, { kind: "ui-action" });
      grantToSession(first.session, { grantId: "g", taskId: "task-B", capability: "web.search", scope: "" });
      const provider = new MockWebProvider("ok");
      // Cross-task: task-A has no grant.
      expect((await handleWebProposal(first.session, { taskId: "task-A" }, provider, search("q"))).outcome.status).toBe("refused");
      // Authority, not URL, is the gate: benign public URL without grant refused.
      expect(
        (await handleWebProposal(first.session, { taskId: "task-A" }, provider, { v: 1, operation: "web-fetch", url: "https://example.com/" })).outcome.status,
      ).toBe("refused");
      // Revocation invalidates.
      revokeSessionGrant(first.session, "g");
      expect((await handleWebProposal(first.session, { taskId: "task-B" }, provider, search("q"))).outcome.status).toBe("refused");
      // Reboot: no grants survive.
      const second = boot(dir);
      if (!second.ok) throw new Error("reboot failed");
      expect((await handleWebProposal(second.session, { taskId: "task-B" }, provider, search("q"))).outcome.status).toBe("refused");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
  it("AQ/AR. queries and URLs never persist", async () => {
    const rig = rigged();
    try {
      const provider = new MockWebProvider("ok");
      const secret = "hunter2-fake-secret";
      const r = await ask(rig, provider, search(`password=${secret}`));
      expect(r.outcome.status).toBe("completed");
      const audit = fs.readFileSync(path.join(rig.dir, "audit.jsonl"), "utf8");
      const state = fs.readFileSync(path.join(rig.dir, "security-state.json"), "utf8");
      expect(audit).not.toContain(secret);
      expect(state).not.toContain(secret);
      const f = await ask(rig, provider, fetch(`https://example.com/?token=${secret}`));
      expect(f.outcome.status).toBe("completed");
      expect(fs.readFileSync(path.join(rig.dir, "audit.jsonl"), "utf8")).not.toContain(secret);
    } finally {
      rig.cleanup();
    }
  });
  it("AU/AV/AW. concurrency, timeout, provider failure", async () => {
    const rig = rigged();
    try {
      expect(tryAcquireWebSlot()).toBe(true);
      const busy = await ask(rig, new MockWebProvider("ok"), search("q"));
      expect(busy.outcome.status).toBe("refused");
      releaseWebSlot();
      const slow = await ask(rig, new MockWebProvider("hang"), search("q"), "task-W", { timeoutMs: 150 });
      expect(slow.outcome.status).toBe("failed");
      const broken = await ask(rig, new MockWebProvider("error"), fetch("https://example.com/"));
      expect(broken.outcome.status).toBe("failed");
    } finally {
      rig.cleanup();
    }
  });
  it("AX. provider misbehavior refused, never trusted", async () => {
    const rig = rigged();
    try {
      const evil: WebSearchProvider = {
        search: async () => "garbage" as unknown as never,
        fetch: async () => ({ status: "ok" }) as unknown as never,
      };
      const r = await ask(rig, evil, search("q"));
      expect(r.outcome.status).toBe("failed");
    } finally {
      rig.cleanup();
    }
  });
  it("AS/BA. no network surface in web sources or kernel", () => {
    const webDir = new URL("../src/web/", import.meta.url);
    for (const file of fs.readdirSync(webDir).filter((f) => f.endsWith(".ts"))) {
      const src = fs.readFileSync(new URL(file, webDir), "utf8");
      for (const forbidden of ["node:http", "node:net", "node:https", "globalThis.fetch", "XMLHttpRequest", "WebSocket"]) {
        expect(src.includes(forbidden), `${file}: ${forbidden}`).toBe(false);
      }
    }
    const kernelDir = new URL("../src/kernel/", import.meta.url);
    for (const file of fs.readdirSync(kernelDir).filter((f) => f.endsWith(".ts"))) {
      const src = fs.readFileSync(new URL(file, kernelDir), "utf8");
      expect(src.includes("node:"), `${file} imports node`).toBe(false);
    }
  });
});
