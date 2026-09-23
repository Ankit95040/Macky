/**
 * Trusted web service (M9 flow). Strict proposal validation →
 * trusted registry classification (Tier1 only; no Tier2/3 web
 * capability exists) → kill/sleep prechecks → single-flight slot →
 * M2 authorize() (SOLE authorization authority; unscoped web.search /
 * web.fetch against live task grants) → provider call with timeout →
 * redirect revalidation loop → bounded versioned contracts → audit.
 *
 * Query text and URLs NEVER enter the audit log (both can carry
 * secrets); audit carries operation, counts, bytes, flags. Web
 * content NEVER enters authorization, grants, policy, or state —
 * contracts are data. No background polling, no sessions, no cookies,
 * no auth, GET-only (the mock performs no HTTP at all; a future real
 * provider owns GET + redirect mechanics under these same rules).
 */
import { authorize } from "../kernel/authorize.js";
import { isEngaged } from "../kernel/kill-switch.js";
import { appendAuditEvent } from "../persistence/audit-store.js";
import {
  persistLogDelta,
  type DurableResult,
  type SecureSession,
} from "../persistence/session.js";
import { truncateText } from "../workspace/text.js";
import { WEB_LIMITS } from "./limits.js";
import {
  WebFetchProposalSchema,
  WebSearchProposalSchema,
} from "./proposal.js";
import type {
  ProviderFetchResponse,
  WebSearchProvider,
} from "./provider.js";
import { classifyWebOperation } from "./registry.js";
import { FetchResultSchema, SearchResultSchema } from "./results.js";
import { validateFetchUrl } from "./url-policy.js";

export interface WebTaskContext {
  readonly taskId: string;
}

export interface WebServiceOptions {
  readonly timeoutMs?: number;
}

let webInFlight = 0;

export function tryAcquireWebSlot(): boolean {
  if (webInFlight >= WEB_LIMITS.MAX_CONCURRENT_REQUESTS) {
    return false;
  }
  webInFlight += 1;
  return true;
}

export function releaseWebSlot(): void {
  webInFlight = Math.max(0, webInFlight - 1);
}

function webRefusal(
  session: SecureSession,
  reason: string,
  auditPersisted: boolean,
): DurableResult {
  return {
    outcome: { status: "refused", stage: "web", reason },
    auditPersisted,
    log: session.log,
  };
}

function persistOne(session: SecureSession, type: string, detail: string): boolean {
  const r = appendAuditEvent(session.sink, { type, detail, epoch: session.epoch, sleep: session.sleep });
  if (!r.ok) {
    session.auditHealthy = false;
    return false;
  }
  return true;
}

async function withTimeout<T>(
  promise: Promise<T>,
  ms: number,
  controller: AbortController,
): Promise<{ readonly ok: true; readonly value: T } | { readonly ok: false }> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const result = await Promise.race([
      promise,
      new Promise<{ readonly ok: false }>((resolve) => {
        timer = setTimeout(() => {
          try {
            controller.abort();
          } catch {
            // Abort is best-effort; the timeout still applies.
          }
          resolve({ ok: false });
        }, ms);
      }),
    ]);
    if (typeof result === "object" && result !== null && "ok" in result && (result as { ok: boolean }).ok === false) {
      return { ok: false };
    }
    return { ok: true, value: result as T };
  } finally {
    if (timer !== undefined) {
      clearTimeout(timer);
    }
  }
}

/** Shrink text until it fits a byte budget (deterministic, terminates). */
function boundBytes(text: string, cap: number): { text: string; truncated: boolean } {
  let current = text;
  let truncated = false;
  for (;;) {
    if (Buffer.byteLength(current, "utf8") <= cap) {
      return { text: current, truncated };
    }
    truncated = true;
    const points = Array.from(current);
    if (points.length <= 1024) {
      return { text: points.slice(0, Math.max(0, points.length - 1)).join(""), truncated };
    }
    current = points.slice(0, points.length - 1024).join("");
  }
}

export interface WebRouter {
  tryRoute(output: unknown, taskId: string): Promise<DurableResult> | undefined;
}

/** Claims ONLY web-search/web-fetch outputs; all else falls through. */
export function createWebRouter(
  session: SecureSession,
  provider: WebSearchProvider,
  opts?: WebServiceOptions,
): WebRouter {
  return {
    tryRoute(output: unknown, taskId: string): Promise<DurableResult> | undefined {
      if (typeof output !== "object" || output === null) {
        return undefined;
      }
      const op = (output as { operation?: unknown }).operation;
      if (op !== "web-search" && op !== "web-fetch") {
        return undefined;
      }
      return handleWebProposal(session, { taskId }, provider, output, opts);
    },
  };
}

export async function handleWebProposal(
  session: SecureSession,
  taskCtx: WebTaskContext,
  provider: WebSearchProvider,
  output: unknown,
  opts?: WebServiceOptions,
): Promise<DurableResult> {
  const timeoutMs = opts?.timeoutMs ?? WEB_LIMITS.REQUEST_TIMEOUT_MS;
  if (!session.auditHealthy) {
    return webRefusal(session, "audit persistence unhealthy", false);
  }
  const asSearch = WebSearchProposalSchema.safeParse(output);
  if (asSearch.success) {
    const searchInput: { query: string; maxResults?: number } =
      asSearch.data.maxResults === undefined
        ? { query: asSearch.data.query }
        : { query: asSearch.data.query, maxResults: asSearch.data.maxResults };
    return await dispatchWeb(session, taskCtx, provider, "web-search", { search: searchInput }, timeoutMs);
  }
  const asFetch = WebFetchProposalSchema.safeParse(output);
  if (!asFetch.success) {
    const ok = persistOne(session, "request.validation-failed", "web proposal failed strict validation");
    return webRefusal(session, "web proposal failed strict validation", ok);
  }
  return await dispatchWeb(session, taskCtx, provider, "web-fetch", { fetch: asFetch.data }, timeoutMs);
}

async function dispatchWeb(
  session: SecureSession,
  taskCtx: WebTaskContext,
  provider: WebSearchProvider,
  operation: "web-search" | "web-fetch",
  proposal: { search?: { query: string; maxResults?: number }; fetch?: { url: string } },
  timeoutMs: number,
): Promise<DurableResult> {
  const def = classifyWebOperation(operation);
  if (def === undefined) {
    const ok = persistOne(session, "request.validation-failed", "unknown web operation");
    return webRefusal(session, "unknown web operation", ok);
  }
  if (isEngaged(session.killSwitch)) {
    const ok = persistOne(session, "execution.rejected", "web refused: kill switch engaged");
    return webRefusal(session, "kill switch engaged", ok);
  }
  if (session.sleep !== "AWAKE") {
    const ok = persistOne(session, "sleep.denied", "web refused while asleep");
    return webRefusal(session, "system is asleep", ok);
  }
  if (!tryAcquireWebSlot()) {
    const ok = persistOne(session, "execution.rejected", "web refused: another request in flight");
    return webRefusal(session, "another web request is already running", ok);
  }
  try {
    // THE authorization decision — M2, sole authority. Unscoped web
    // capabilities authorize against live task grants; no resource.
    // NOTE: M2 operations are "search"/"fetch" (registry-declared);
    // the "web-"-prefixed names are M9 proposal vocabulary only.
    const m2Operation = operation === "web-search" ? "search" : "fetch";
    const before = session.log.events.length;
    const authorized = authorize(
      { capability: def.capability, operation: m2Operation, taskId: taskCtx.taskId },
      { sleep: session.sleep, grants: session.grants, confirmations: session.confirmations, log: session.log },
    );
    session.log = authorized.log;
    const persistedAuth = persistLogDelta(session, before);
    if (authorized.decision.verdict !== "allow") {
      return webRefusal(session, `authorization did not allow (got ${authorized.decision.verdict})`, persistedAuth);
    }
    if (isEngaged(session.killSwitch) || session.sleep !== "AWAKE") {
      const ok = persistOne(session, "execution.rejected", "web stopped at provider boundary");
      return webRefusal(session, "stopped at provider boundary", ok);
    }
    const controller = new AbortController();
    if (proposal.search !== undefined) {
      return await runSearch(session, def.capability, provider, proposal.search.query, proposal.search.maxResults ?? 5, controller, timeoutMs);
    }
    const fetchUrl = proposal.fetch?.url;
    if (fetchUrl === undefined) {
      const ok = persistOne(session, "request.validation-failed", "web-fetch unparseable");
      return webRefusal(session, "web-fetch unparseable", ok);
    }
    return await runFetch(session, def.capability, provider, fetchUrl, controller, timeoutMs);
  } finally {
    releaseWebSlot();
  }
}

async function runSearch(
  session: SecureSession,
  capability: string,
  provider: WebSearchProvider,
  query: string,
  maxResults: number,
  controller: AbortController,
  timeoutMs: number,
): Promise<DurableResult> {
  const startedOk = persistOne(session, "execution.started", `started ${capability} tier=1`);
  if (!startedOk) {
    return webRefusal(session, "audit unhealthy: refused before provider call", false);
  }
  const raced = await withTimeout(
    provider.search({ query, maxResults, signal: controller.signal }),
    timeoutMs,
    controller,
  );
  if (!raced.ok) {
    persistOne(session, "execution.failed", `${capability} timeout`);
    return {
      outcome: { status: "failed", stage: "adapter", reason: "web provider timeout" },
      auditPersisted: session.auditHealthy,
      log: session.log,
    };
  }
  let hits: ReadonlyArray<{ title: string; url: string; snippet: string }>;
  try {
    if (!Array.isArray(raced.value)) {
      throw new Error("bad provider shape");
    }
    hits = raced.value;
  } catch {
    persistOne(session, "execution.failed", `${capability} provider misbehavior`);
    return {
      outcome: { status: "failed", stage: "adapter", reason: "web provider misbehavior" },
      auditPersisted: session.auditHealthy,
      log: session.log,
    };
  }
  // Enforce count cap, then payload cap (pop extras, never silent).
  let truncated = hits.length > maxResults;
  let results = hits.slice(0, maxResults).map((h) => ({
    title: truncateText(String(h.title ?? ""), WEB_LIMITS.MAX_TITLE_CHARS).text,
    url: truncateText(String(h.url ?? ""), WEB_LIMITS.MAX_URL_CHARS).text,
    snippet: truncateText(String(h.snippet ?? ""), WEB_LIMITS.MAX_SNIPPET_CHARS).text,
  }));
  for (;;) {
    const bytes = Buffer.byteLength(JSON.stringify(results), "utf8");
    if (bytes <= WEB_LIMITS.MAX_RESULTS_PAYLOAD_BYTES || results.length === 0) {
      break;
    }
    truncated = true;
    results = results.slice(0, results.length - 1);
  }
  const parsed = SearchResultSchema.safeParse({ v: 1, query, results, truncated });
  if (!parsed.success) {
    persistOne(session, "execution.failed", `${capability} result contract failed`);
    return {
      outcome: { status: "failed", stage: "adapter", reason: "result contract failed" },
      auditPersisted: session.auditHealthy,
      log: session.log,
    };
  }
  persistOne(
    session,
    "execution.completed",
    `${capability} ok results=${parsed.data.results.length} truncated=${truncated}`,
  );
  return {
    outcome: { status: "completed", operation: `${capability}:search`, result: parsed.data, redacted: false },
    auditPersisted: session.auditHealthy,
    log: session.log,
  };
}

async function runFetch(
  session: SecureSession,
  capability: string,
  provider: WebSearchProvider,
  rawUrl: string,
  controller: AbortController,
  timeoutMs: number,
): Promise<DurableResult> {
  const first = validateFetchUrl(rawUrl);
  if (!first.ok) {
    const ok = persistOne(session, "request.validation-failed", `fetch URL refused: ${first.reason}`);
    return webRefusal(session, `URL refused: ${first.reason}`, ok);
  }
  const startedOk = persistOne(session, "execution.started", `started ${capability} tier=1`);
  if (!startedOk) {
    return webRefusal(session, "audit unhealthy: refused before provider call", false);
  }
  let current = first.url;
  let redirected = false;
  for (let hop = 0; hop <= WEB_LIMITS.MAX_REDIRECTS; hop += 1) {
    let res: ProviderFetchResponse;
    try {
      const raced = await withTimeout(
        provider.fetch({ url: current, signal: controller.signal }),
        timeoutMs,
        controller,
      );
      if (!raced.ok) {
        persistOne(session, "execution.failed", `${capability} timeout`);
        return {
          outcome: { status: "failed", stage: "adapter", reason: "web provider timeout" },
          auditPersisted: session.auditHealthy,
          log: session.log,
        };
      }
      res = raced.value;
    } catch {
      persistOne(session, "execution.failed", `${capability} provider failure`);
      return {
        outcome: { status: "failed", stage: "adapter", reason: "web provider failure" },
        auditPersisted: session.auditHealthy,
        log: session.log,
      };
    }
    if (res.status === "redirect") {
      if (hop >= WEB_LIMITS.MAX_REDIRECTS) {
        persistOne(session, "execution.failed", `${capability} redirect limit exceeded`);
        return {
          outcome: { status: "failed", stage: "adapter", reason: "redirect limit exceeded" },
          auditPersisted: session.auditHealthy,
          log: session.log,
        };
      }
      const next = validateFetchUrl(res.location);
      if (!next.ok) {
        persistOne(session, "execution.failed", `${capability} redirect target refused`);
        return {
          outcome: { status: "failed", stage: "adapter", reason: `redirect refused: ${next.reason}` },
          auditPersisted: session.auditHealthy,
          log: session.log,
        };
      }
      current = next.url;
      redirected = true;
      continue;
    }
    if (res.status === "error") {
      persistOne(session, "execution.failed", `${capability} provider error`);
      return {
        outcome: { status: "failed", stage: "adapter", reason: "web provider error" },
        auditPersisted: session.auditHealthy,
        log: session.log,
      };
    }
    // Revalidate the final URL defensively (provider must not widen policy).
    const final = validateFetchUrl(res.url);
    if (!final.ok) {
      persistOne(session, "execution.failed", `${capability} final URL refused`);
      return {
        outcome: { status: "failed", stage: "adapter", reason: "final URL refused" },
        auditPersisted: session.auditHealthy,
        log: session.log,
      };
    }
    const bounded = boundBytes(String(res.body ?? ""), WEB_LIMITS.MAX_FETCH_RESPONSE_BYTES);
    const title = truncateText(String(res.title ?? ""), WEB_LIMITS.MAX_TITLE_CHARS);
    const parsed = FetchResultSchema.safeParse({
      v: 1,
      url: final.url,
      title: title.text,
      body: bounded.text,
      truncated: bounded.truncated,
      redirected,
    });
    if (!parsed.success) {
      persistOne(session, "execution.failed", `${capability} result contract failed`);
      return {
        outcome: { status: "failed", stage: "adapter", reason: "result contract failed" },
        auditPersisted: session.auditHealthy,
        log: session.log,
      };
    }
    const bytes = Buffer.byteLength(parsed.data.body, "utf8");
    persistOne(
      session,
      "execution.completed",
      `${capability} ok bytes=${bytes} truncated=${bounded.truncated} redirected=${redirected}`,
    );
    return {
      outcome: { status: "completed", operation: `${capability}:fetch`, result: parsed.data, redacted: false },
      auditPersisted: session.auditHealthy,
      log: session.log,
    };
  }
  persistOne(session, "execution.failed", `${capability} redirect limit exceeded`);
  return {
    outcome: { status: "failed", stage: "adapter", reason: "redirect limit exceeded" },
    auditPersisted: session.auditHealthy,
    log: session.log,
  };
}
