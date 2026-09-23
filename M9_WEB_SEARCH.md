# M9 Controlled Web Search (M9 — normative)

M9 adds read-only web search + bounded retrieval. Untrusted on both
ends (planner proposes, web answers); trusted in the middle (kernel
authorizes, adapter bounds). NOT browser automation: no navigation,
cookies, auth, JS, uploads, or methods beyond GET.

## 1. Threat model

Adversaries: malicious planner output (forged caps/risk/provider/
headers/cookies/auth/method/timeout), malicious URLs (SSRF,
credential-bearing, obfuscated IPs), malicious redirect chains,
malicious page content (prompt injection), oversized/timeout/failing
providers. Defenses, in order: strict schemas → trusted registry →
task-bound M2 grants → sleep/kill/slot → URL policy (+ per-redirect
revalidation) → timeout → bounded contracts → metadata-only audit.

## 2. Trusted/untrusted split

UNTRUSTED: planner output, query text, URLs, provider responses,
titles/snippets/bodies. TRUSTED: schemas, registry (web.search,
web.fetch — Tier1, and nothing else), M2 decisions, task grants,
sleep/kill/epoch, URL policy, timeout/redirect/size enforcement,
contracts, audit. The provider sees validated inert data only.

## 3. Capabilities + proposals

Exactly `web.search`/`web.fetch` (family `network`, Tier1,
unscoped — queries/URLs are M9-validated, not M2-scoped). No
`network.execute`, `browser.*`, `http.execute`, or generic cap.
Schemas `{v, operation, query, maxResults?}` /
`{v, operation, url}` strict; every trusted field absent and hence
forbidden. Oversized values refused, never clamped.

## 4. URL + SSRF policy

HTTPS only; no credentials/fragments/ports/control chars; localhost
(+ .localhost) refused; IPv6 refused wholesale (no M9 use case);
single-label hosts refused; WHATWG normalization collapses hex/
octal/integer IPv4 evasions before range checks over 127/8, 10/8,
172.16/12, 192.168/16, 169.254/16, 100.64/10, 0.0.0.0/8,
224.0.0.0/4. No DNS resolution in M9 (residual for real providers).

## 5. Redirects + method

GET-only by construction (no method field exists). ≤3 redirects,
each target revalidated identically; final URL revalidated before
the contract. Exceeding the chain fails closed.

## 6. Responses

Search: count cap (default 5, max 10), per-field Unicode truncation,
64 KiB payload pop-loop with explicit truncated flag. Fetch:
128 KiB byte-bounded body, Unicode-safe, truncated flag, redirected
flag. Contracts strict-versioned; provider misbehavior refused.
Timeouts (10 s, AbortSignal handed over) and failures are typed,
never silent. Concurrency 1 (slot-guarded).

## 7. Injection containment

Snippets/bodies ship with live injection strings in fixtures to
prove the property continuously: content completes as data, changes
no grant/confirmation/policy/sleep/kill/epoch, and never reaches
audit (queries/URLs are never logged — both can carry secrets).

## 8. Sleep/kill/epoch + audit

Pre-authorize checks, M2 sleep-gated caps, provider-boundary
re-check; kill blocks new calls (in-flight abort best-effort via
AbortSignal); stale/revoked denies via live grants. Audit carries
operation, counts, bytes, flags — never query text, URLs, or
content. Planner has no sink access.

## 9. Residual risks

No DNS-time validation (see §4); in-flight abort depends on
provider cooperation; single-process slot (no cross-process lock);
truncation can split context mid-sentence (marked); IPv6 refused
rather than policed (revisit if needed).

## 10. Non-goals

Browser control, profiles, cookies, logins, forms, uploads,
downloads, JS, arbitrary methods/navigation, network utilities,
MCP/LLM runtimes, autonomy, background workers, sessions,
telemetry, real external provider (mock suffices for M9).
