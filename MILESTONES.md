# Macky Milestones & Gates

## M1 — Foundation (accepted, frozen)

Checkpoint: commit `52d03ae`, tag `m1-foundation`. 28/28 tests green.
M1 files MUST NOT be modified; M1 tests MUST remain green unmodified.

Scope: repo scaffold, normative docs, deterministic kernel skeleton,
Vitest gates. No model, sensors, or OS control.

## M2 — Deterministic Security Boundary (accepted, frozen)

Checkpoint: commit `6f8a18f`, tag `m2-security-boundary`. 71/71 tests.
M2 files MUST NOT be modified in ways that change M2 behavior; M1/M2
tests MUST remain green unmodified (additive extension only).

## M3 — Trusted Read-Only Execution (accepted, frozen)

Checkpoint: commit `4fccbab`, tag `m3-read-only-execution`. 104/104 tests.
M3 behavior frozen; M1/M2/M3 tests MUST remain green unmodified.

## M4 — Durable Security State & Audit (accepted, frozen)

Checkpoint: commit `37ac133`, tag `m4-durable-security`. 130/130 tests.
M4 behavior frozen; all prior tests MUST remain green unmodified.

## M5 — LLM Planner Integration (accepted, frozen)

Checkpoint: commit `8e86131`, tag `m5-planner-boundary`. 148/148 tests.
M5 behavior frozen; all prior tests MUST remain green unmodified.

## M6 — Conversation + Controlled Tool Loop (accepted, frozen)

Checkpoint: commit `14e0eed`, tag `m6-conversation-loop`. 173/173 tests.
M6 behavior frozen; all prior tests MUST remain green unmodified.

## M7 — Workspace / File Intelligence, Read-Only (accepted, frozen)

Checkpoint: commit `ec220be`, tag `m7-workspace-readonly`. 215/215 tests.
M7 behavior frozen; all prior tests MUST remain green unmodified.

## M8 — Controlled Terminal Execution (accepted, frozen)

Checkpoint: commit `99e6ca8`, tag `m8-controlled-terminal`. 241/241 tests.
M8 behavior frozen; all prior tests MUST remain green unmodified.

## M9 — Controlled Web Search Intelligence, Read-Only (current)

Scope: Tier1 web.search/web.fetch only (no generic network cap),
strict proposal schemas, HTTPS-only SSRF URL policy with redirect
revalidation, GET-only provider abstraction + deterministic mock,
bounded Unicode-safe contracts, prompt-injection containment,
M2-authorized service, conversation websearch/webfetch, A–BD
battery. No browser, cookies, auth, uploads, or autonomy.

Acceptance: Gates 1–30 per the M9 brief, then tag `m9-web-search`.
Do NOT push.

Scope: trusted workspace registry + task binding, relative-path
semantics on M3 enforcement, read/find/search/tree adapters,
versioned contracts, unicode-safe truncation, conversation routing
via injected router, A–AQ battery. Read-only; no writes, shell,
network, watchers, memory, or autonomy.

Acceptance: Gates 1–25 per the M7 brief, then tag
`m7-workspace-readonly`.

Scope: versioned conversation contracts, deterministic bounds,
orchestrator (validate → trusted taskId → ≤3 planner/tool rounds,
every action via M5 handleProposal), mock conversational planner,
A–O injection battery, structural import test. Session-local only:
no memory, UI, voice, real LLM, network, autonomy.

Acceptance: Gates 1–15 per the M6 brief, then tag
`m6-conversation-loop`.

Scope: versioned strict planner contract, offline MockPlanner
(valid + malicious), single trust boundary (validate → trusted
task binding → closed translation → M2 → M3 → M4 durable audit).
No real LLM, no network, no new runtime dependencies.

Acceptance: full suite green, typecheck, build, planner static
scan (no OS/network imports), secret scan, diff review, then tag
`m5-planner-boundary`.

Scope: security-state model + atomic state file, safe boot (SLEEP,
epoch+1, empty authority), durable JSONL hash-chained audit with
verify/repair, epoch-bound runDurable, kill/sleep durability,
bounded storage, trusted bootstrap config, 0o600/0o700 perms,
recovery + restart (real-subprocess) + secrecy tests. No LLM,
no autonomy, no secrets subsystem, no network, no database.

Acceptance: Gates 1–16 per the M4 brief, then tag
`m4-durable-security`.

Scope: narrow trusted executor (`run()` authorizes internally, then
runs one allowlisted read-only adapter), path/symlink/sensitive
controls, secret sanitizer, resource limits, git fixed-argv adapter,
system-info allowlist, sleep re-check, kernel kill switch, execution
audit events, adversarial tests. No writes, no network, no model,
no autonomy, no background operation.

Acceptance: Gates 1–10 per the M3 brief (M1+M2 regression, M3 tests,
typecheck, static inspection, dependency audit, secret scan, manual
adversarial review, scope audit, clean tree) then tag
`m3-read-only-execution`.

Scope: structured action requests, capability registry, task-scoped
grants, deterministic pipeline, risk tiers, confirmation boundary,
sleep enforcement, revocation, audit events, adversarial tests.
No executor, no model, no sensors, no OS control.

Acceptance criteria (ALL required for `m2-security-boundary` tag):

- [ ] All M1 tests green, unmodified
- [ ] New adversarial tests pass (request attacks, escalation, risk,
      sleep, confirmation, policy, revocation, transitions, audit)
- [ ] `npm test` fully green
- [ ] `npm run typecheck` clean (existing strict config)
- [ ] No OS/execution imports in `src/kernel/`
- [ ] No new dependencies (or every addition explained)
- [ ] No secrets / `.env` / tokens / keys
- [ ] Git diff audited; only intended M2 scope
- [ ] No M3 scope begun (LLM, voice, sensors, execution, GUI)
- [ ] Working tree clean after checkpoint

## M3+ (not started; listed to prevent scope creep)

- M3: confirmation UX (CLI stub) + audit file sink + read-only tools
  behind the kernel (clock, file-info with explicit grants)
- M4+: local model wiring, voice, sensors — each behind S15
  boundaries, explicit human approval, and SLEEP gating.
