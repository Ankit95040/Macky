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

## M9 — Controlled Web Search Intelligence, Read-Only (accepted, frozen)

Checkpoint: commit `c2646e9`, tag `m9-web-search`. 261/261 tests.
M9 behavior frozen; all prior tests MUST remain green unmodified.

## M10 — Trusted Memory Boundary (accepted, frozen)

Checkpoint: commit `856bd6a`, tag `m10-memory-boundary`. 288/288 tests.
M10 behavior frozen; all prior tests MUST remain green unmodified.

## M11 — Controlled macOS Application Launch (accepted, frozen)

Checkpoint: commit `ca54553`, tag `m11-controlled-app-launch`. 302/302 tests.
M11 behavior frozen; all prior tests MUST remain green unmodified.

## M12 — Real LLM Planner Boundary (accepted, frozen)

Checkpoint: commit `157402c` + corrective `cd446c2`, tag `m12-real-llm-planner`. 327/327 tests.
M12 behavior frozen; all prior tests MUST remain green unmodified.

## M13 — Controlled Speech Announcement (current)

Scope: one Tier2 speech.announce capability; strict text-only
proposals; shared shell-char set + secret screen; additive digest
field + strict digest matcher (existing confirmation behavior
identical); fixed /usr/bin/say spawn with single argv; text-bound
confirmation gate; A–AG battery. No messaging, voice choice,
audio files, or autonomy.

Acceptance: full suite + typecheck + build + scans green, then ONE
commit. Do NOT create/move any tag. Do NOT push.

Scope: real HTTPS provider abstraction (fixed shape, no SDK) +
deterministic fake, trusted config, strict JSON parsing with
duplicate-key refusal, single-inference adapter with sleep/kill
gates, M5-unchanged integration, A–BO battery. Offline by default;
no autonomy, loops, tool-calling, or memory automation.

Acceptance: Gates 1–63 per the M12 brief, then tag
`m12-real-llm-planner`. Do NOT push.

Scope: one Tier1 app.launch capability; 3-entry verified registry
(TextEdit/Calculator/Terminal); strict appId-only proposals;
per-launch identity verification; direct /usr/bin/open spawn with
fixed argv and minimal env; timeout + slot guard; M2-authorized
service; conversation launch verb; A–BG battery. Launch only — no
control, scripts, URLs, installs, or autonomy.

Acceptance: Gates 1–49 per the M11 brief, then tag
`m11-controlled-app-launch`. Do NOT push.

Scope: versioned memory records (trusted IDs/timestamps/task/
epoch), strict proposal schemas, Tier1 read/write/delete caps,
atomic bounded JSON store, secret heuristic, create-only writes,
durable deletes, substring search, prompt-injection containment,
conversation verbs, A–AX battery. Information only — never
authority. No embeddings, network, autonomy, or secret vault.

Acceptance: Gates 1–34 per the M10 brief, then tag
`m10-memory-boundary`. Do NOT push.

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
