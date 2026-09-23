# Macky Milestones & Gates

## M1 — Foundation (accepted, frozen)

Checkpoint: commit `52d03ae`, tag `m1-foundation`. 28/28 tests green.
M1 files MUST NOT be modified; M1 tests MUST remain green unmodified.

Scope: repo scaffold, normative docs, deterministic kernel skeleton,
Vitest gates. No model, sensors, or OS control.

## M2 — Deterministic Security Boundary (current)

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
