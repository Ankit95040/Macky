# Macky Milestones & Gates (M1)

## M1 — Foundation (current)

Scope: repo scaffold, normative docs, deterministic kernel skeleton,
Vitest gates. No model, sensors, or OS control.

Acceptance criteria (ALL required for `m1-foundation` tag):

- [ ] `ARCHITECTURE.md`, `SECURITY_SPEC.md`, `SLEEP_SPEC.md`,
      `THREAT_MODEL.md` present and normative
- [ ] `src/kernel/*` pure functions only (no fs/shell/net/macOS APIs)
- [ ] SLEEP state machine explicit + tested (all 12 categories)
- [ ] No wake-word path exists; wake is explicit-local-action only
- [ ] Capabilities are types/interfaces; no unrestricted placeholders
- [ ] `npm test` (vitest run) fully green
- [ ] `npm run typecheck` (`tsc --noEmit`) clean
- [ ] Git diff inspected; no secrets; only intended M1 scope
- [ ] Checkpoint commit + tag `m1-foundation`

## M2+ (not started; listed to prevent scope creep)

- M2: capability registry + confirmation UX (CLI stub) + audit file sink
- M3: read-only tools behind the kernel (clock, file-info with
  explicit grants) + adversarial tests
- M4+: local model wiring, voice, sensors — each behind S15
  boundaries, explicit human approval, and SLEEP gating.

No M2 work begins until M1 is tagged.
