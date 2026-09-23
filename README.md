# Macky

Local-first personal AI computer assistant for macOS.

> Core principle: the AI model is UNTRUSTED. The security layer is TRUSTED.

## Status: M2 — deterministic security boundary

M1 (foundation, frozen, tag `m1-foundation`) contains normative specs
plus a deterministic, pure-function security kernel skeleton.
M2 adds the authorization boundary proving an untrusted planner can
propose actions but cannot grant itself authority: structured action
requests, capability registry with trusted risk tiers, task-scoped
grants, deterministic pipeline, confirmation boundary, sleep
enforcement, revocation, audit events, adversarial tests.
There is no model, voice, sensor, executor, or OS control code.

- `ARCHITECTURE.md` — control flow and trust placement
- `SECURITY_SPEC.md` — 15 normative security requirements
- `SLEEP_SPEC.md` — hard privacy state (security state, not a flag)
- `THREAT_MODEL.md` — trust boundary and abuse cases
- `MILESTONES.md` — gates and acceptance criteria
- `src/kernel/` — pure-function kernel skeleton (no I/O)
- `tests/` — Vitest gates enforcing the specs

## Develop

Requires Node >= 22. No global installs beyond npm.

```sh
npm install
npm test
npm run typecheck
```

Disk-light: dependencies are `typescript`, `vitest`, `zod` only.
No models, Docker images, voice/vision/browser-automation packages.
