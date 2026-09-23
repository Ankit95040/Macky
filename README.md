# Macky

Local-first personal AI computer assistant for macOS.

> Core principle: the AI model is UNTRUSTED. The security layer is TRUSTED.

## Status: M1 — foundation only

M1 contains normative specs plus a deterministic, pure-function
security kernel skeleton. There is no model, voice, sensor, or OS
control code, by design.

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
