# Macky Architecture (M1 — normative)

## 1. Purpose

Macky is a local-first personal AI computer assistant for macOS.
M1 covers foundation, architecture documentation, security specification,
and a deterministic kernel skeleton only. No model, voice, sensors,
or OS control.

## 2. Core principle (normative)

> The AI model is UNTRUSTED. The security layer is TRUSTED.

The LLM may propose actions. It may NEVER grant itself permission
to perform those actions.

## 3. Control flow

```
USER
 ↓
Macky Interface / Voice (future; NOT in M1)
 ↓
LLM / Planner (UNTRUSTED; NOT in M1)
 ↓
=== TRUST BOUNDARY ===
 ↓
Deterministic Security Kernel (TRUSTED; M1 skeleton, pure functions)
 ↓
Authorization / Capability System (TRUSTED; M1 types + pure checks)
 ↓
Tool Layer (future; M1 declares interfaces ONLY, no implementations)
 ↓
macOS (future; NO real control in M1)
```

## 4. Trust placement

UNTRUSTED (never in the kernel): LLM, planner, model-generated tool
calls, web pages, repos, READMEs, PDFs, downloads, terminal output,
code comments, browser content, external messages, persistent memory.

TRUSTED (kernel side of the boundary): security policy engine,
authorization engine, capability manager, confirmation system,
secret boundary, audit logger, SLEEP state machine, kill switch.

See `SECURITY_SPEC.md` and `THREAT_MODEL.md` (normative).

## 5. M1 module map

```
src/kernel/
  types.ts         shared types, SLEEP-gated categories, risk levels
  policy.ts        default-deny evaluation, fail-closed (pure)
  capabilities.ts  capability declarations as DATA + interfaces (no impl)
  sleep.ts         explicit SLEEP state machine (pure)
  confirm.ts       high-risk confirmation gate (pure)
  audit.ts         append-only audit log (pure, immutable)
  index.ts         re-exports (no I/O, no side effects)
```

Rules for M1 code:

- Pure functions only. No filesystem, shell, network, or macOS APIs.
- No sensor code (mic/screen/keyboard/mouse/watchers).
- No inference calls. No wake-word listener.
- Future capabilities appear as types/interfaces, never as
  unrestricted placeholder implementations.
- `tsc --noEmit` and `vitest run` must pass for any checkpoint.

## 6. What M1 explicitly is NOT

Model integration, voice, screen/browser/mouse/keyboard automation,
live sensors, background agents, UI beyond a future CLI stub,
Docker images, hosted services.
