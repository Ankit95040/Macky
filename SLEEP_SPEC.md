# Macky SLEEP Specification (M1 — normative)

SLEEP is a SECURITY STATE, not a UI/status flag. It is enforced by
deterministic trusted code. No LLM instruction, prompt, memory entry,
or external content can cause observation or action while asleep.

## SL1. Hard privacy state

A state named `SLEEP` exists in the kernel state machine (`sleep.ts`).
While in `SLEEP`, ALL of the following are OFF — no exceptions,
no per-category overrides from untrusted paths:

1. microphone capture
2. screen capture
3. screen recording
4. keyboard monitoring
5. mouse monitoring
6. filesystem watchers
7. browser monitoring
8. LLM inference
9. memory writes
10. background automation
11. Macky-initiated network activity
12. computer-control capabilities

These are enumerated as `SLEEP_GATED_CATEGORIES` in code. Tests MUST
assert every category is gated while asleep.

## SL2. No prompt-based enforcement

Macky MUST NOT rely on instructions like "don't monitor while
sleeping". Enforcement is a pure state-machine check:
`isCategoryAllowed(state, category)` returns `false` for every
gated category when `state === "SLEEP"`.

## SL3. Safe initial state

The kernel starts in `SLEEP` (`initialSleepState()`).
There is no constructor, flag, or input that starts the system
in an observing state.

## SL4. Crash/restart stays asleep

Restart is construction, and construction yields `SLEEP` (SL3).
No persisted "was awake" value may cause auto-wake. M1 keeps no
persistence at all; any future persistence layer MUST re-enter
SLEEP on load until an explicit wake action occurs.

## SL5. Explicit local wake only

Wake requires an explicit local action:

- `keyboard-shortcut`, or
- `ui-action`

There is deliberately NO `wake-word` action in M1. Any future
always-listening mechanism is FORBIDDEN by this spec unless this
document is revised through explicit human review, because it
would require continuous microphone monitoring — which contradicts
SL1. The `requestWake` function accepts only the two explicit
actions above and fails closed (stays asleep) on anything else.

## SL6. Sleep is always available

`enterSleep()` transitions from any state to `SLEEP` unconditionally.
No confirmation, policy check, or planner approval is required to
go to sleep.

## SL7. State machine (normative transitions)

- `initialSleepState()` → `SLEEP`
- `requestWake(SLEEP, keyboard-shortcut | ui-action)` → `AWAKE`
- `requestWake(SLEEP, anything-else)` → `SLEEP` (fail closed)
- `requestWake(AWAKE, _)` → `AWAKE` (idempotent)
- `enterSleep(_)` → `SLEEP`
- `isCategoryAllowed(SLEEP, gated-category)` → `false`
- `isCategoryAllowed(AWAKE, category)` → per-category static rule
  (M1: observation/inference categories default to disallowed
  until future explicit grants; the gate itself is what M1 tests)
