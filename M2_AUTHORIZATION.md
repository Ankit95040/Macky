# M2 Authorization Boundary (M2 — normative)

M2 proves: an untrusted planner can propose actions but cannot grant
itself authority, escalate scope, alter risk classification, forge
confirmation, bypass policy, or operate while Macky is sleeping.

M2 only authorizes. M2 does not execute. No executor exists.

## 1. Authorization flow (implemented in `src/kernel/authorize.ts`)

```
untrusted request (unknown)
 → strict schema validation      fail closed: DENY
 → legacy M1 ids?                M1-compat path (frozen M1 semantics)
 → resolve trusted definition    unknown: DENY
 → resolve trusted task grant    planner taskId is a lookup key only;
                                 missing/forged/revoked: DENY
 → sleep-state enforcement       SLEEP denies every gated capability,
                                 including previously valid ones
 → operation check               exact match against declaration; else DENY
 → scope containment             resource must sit inside a live grant
                                 scope (segment-boundary paths, domain
                                 rules for network); else DENY
 → trusted risk tier             from the registry ONLY; the request
                                 cannot carry risk metadata (the strict
                                 schema rejects it)
 → confirmation requirement      tier >= 2 or declaration flag
 → trusted confirmation state    mock store; planner approval fields
                                 have zero authority
 → final decision + one audit event (secrets redacted)
```

## 2. Capability model (`capability-model.ts`)

Twelve families: filesystem, terminal, git, browser, screen,
app-control, keyboard, mouse, network, memory, audit, sleep.
Tiers 0–3 per M2 section 6. Deliberately ABSENT (hence ungrantable):
`system.wake`, policy modification, secret access, shell execution,
Docker control. Wake remains a trusted local action via `requestWake`,
never a capability.

## 3. Task scoping (`task-grants.ts`)

Trusted code issues grants (`issueGrant` validates capability +
scope shape and throws on programmer error). Grants bind
(taskId, capability, scope) and support revocation (`revokeGrant`
returns a new frozen array). The pipeline matches live grants only.

## 4. Confirmation (`confirm.ts`, M2 section)

`ConfirmationStore` is the deterministic/mock provider: trusted
records, exact-match lookup on (task, capability, operation,
resource). No Touch ID, no voice auth in M2.

## 5. Audit (`audit.ts`, M2 section)

One typed event per `authorize()` call; lifecycle events
(issued/revoked/sleep/wake) via `appendSecurityEvent`. All details
pass through `redactSecrets`. Append-only, frozen, no mutation API.

## 6. Static guarantees

No OS imports in `src/kernel/`; no child_process/fs/net/browser/
screen/keyboard/mouse/mic/LLM execution surface anywhere; M1 files
byte-identical (M1 tests unmodified and green).
