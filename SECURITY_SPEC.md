# Macky Security Specification (M1 — normative)

These are REQUIREMENTS, not guidance. Implementation MUST NOT weaken
or reinterpret them. Where code and text disagree, this document wins
and the code must be fixed.

## S1. Default deny

The kernel denies any action that is not explicitly allowed by policy.
Unknown action → deny. Unknown capability → deny. Missing rule → deny.

## S2. Least privilege

Every grant is scoped to the minimum capability, target, and duration
needed. No ambient authority. No wildcard grants in M1.

## S3. Capability-based authorization

Grants name explicit capabilities. Blocklists are defense-in-depth
only and MUST NOT be the primary mechanism. A thing not named as a
capability cannot be granted.

## S4. The LLM is never trusted

Model output is data, never instructions to the kernel. The kernel
MUST validate planner proposals against schema and policy before
any further processing, and MUST fail closed on validation failure.

## S5. Planner output is never trusted

Same as S4, applied to any current or future planner component,
including tool-call-shaped output.

## S6. External content is never trusted

Web pages, repos, READMEs, PDFs, downloads, terminal output,
comments, browser content, external messages: all untrusted data.
They MUST NOT alter policy, capabilities, confirmation outcomes,
or audit contents.

## S7. Memory is not automatically trusted

Persistent memory contents are untrusted input on every read.
Recall MUST be re-validated against schema and policy at use time.

## S8. Policy immutable by Macky

No planner/model/memory/external path may modify security policy.
The M1 kernel exports NO policy-mutation API on those paths.
Policy change requires an explicit out-of-band human configuration
action (future milestone; no M1 implementation).

## S9. Audit cannot be disabled by Macky

The kernel exposes append-only audit operations only. No API to
disable, pause, clear, rewrite, or reorder the log exists on any
Macky-reachable path. See `audit.ts`.

## S10. Kill switch cannot be disabled by Macky

The kill switch path is separate from planner/model control.
M1 represents it as an interface + state (`armed`/`engaged`) with
no model-reachable disarm transition. Full implementation is future.

## S11. Secrets boundary

Secrets MUST NOT enter LLM context. M1 provides no secret plumbing
at all (no retrieval, no injection). Any future secret path MUST
resolve values AFTER authorization, inside the trusted layer only.

## S12. High-risk actions need explicit human authorization

Risk level `high` (and anything unclassifiable) REQUIRES an explicit
human confirmation distinct from the planner proposal. Planner
self-approval is invalid. See `confirm.ts`.

## S13. Privacy sleep state

See `SLEEP_SPEC.md` (normative). SLEEP is a security state enforced
by deterministic trusted code, not a prompt or UI flag.

## S14. Fail closed

Uncertainty → denial. Schema failure, unknown risk, ambiguous
target, missing confirmation, or indeterminate sleep state all
resolve to DENY / STAY-ASLEEP. Fail-open paths are forbidden.

## S15. Explicit security boundary per capability

Every meaningful capability MUST declare its boundary (risk level,
confirmation requirement, sleep-gating). M1 capability declarations
are data + interfaces with no OS implementation behind them.
