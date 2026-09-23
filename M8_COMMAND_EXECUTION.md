# M8 Controlled Terminal Execution (M8 — normative)

M8 is the first milestone that executes commands — five fixed
binaries, structured argv, no shell. Planner proposes; kernel
authorizes; runner spawns. No autonomy, network, or writes.

## 1. Threat model

The planner is an active adversary with a single narrow channel:
naming a registered commandId + inert argv + workspace context. It
cannot set risk, capability, executable, env, timeout, approval,
policy, cwd root, or concurrency. Every forgery class dies at
schema, classifier, binding, or M2 — each tested.

## 2. Registry (`commands/registry.ts`)

Allowed (exact paths, verified present on the build machine):
`command.echo`→/bin/echo, `command.printf`→/usr/bin/printf,
`command.whoami`→/usr/bin/whoami, `command.pwd`→/bin/pwd (all
Tier0, no confirmation), `command.id`→/usr/bin/id (Tier2:
uid/gid/group exposure is human-gated — the concrete reason).
printf formats restricted to `%s/%d/%%` (`%n` is a memory write).
Denied Tier3 denylist (~26 ids: shells, sudo, rm/mv/cp/mkdir,
curl/ssh, npm/python/node, osascript, git-as-command) over
default-deny. No PATH lookup exists.

## 3. Schema + classifier

`{v, operation:"command-exec", commandId, workspaceId, cwd?, argv?}`
strict; unknown/missing/trusted fields rejected, never repaired.
Global argv rejection: shell metachars, NUL/newline, leading `-`,
`/`, backslash, >1024 code points. Per-command arity/format after.
Risk comes ONLY from the classifier reading the registry.

## 4. Tier semantics + why Tier3 denies by default

Tier0 executes on M2 ALLOW. Tier2 additionally needs an exact-match
trusted confirmation (M2 store). Tier3 (and unknown) die in the
classifier BEFORE M2 and confirmation are even consulted — no
approval, token, or retry can revive them. Structural, not policy.

## 5. Authorization path (no parallel system)

Service validates → binds workspace (registered + task-bound +
reverified) → classifies → resolves cwd (M3 containment) →
validates argv → kill/sleep prechecks → **M2 authorize()** (sole
authority; Tier2 via trusted store) → re-check at spawn boundary →
spawn → audit. M5's family table cannot express per-command
capabilities without a forbidden generic entry, so the service
applies M5's identical disciplines (strict schema, trusted task
binding, zero forgery) and routes the DECISION through M2. M3
run() structurally cannot execute commands (argv unrepresentable
in M2 requests) — tested.

## 6. Runner

`spawn` direct (exact exe + argv array, `shell:false`,
`stdio:ignore/pipe/pipe`, env exactly `{LC_ALL:"C"}` — PATH omitted).
Streaming byte caps (64 KiB/stream) + Unicode-safe decode
(StringDecoder) + shared truncation. Timeout 10 s → SIGTERM → 1 s
grace → SIGKILL; timed-out/failed contracts; single in-flight slot.
spawn injectable for deterministic timeout/cleanup tests.

## 7. Workspace + environment

Commands run only with cwd inside a reverified trusted workspace
(absolute/`..`/backslash/NUL/encoded rejected; root drift refused).
Environment is constructed, never inherited — proven by exact-shape
unit test under a poisoned parent env.

## 8. Sleep/kill/epoch + audit

Pre-authorize checks, M2 sleep-gated capabilities, spawn-boundary
re-check; stale epochs/revoked grants deny; kill blocks new work.
Audit (existing sink): started/completed/failed/timed-out with
commandId, task, workspace, relative cwd, tier, exit, byte counts —
never stdout/stderr contents, argv values, or env. Planner cannot
forge events (no sink access; strict envelope).

## 9. Residual risks

Process-group containment: no shell/background syntax can reach
spawn, and the five binaries do not fork — but SIGTERM/SIGKILL
address the direct child only; a hypothetical grandchildren escape
is not contained (documented, accepted for non-forking allowlist).
TOCTOU check→spawn (M3 carryover). Timeout grace adds ≤1 s delay.
Single-process concurrency guard (no cross-process lock).

## 10. Non-goals

Shells, sudo, writes, installs, network, git mutation, interpreters,
daemons, PTYs, MCP/LLM runtimes, autonomy — all refused and tested.
