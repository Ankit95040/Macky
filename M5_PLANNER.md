# M5 Planner Boundary (M5 — normative)

M5 proves: an untrusted planner can propose actions but cannot
manufacture authority or bypass the kernel. Fully offline — the only
planner is a deterministic mock. No provider SDKs, no network.

## 1. Contract (`planner/proposal.ts`)

Versioned (`plannerVersion: 1`), strict: taskId, family
(filesystem/git/system), operation, resource?, requestId?,
rationale?. Forbidden trusted fields (risk, decision, approved,
confirmedBy, grants, kill-switch, sleep, policy, shell, code, …)
fail validation and the proposal is REJECTED — never stripped and
repaired. Rationale is inert metadata.

## 2. Planner abstraction (`planner/mock-planner.ts`)

`Planner.propose(input): Promise<unknown>` — async for future
providers, output always treated as adversarial. `MockPlanner`
scripts valid + 14 malicious behaviors. The module imports contract
types ONLY: no fs, child_process, net, kernel, executor, or
persistence. A planner that cannot import execution cannot execute.

## 3. Boundary (`planner/boundary.ts`) — the only path

envelope `{epoch, taskId, output}` (strict; taskId is the TRUSTED
app-assigned binding) → proposal validation → task-binding equality
(proposal.taskId must equal envelope taskId; cross-task claims die
here) → closed translation table to an M2 ActionRequest (rationale
DROPPED — prompt injection cannot reach auth or audit) → M4
runDurable (epoch, M2 auth, M3 exec, durable audit). No second auth
system, no registry copy, no metadata influence.

## 4. Audit

Planner output never reaches the audit store directly. Boundary
refusals persist `request.validation-failed`; successes flow through
the existing M4 delta persistence. Injection text appears in neither.

## 5. Invariants (all tested A–Q + purity)

Planner untrusted; no granted authority; no risk change; no
confirmation; no M2 bypass; no OS APIs; no secrets; no wake; no
policy/kill manipulation; no audit writes; sleep/kill/epoch
authoritative; all execution M2→M3. Cross-task binding enforced by
trusted envelope equality (M5 addition; M2 authorize untouched).
