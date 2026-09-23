# M6 Conversation + Controlled Tool Loop (M6 — normative)

M6 adds session-local conversation orchestration around the frozen
M5→M2→M3→M4 path. Orchestration is NOT security: every action still
crosses the exact same trusted boundary. No memory, no UI, no real
LLM, no autonomy.

## 1. Contracts (`conversation/messages.ts`, `limits.ts`)

Versioned strict messages: user / assistant / tool, each with id,
role, bounded content, gapless seq. Bounds: 4 KiB/message, 32
messages, 3 loop iterations, 8 KiB planner output, 64 KiB
conversation, 4 KiB tool text (truncates WITH marker — the one
documented exception to fail-closed, §8), 8 history items to planner.

## 2. Orchestrator (`conversation/orchestrator.ts`)

`handleUserMessage(ctx, raw, opts?)`: validate → append → trusted
taskId (minted via stdlib `randomUUID`; trusted caller may supply
for continuity — NEVER the planner) → bounded loop: minimal planner
input (taskId, latest text, recent history only — no grants, secrets,
decisions, kernel objects) → oversized-output guard → `final`
response (strict, else not final) → M5 `handleProposal` with the
TRUSTED envelope → completed tool text appended (bounded) / refusal
mapped to generic codes (no kernel internals in user text) /
failure / loop-limit stop. Sleep/kill/epoch re-checked every
iteration by the underlying boundaries, not by the orchestrator.

## 3. Mock conversational planner

Test-only NLU stand-in with a documented micro-language
(`info`, `read|list <abs>`, `git status|log|diff <abs>`) plus
`stubborn`/`loop-grab`/`task-grab`/`garbage` modes. Data in/out
only. Notably: tool/history text is never interpreted — the mock
parses the latest user text alone, so injection in history cannot
redirect it (tested B–E).

## 4. Invariants (tested)

Every tool action reaches M5 (no second system of anything);
task identity originates trusted; loop hard-stops at 3;
planner-limit/task forgeries die at strict schemas; oversized
input/output refused; tool overflow truncates marked; sleep/kill/
epoch authoritative; conversation never enters security audit;
session-local state only (dies with the process).
