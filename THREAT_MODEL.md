# Macky Threat Model (M1 — normative)

## T1. Trust boundary

UNTRUSTED: LLM, planner, model-generated tool calls, web pages,
GitHub repos, READMEs, PDFs, downloads, terminal output, code
comments, browser content, external messages, persistent memory.

TRUSTED (eventually; M1 skeleton): policy engine, authorization
engine, capability manager, confirmation system, secret boundary,
audit logger, SLEEP machine, kill switch.

## T2. Abuse cases the kernel MUST defeat (tested where M1-testable)

1. Planner grants itself a capability → defeated by S1/S3:
   planner output is data; grants come only from policy + human
   confirmation. (Test: self-approving proposal denied.)
2. Malicious prompt-in-README/PDF/webpage escalates privilege →
   defeated by S6: external content never alters policy/capabilities.
   (M1: no external-content ingestion path exists at all.)
3. Poisoned memory replays an old grant → defeated by S7:
   memory re-validated at use; no standing grants in M1.
4. Planner disables audit to hide actions → defeated by S9:
   no disable/clear API exists. (Test: audit module exports no
   mutating remover; log is immutable/persistent-structure.)
5. Planner edits policy or kill switch → defeated by S8/S10:
   no mutation API on reachable paths. (Test: none exported.)
6. Secrets leak into model context → defeated by S11:
   M1 has no secret plumbing; nothing to leak through the kernel.
7. High-risk action without human approval → defeated by S12:
   `confirm.ts` requires distinct human approval. (Test.)
8. Observation while "sleeping" → defeated by SL1/SL2:
   state-machine gate, not a prompt. (Tests: all 12 categories.)
9. Crash auto-wakes into monitoring → defeated by SL4:
   construction always yields SLEEP. (Test.)
10. Always-listening wake word smuggled in → defeated by SL5:
    no such action exists; unknown wake actions fail closed. (Test.)
11. Ambiguous/uncertain request slips through → defeated by S14:
    fail-closed evaluation. (Tests: unknown action, unknown risk,
    schema-invalid proposal all deny.)

## T3. Out of scope for M1 (tracked, not implemented)

Real sensor drivers, OS permission prompts, TCC entitlements,
code-signing/notarization, sandbox profiles, secret-store
integration, remote-attack surface. These arrive with the
milestones that introduce the corresponding capability, each with
its own explicit boundary per S15.
