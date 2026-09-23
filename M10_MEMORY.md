# M10 Trusted Memory Boundary (M10 — normative)

M10 adds durable local memory as INFORMATION ONLY. Memory cannot
create, modify, grant, revoke, escalate, or infer authority — this
is tested, not asserted. No embeddings, no vector DB, no network,
no autonomy, no background writes.

## 1. Threat model

Adversaries: forged trusted metadata in proposals, poisoned content
(including the nine canonical injections, stored and re-read),
secret-bearing content, oversized/corrupt storage, stale/revoked/
cross-task authority, planner-reachable paths/IDs. Defenses, in
order: strict schemas → trusted registry → task-bound M2 grants →
sleep/kill/slot → secret screen → atomic bounded commit → metadata-
only audit. Content is validated for storage, then treated as data
forever after.

## 2. Trusted/untrusted split

Planner controls ONLY content + kind. Trusted: schema, limits,
storage root, IDs (`mem-<uuid>`), timestamps, task/epoch context,
decisions, sleep/kill, audit, retention (create-only + explicit
delete; no other lifecycle). Retrieved text, queries, summaries —
untrusted, always.

## 3. Record model

`{v:1, id, content, kind, createdAt, updatedAt, source, taskId,
epoch}` — content stored EXACTLY as supplied (no dedup, inference,
or rewriting); kind is descriptive. Single trusted namespace;
planner chooses no location/tenant/user.

## 4. Capabilities

Exactly `memory.read/write/delete`, Tier1, family `memory`,
sleep-gated, unscoped (namespace validated by M10, not M2 scopes).
No admin/execute/export/import/policy/search capability exists.

## 5. Persistence

One bounded JSON file (`memory.json`, 0o600, 0o700 dir), tmp +
fsync + rename. Strict versioned validation on every load;
malformed storage fails closed at open. Count (1000), per-record
(8 KiB), and total (4 MiB) caps enforced BEFORE disk is touched;
in-memory state swaps only on success, so failed writes mutate
nothing. Memory survives reboot; authority never does (grants live
only in-session) — both directions tested.

## 6. Authorization flow

Proposal → registry classification → kill/sleep/slot → M2
authorize() (sole authority; live task grants) → boundary re-check
→ substring search (normalized, deterministic, insertion-ordered)
or create-only write or durable delete → versioned contract →
audit. No `execute(decision)` equivalent exists. Reads return
cross-task matches as inert data (single-user namespace); writes
bind the CURRENT trusted task; deletes need existence + live grant.

## 7. Injection/poisoning containment

Nine canonical injections stored, re-read, and executed-around:
grants, registry, epoch, sleep, kill, task binding unchanged;
terminal/web attempts without grants still refused. Poison is data
with provenance, never instruction.

## 8. Secrets

Heuristic screen (PEM headers, key/token/password assignments)
refuses obviously unsafe writes — documented as imperfect; the
structural guarantee (content ≠ authority) holds when it misses.
Content and queries NEVER enter audit (operation, status, id,
counts, bytes only).

## 9. Bounds

4096 content chars / 1000 records / 256 query chars / 20 results /
4 MiB storage / 8 KiB records / 64 KiB payloads — all code-point
measured. Oversized refused, never clamped. Documented tension:
4096 astral chars are legal input but exceed the 8 KiB record cap
and fail loudly at commit.

## 10. Sleep/kill/epoch + audit + conversation

All three ops sleep-gated; kill blocks new work; stale/revoked/
cross-task/rebooted authority denied. Mock verbs
(`memoryread|write|delete`) route through an injected router; the
frozen M6 import boundary is intact (literals, no new imports).

## 11. Residual risks

Substring search has no ranking (insertion order); heuristic screen
is bypassable by obfuscation (accepted: authority boundary holds);
single-process slot; cross-task reads visible within the local
single-user namespace (documented decision, not a leak path to
authority); no backup/rotation story yet.

## 12. Non-goals

Semantic/embedding search, auto-remember, summarization,
background writes, model-driven memory, secret vault, multi-user
tenancy, cloud sync, encryption layer.
