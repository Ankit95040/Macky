# M7 Workspace / File Intelligence (M7 — normative)

M7 makes Macky useful for inspecting a trusted workspace through
bounded read-only operations. The planner stays untrusted; M2
authorizes, M3 enforces, M4 audits. No writes, network, or autonomy.

## 1. Model

Trusted app registers workspaces `{id, canonical root, dev+ino}`
(`workspace/registry.ts`). Roots must be absolute, existing,
directories, realpath-resolved, non-sensitive (one authoritative
M3 list, extended in M7 with secret-store dir basenames). Planner
references a registered id + RELATIVE target only. Task binding
`{taskId, workspaceIds}` is trusted per-call context: a claimed id
outside the binding dies before resolution. Workspace narrows WHERE;
M2 grants decide WHETHER.

## 2. Path semantics

Relative-only (absolute/`..`/backslash/NUL rejected outright, never
normalized-away). `join(root, rel)` → existing M3 `resolveWithinRoot`
(realpath containment + sensitivity on both forms) → M2 absolute
grant check → M3 adapter. Roots re-resolved + dev/ino-compared per
request; drift/disappearance fails closed. Single-shot TOCTOU remains
(documented M3 carryover); no locking.

## 3. Operations (all read-only, all via M5→M2→M3)

`file-read`/`dir-list` reuse M3 adapters unchanged. `file-find`,
`content-search`, `tree` are new M3 adapter functions (fixed params:
exactly `{pattern}` / `{query}` / none) authorized by new Tier-0
`filesystem.find/search/tree` capabilities (same trust as
`filesystem.read`) and translated by three explicit M5 table rows —
documented here per the M5 extension rule. Git status/log/diff reuse
the fixed-argv adapter with workspace-relative repos. No commit, push,
or mutating op has vocabulary anywhere.

## 4. Discovery rules

Byte-sorted walks; directory symlinks never descended; file symlinks
resolved + contained or pruned; dangling links pruned; sensitive
paths pruned from discovery with explicit counts (read-time denial
stays primary). Pattern language: exact name, `*`, `*suffix` —
nothing else. Search skips oversized/binary files, caps matches and
line context, sanitizes output. Tree caps depth/nodes with explicit
truncated flags. Every cap reports `truncated`/`pruned`, never silent.

## 5. Limits (single policies in M3 LIMITS; workspace adds only text bounds)

64 KiB files, 200 dir entries, 256 KiB results, depth 8 (tree 6),
2000 visited, 200 find results, 100 matches, 32 KiB search files,
300 tree nodes, 128-char patterns, 256-char queries, 1024-char
paths, 16 workspaces. Full/over ⇒ deterministic refusal.

## 6. Unicode

Shared `truncateText` (code-point split, explicit marker, never lone
surrogates) fixes the M6 issue; M6's orchestrator now uses the same
semantics inline (frozen import boundary preserved). Emoji/CJK/
combining-mark boundary tests included.

## 7. Contracts

Versioned strict results with workspace-relative paths (absolute
paths never surface), bounded fields, explicit truncated flags.
Git keeps existing M3 shapes.

## 8. Conversation

M6 mock gains workspace-relative commands; the orchestrator routes
M7-shaped outputs through an injected router (no new conversation
imports — frozen M6 boundary intact) with trusted per-call workspace
binding. Natural-language understanding awaits a real planner; the
mock proves the trusted path for structured commands.

## 9. Invariants (A–AQ tested)

Registration strictness; no escape/traversal/alias; binding enforced;
root-change safe; caps explicit; patterns/argv fixed; no write/shell/
network/policy/grant vocabulary; sleep/kill/epoch authoritative;
injection inert; contracts relative-only.
