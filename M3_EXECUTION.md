# M3 Trusted Read-Only Execution (M3 — normative)

M3 proves: a real macOS action occurs ONLY downstream of an M2 ALLOW,
through the single `run()` entry point. No LLM, planner, autonomy,
writes, network, or background operation exists.

## 1. Trust boundary

```
untrusted request → M2 authorize() → ALLOW → run() → adapter → macOS
                                                  → sanitized result → audit
```

`run()` authorizes INTERNALLY. There is no `execute(decision)` API:
accepting an external decision would admit forged ALLOWs. The same
request object is authorized and executed in one call, so
post-approval mutation is structurally impossible.

## 2. Exact OS surface (closed allowlist, `EXECUTABLE_OPERATIONS`)

- `system.info:info` — os, osVersion, architecture, hostname, runtime.
  Never the environment, never arbitrary files.
- `filesystem.read:read/list` — single file / single-level directory,
  inside the rebound grant root. No writes, no chmod, no deletes.
- `git.read:status/log/diff` — fixed argv via `execFile`, `cwd` set to
  the validated repo, no shell. No commit/push/reset/clean/checkout.

Gate-5 accounting: `exec`/`spawn`/`eval`/`shell: true` appear nowhere
in `src/`. Git runs via `execFile` (argv execution, no shell) with an
allowlisted binary path, scrubbed `GIT_*` environment, fixed formats,
byte caps, and a 10 s timeout. Arbitrary command strings are
structurally impossible — no string-command API exists.

## 3. Filesystem model (`paths.ts`, `sensitive-paths.ts`)

Re-resolve every path: lexical normalize → realpath both root and
target → containment of the FINAL target → sensitive screening of both
forms. Symlinks are resolved, never assumed; escaping links are
denied. Sensitive locations (SSH/key stores, keychains, `.env*`,
private-key names/extensions, shell history, `.npmrc`/`.netrc`,
browser credential DBs) are denied regardless of grants.

LIMITATION (documented, not solved): TOCTOU — a path swapped between
check and use is not defended. M3 performs single-shot reads; no
privilege boundary is crossed by such a race, but a future executor
with serwisu writes must add open-by-handle discipline.

## 4. Sanitizer (`sanitize.ts`)

NUL/binary refused. Credential patterns redacted via the M2
`redactSecrets`. Redaction is defense-in-depth; path controls are the
authorization. `redacted: boolean` is reported so callers and audit
distinguish complete / redacted / denied.

## 5. Limits (`limits.ts`)

64 KiB file cap, 200 dir entries, 256 KiB result cap, 50 git commits,
128 KiB git output, 10 s timeout, listings never recursive. Over-limit
is a deterministic refusal (`limit.exceeded`), never silent truncation.

## 6. Sleep + kill switch

Sleep is re-checked at the OS boundary inside `run()` (§11): an older
ALLOW cannot execute while asleep, and the executor cannot wake.
Kill switch (`kernel/kill-switch.ts`, pure): engage unconditionally
blocks new operations; disengage needs the opaque trusted key object,
which is never serialized or logged.

Trust note: `run()` takes TWO arguments — the untrusted request and a
trusted context (sleep state, grants, confirmations, kill-switch
state, log) supplied by the trusted caller. The planner only ever
produces the first; it cannot forge, name, or flip anything in the
second, and request-embedded fields claiming to (`killSwitch: false`,
`disengage: true`) are rejected by the strict schema.

## 7. Audit

`authorization.*` (from M2) then exactly one of: `execution.started`
→ `execution.completed` / `execution.failed`, or
`execution.rejected`, plus `result.redacted` / `limit.exceeded` where
applicable. Event details carry operation + safe metadata only — never
file contents, credentials, or keys.
