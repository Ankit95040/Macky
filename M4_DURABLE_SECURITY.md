# M4 Durable Security State & Audit (M4 — normative)

M4 makes security state and history survive process boundaries
without ever letting restart, corruption, or malformed data grant
authority. No LLM, no autonomy, no memory, no secrets subsystem.

## 1. Security-state model (`persistence/security-state.ts`)

`{ schemaVersion: 1, epoch: N≥1 }`, strict Zod, nothing else. That is
the ENTIRE persisted security state. Sleep/kill/grants/confirmations
are derived per boot (below), never restored — restoring authority is
exactly what §2 forbids. Atomic save (tmp + fsync + rename, 0o600).

## 2. Boot (`bootstrap/boot.ts`, `bootstrap/config.ts`)

Config is trusted-local: absolute state dir (explicit arg or
`MACKY_STATE_DIR`, else `~/.macky`), derived audit/state paths,
`mkdir 0o700`. Boot: load state (missing = epoch 1; invalid = NO
session) → epoch+1 (overflow = NO session) → persist → verify audit
chain (corrupt = NO session) → fresh session (SLEEP, disengaged kill,
zero grants/confirmations) → boot event persisted (failure = NO
session). There is no boot path that yields authority.

## 3. Epoch (`session.ts`)

Persisted counter, +1 per boot. `runDurable` requires an envelope
`{ epoch, request }` (strict) equal to the live epoch; stale envelopes
deny pre-OS-touch. Grants/confirmations are never persisted, so old
process artifacts are doubly void (no epoch match AND no live grant).

## 4. Audit store (`persistence/audit-store.ts`)

JSON Lines, canonical field order, SHA-256 chain (`prevHash`/`hash`,
genesis `"GENESIS"`), per-event seq, ISO ts (informational only —
epoch is the security ordering), epoch, type, redacted detail, sleep.
O_APPEND + fsync, 0o600. Single-writer model (one process owns the
dir); multi-process concurrency is out of scope and stated, not solved.

## 5. Integrity = tamper EVIDENCE, precisely

Detection covers: malformed lines, partial tails, schema violations,
broken hashes, broken links, seq gaps/duplicates. Guarantee: any
modification of a verified prefix is detectable on next verify/open.
Non-guarantee: a privileged local attacker can delete or truncate the
file — detectable only by absence, never prevented. No secrets are
hashed in (hashes cover redacted text only).

## 6. Recovery: never automatic

`verifyAuditFile` reports ok/events/errors with the valid prefix
identified. Corrupt tail ⇒ boot refuses. Recovery is the explicit
operator function `repairAuditToPrefix` (tested, incl. real-process
recovery). History is never rewritten by normal operation.

## 7. Failure policy (§6, exact)

Authorization decisions are always computable in-memory. EXECUTION
completion additionally requires audit persistence: `runDurable`
probes the sink BEFORE dispatch (refuse pre-OS-touch when unwritable/
full) and persists the event delta after; any persistence failure
marks the session degraded and all subsequent calls refuse until a
fresh boot. Result always distinguishes decision / persisted /
not-persisted (`auditPersisted`).

## 8. Limits

5 MiB audit file, 4 KiB event, 2 KiB detail. Full ⇒ `audit-full`
refusal, never rotation/deletion in M4.

## 9. Kill/sleep durability

Kill engagement is process-lifetime (key never leaves memory);
persisting it without a trusted disengage path would brick, so it is
NOT persisted — safety is carried by forced SLEEP + epoch bump, which
is strictly more restrictive than any pre-restart state (documented
§13 rationale). Sleep is ALWAYS SLEEP at boot, including after awake
shutdowns.

## 10. Invariants → tests

1. Restart never grants authority — reboot + stale-envelope suites.
2. Startup sleeps/non-observing — first/second boot + integration.
3. Old auth cannot cross epochs — stale envelope/grant/confirmation.
4. Invalid persisted state ⇒ no active state — corrupt-state boots.
5. Corruption never becomes trusted history — verify/repair suites.
6. Planner cannot steer persistence — forged envelope fields; sink
   paths derived from trusted config only.
7. Audit holds no secrets — synthetic PEM/token/password suites.
8. Security state not planner-controlled — strict schema rejects
   forged fields; state path never from requests.
9. No autonomy — static scan (no schedulers/daemons/loops in src).
10. No LLM — static scan (no SDKs/models/network in src).

Carryovers: M3 TOCTOU note stands; `src/kernel/` remains OS-free
(audit event-type additions only); M1/M2/M3 behavior frozen.
