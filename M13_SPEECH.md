# M13 Controlled Speech Announcement (M13 — normative)

M13 adds ONE outbound action: speaking a single bounded text through
fixed `/usr/bin/say`. Chosen because broadcast audio has no
addressee (the recipient-identity problem that blocks messaging),
no network, no persistence, and maps exactly onto M8's validated
spawn mechanics. Email/SMS/WhatsApp stay denied (need secrets +
identity we don't have); clipboard/notifications stay out (exfiltration
sink / script-only primitive); voice choice, SSML, audio files, and
background speech stay denied.

## 1. Capability

Exactly `speech.announce` (family `terminal`, pre-existing M2 union —
family is metadata), ops `["announce"]`, Tier2, confirmation
required, sleep-gated, unscoped (text-bound, not scope-bound).

## 2. Proposal + text rules

`{v, operation:"speech-announce", text}` strict — text is the ONLY
untrusted field. 1..500 code points, no truncation, Unicode-safe
counting. Full M8 shell-char set shared (not duplicated) plus
leading-dash rejection (option injection: `-f file` would read a
file) plus M10 secret screening. `/` stays refused conservatively
(text is never path-resolved, but the surface cannot drift weaker).

## 3. Text-bound confirmation (why it exists)

M2 identity (task/capability/operation/resource) cannot cover
payload text — approving "announce something" must never authorize
speaking something else. `TrustedConfirmationRecord.digest?` is
additive: `hasConfirmation` never reads it (existing behavior
bit-identical); new `hasDigestConfirmation` demands exact match on
all five fields. The service computes SHA-256 over the exact
validated text and requires a digest-bound record for THIS task +
capability + op — a generic confirmation that satisfied M2 still
refuses without it. One changed byte needs a new confirmation;
foreign digests never match (no existence oracle either: unknown
and foreign both refuse identically).

## 4. Execution

Fixed `/usr/bin/say`, argv exactly `[text]`, `shell:false`,
`{LC_ALL:"C"}`, ignored stdio, cwd inert, 10 s timeout, single
process-wide flight shared with M8 (one spawned child max across
both). Reuses M8 `runSpawned` mechanics only — M8's registry,
classifier, and command vocabulary cannot resolve `speech.announce`
(unknown → refused, tested both directions), and this service takes
no commandId. No voice/volume/URL/file flags can exist.

## 5. Task/epoch/sleep/kill + audit

Current task + live grant + current epoch + awake + clear kill,
checked pre-authorize and re-checked at spawn. Stale/revoked/
cross-task/rebooted denied with zero spawns (invocation-counted).
Audit: operation, taskId, tier, text digest + length, duration,
outcome — never text, env, or secrets.

## 6. Conversation

Mock `say <text>` (multi-word preserved; strict single-shape
output); router claims `speech-announce` only; M6 import boundary
intact. Real-LLM path unchanged (M12): model output without taskId
binds the envelope; digest confirmation still required.

## 7. Residual risks

Spoken secrets the screen misses are audible (mitigated, not
eliminated — confirmation displays exact text to the approver);
bystander overhearing is inherent to speakers; `say` voice data
could theoretically trigger a download (no `-v` reachable, default
voice present); single-process slot shared with M8 serializes
heterogeneous spawns (documented, acceptable).

## 8. Non-goals

Messaging/email/clipboard/notifications/printing/calendar, voice
selection, SSML, audio files, volume, background speech, secret
vault, autonomy.
