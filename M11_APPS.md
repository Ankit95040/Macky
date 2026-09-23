# M11 Controlled macOS Application Launch (M11 — normative)

M11 launches ONLY registered macOS applications — one primitive,
no control afterward. Planner names a logical id; the registry owns
every path; M2 authorizes; a direct `/usr/bin/open` spawn launches.
No mouse, keyboard, GUI automation, scripts, URLs, or files.

## 1. Threat model

Adversaries: forged paths/argv/env/cwd/URLs/privilege/risk/caps in
proposals; traversal/symlink/drifted/missing bundle attacks;
sleep/kill/stale/cross-task launches; injection text; launcher
hangs/failures. Defenses: strict schema (appId ONLY) → registry
lookup (unknown dies pathless) → kill/sleep/slot → M2 live grants
→ boundary re-check → fresh identity verification → fixed-argv
spawn → bounded contract → metadata audit.

## 2. Trusted/untrusted split

UNTRUSTED: planner output, app names/ids, external/memory/web/
terminal text, launch outcomes. TRUSTED: registry (3 verified
entries below), tiers, task/epoch/sleep/kill, authorization,
launcher path/argv/env, audit. The planner never sees a path.

## 3. Capability

Exactly `app.launch` (family `app-control`, pre-existing M2 union —
family is metadata), Tier1, no confirmation, sleep-gated, unscoped
(registry-bound). No execute/control/terminate/install/register/
open-url/open-file/gui capability exists.

## 4. Registry (verified on-machine, Sequoia layout)

`app.textedit` → /System/Applications/TextEdit.app (+ MacOS/TextEdit),
`app.calculator` → /System/Applications/Calculator.app (+ MacOS/Calculator),
`app.terminal` → /System/Applications/Utilities/Terminal.app (+ MacOS/Terminal).
Static, frozen, no discovery, no planner registration. Test
registries are separate construction paths, never production.

## 5. Identity + paths

Per launch: absolute + canonical (realpath equality — drift refuses),
existence, executable-is-file-inside-bundle containment, Info.plist
presence, X_OK. Code-signing/publisher identity NOT verified —
documented limitation; path checks prove location, not authorship.

## 6. Launch primitive

Static `/usr/bin/open` (existence + file check), direct spawn,
argv exactly `[bundlePath]` (no -a/--args/operands), `shell:false`,
env `{LC_ALL:"C"}` only, stdio ignored, 10 s timeout with
TERM→KILL inside production launcher AND a service-level race
(double safety). Slot guard: 1 in flight. Controls the LAUNCHER
process only — a launched GUI app persists under macOS ownership,
outside M11 termination authority (explicit).

## 7. Task/epoch/sleep/kill + audit

Current task + live grant + current epoch + awake + clear kill,
checked pre-authorize and re-checked at the launcher boundary.
Stale/revoked/cross-task/rebooted launches denied; registry itself
survives reboot as static config. Audit: operation, registry appId,
status, duration, exit — never paths, env, secrets, or content.
Planner has no sink access.

## 8. Conversation

Mock `launch <word>` → `{appId: app.<word>}`; multi-word tails fail
the strict language (refused whole). Router claims `app-launch`
only; M6 import boundary intact.

## 9. Residual risks

No publisher-identity proof (see §5); post-launch app behavior is
macOS's domain; realpath-stability assumed per machine (verified
here; a firmlinked layout would refuse safely, not bypass);
single-process slot; no launch history beyond audit.

## 10. Non-goals

GUI control, scripts, URLs/files-as-operands, installs, sudo,
termination, watchers, discovery, network, autonomy.
