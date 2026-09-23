# M12 Real LLM Planner Boundary (M12 — normative)

M12 plugs a real LLM in as a proposal generator — and proves it
gains zero authority for it. One inference → one untrusted object →
M5 → M2 → services. Offline by default (deterministic fake);
no SDKs, no tools/function-calling, no retries, no loops.

"The LLM is never an authority source."

## 1. Threat model

Adversaries: hostile model output (all 20+ forgery classes),
prose/multi-object/oversized/duplicate-key payloads, secret-shaped
output, hanging/failing providers, prompt-injected user text,
stale/cross-task/revoked reuse, concurrent inferences, credential
exposure. Defenses: gates → single slot → bounded prompt → timeout
+ abort → byte cap → strict JSON (no repair/extraction) → dup-key
refusal → M5 strictness → M2 grants → sleep/kill/epoch → audit
metadata without secrets.

## 2. Trusted/untrusted split

UNTRUSTED: model text, parsed objects, prompts, history, user text.
TRUSTED: config (endpoint/model/var-name/timeout/tokens), system
prompt (instructional only), request shape (fixed POST, fixed
headers, no cookies, no redirects, no tools), schemas, registry,
grants, sleep/kill/epoch, audit. The API key is read at call time
by provider code and never returned, logged, or embedded.

## 3. Provider + network boundary

`src/llm/` is the ONLY network surface (verified by scan):
fixed HTTPS endpoint from trusted config (no creds/fragments;
localhost/private refused without documented opt-in), POST,
bearer auth, 15 s timeout with AbortSignal, redirect:error.
fetch is injectable for header/body discipline tests. No
planner-chosen URL/method/headers/proxy/cookies. No generic
network capability is added — provider calls are infrastructure,
not planner authority.

## 4. Parsing + M5 integration

Whole-text JSON.parse or refusal; top-level duplicate keys refused
(escape-aware scanner); arrays/scalars refused. The parsed object
is returned AS-IS to the orchestrator, which routes it through the
unchanged M5 boundary (strict proposal + trusted envelope equality
+ closed translation + M2). No second authorization exists.

## 5. Task binding (corrective fix — trusted envelope authoritative)

The LLM does not receive or select task identity. The trusted envelope
is authoritative. A taskId omitted by the planner is bound to the
envelope taskId. A planner-supplied mismatching taskId is rejected.

Concretely: `UntrustedProposalSchema.taskId` is optional. Absent →
the M2 request is built from the envelope value (as it always was).
Present and equal → same result. Present and different → refusal at
M5 proposal validation, before authorization. The M2 request NEVER
uses the proposal value. This is context binding, not repair: no
capability, scope, approval, or other authorization content is ever
inferred — only the routing context the trusted caller already holds
is applied.

## 6. Singularity rules

One inference per adapter instance (second propose throws); one
proposal per inference (single return); at most one tool op per
message (post-tool `final` is synthesized locally, no inference);
one in-flight request per process (slot); no retries; no loop.

## 7. Sleep/kill/epoch + audit + secrets

Gate closure checked BEFORE any provider call (counts prove it);
stale envelopes, revoked grants, and cross-task use refused
downstream. Audit callback receives bounded metadata only
(op/status/code/bytes/duration) — never prompts, responses,
headers, or keys. Synthetic-credential tests cover planner,
audit, conversation, and memory absence.

## 8. Conversation + memory discipline

The adapter implements ConversationPlanner: zero orchestrator/
kernel changes. History forwarded is bounded untrusted text (oldest
drops first); grants/epoch/kill/secrets/paths/decisions never
enter prompts (unit-asserted). No automatic memory writes; no
memory read by the adapter at all.

## 9. Residual risks

A hostile model can waste wall-clock (bounded by timeout/slot);
truncation-free refusal means large-token bills are possible
(mitigated by max_tokens + byte caps, not eliminated); DNS-time
behavior of the real endpoint is the operator's network; task
binding limitation (§5) defers authorized LLM action to M13+;
provider-side logging is outside Macky's control (never send
secrets in prompts — enforced by prompt construction, not by trust).

## 10. Non-goals

Autonomy, retries, loops, tool-calling, model-selected tools/
caps/risk/confirmation, voice, vision, browser/GUI, code exec,
persistent history, auto-memory, training, local models.
