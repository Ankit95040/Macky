/**
 * Shared kernel types. Pure data + type definitions only.
 * No I/O, no side effects, no OS APIs.
 */

/** Kernel privacy states. SLEEP is a security state, not a UI flag. */
export type SleepState = "SLEEP" | "AWAKE";

/**
 * Explicit local wake actions ONLY. There is deliberately no
 * "wake-word" variant: always-listening wake is forbidden by
 * SLEEP_SPEC.md SL5 unless revised through explicit human review.
 */
export type WakeActionKind = "keyboard-shortcut" | "ui-action";

export interface WakeAction {
  kind: WakeActionKind;
}

/**
 * Every activity category gated by SLEEP (SLEEP_SPEC.md SL1).
 * While asleep, ALL of these are OFF with no exceptions.
 */
export const SLEEP_GATED_CATEGORIES = [
  "microphone-capture",
  "screen-capture",
  "screen-recording",
  "keyboard-monitoring",
  "mouse-monitoring",
  "filesystem-watchers",
  "browser-monitoring",
  "llm-inference",
  "memory-writes",
  "background-automation",
  "network-activity",
  "computer-control",
] as const;

export type SleepGatedCategory =
  (typeof SLEEP_GATED_CATEGORIES)[number];

/**
 * Observation/inference categories stay disallowed even when AWAKE
 * in M1 — they require future explicit grants (SLEEP_SPEC.md SL7).
 */
export const AWAKE_RESTRICTED_CATEGORIES: ReadonlySet<SleepGatedCategory> =
  new Set<SleepGatedCategory>([
    "microphone-capture",
    "screen-capture",
    "screen-recording",
    "keyboard-monitoring",
    "mouse-monitoring",
    "filesystem-watchers",
    "browser-monitoring",
    "llm-inference",
  ]);

export type RiskLevel = "low" | "medium" | "high";

export type DecisionVerdict = "allow" | "deny" | "require-confirmation";

export interface Decision {
  verdict: DecisionVerdict;
  reason: string;
}

/**
 * Capability identifiers known to M1. Future capabilities MUST be
 * added here as declarations (data + boundary) — never as
 * unrestricted placeholder implementations (SECURITY_SPEC.md S15).
 */
export type CapabilityId = "system.sleep" | "audit.append" | "audit.read";

export interface CapabilityDeclaration {
  id: CapabilityId;
  risk: RiskLevel;
  requiresConfirmation: boolean;
  sleepGated: boolean;
  description: string;
}
