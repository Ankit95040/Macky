/**
 * SLEEP state machine (normative: SLEEP_SPEC.md).
 * Pure functions only. No timers, no listeners, no I/O.
 */
import {
  AWAKE_RESTRICTED_CATEGORIES,
  SLEEP_GATED_CATEGORIES,
  type SleepGatedCategory,
  type SleepState,
  type WakeActionKind,
} from "./types.js";

const WAKE_ACTIONS: ReadonlySet<string> = new Set<string>([
  "keyboard-shortcut",
  "ui-action",
]);

function isWakeActionKind(value: unknown): value is WakeActionKind {
  return typeof value === "string" && WAKE_ACTIONS.has(value);
}

/** Kernel construction always yields SLEEP (SL3/SL4). */
export function initialSleepState(): SleepState {
  return "SLEEP";
}

/**
 * Wake requires an explicit local action (SL5).
 * Anything else fails closed: stays asleep.
 */
export function requestWake(
  state: SleepState,
  action: unknown,
): SleepState {
  if (state === "AWAKE") {
    return "AWAKE";
  }
  if (
    typeof action === "object" &&
    action !== null &&
    "kind" in action &&
    isWakeActionKind((action as { kind: unknown }).kind)
  ) {
    return "AWAKE";
  }
  return "SLEEP";
}

/** Sleep is always available, unconditionally (SL6). */
export function enterSleep(_state: SleepState): SleepState {
  return "SLEEP";
}

/**
 * Deterministic gate (SL2). SLEEP denies every gated category.
 * AWAKE denies observation/inference categories until future
 * explicit grants; remaining categories are sleep-open but still
 * subject to policy + confirmation downstream.
 */
export function isCategoryAllowed(
  state: SleepState,
  category: SleepGatedCategory,
): boolean {
  if (state === "SLEEP") {
    return false;
  }
  return !AWAKE_RESTRICTED_CATEGORIES.has(category);
}

/** Test helper: every category SLEEP_SPEC.md SL1 enumerates. */
export function allGatedCategories(): ReadonlyArray<SleepGatedCategory> {
  return SLEEP_GATED_CATEGORIES;
}
