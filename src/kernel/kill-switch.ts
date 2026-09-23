/**
 * Deterministic kill switch (M3 section 13). Pure data + pure functions.
 *
 * The kill switch prevents NEW executor operations when engaged.
 * Authority model: `createKillSwitch` returns a state/key pair. The key
 * is an opaque object held by trusted setup code only — it is never
 * serialized, never logged, and never appears in any planner-visible
 * structure, so the planner cannot possess or forge it. Engaging needs
 * no key (any trusted path can engage); disengaging requires the exact
 * key. There is deliberately no disengage-by-request path.
 */
export interface KillSwitchState {
  readonly engaged: boolean;
}

export interface KillSwitchKey {
  readonly token: number;
}

export interface KillSwitch {
  readonly state: KillSwitchState;
  readonly key: KillSwitchKey;
}

let nextToken = 1;

export function createKillSwitch(): KillSwitch {
  const key: KillSwitchKey = Object.freeze({ token: nextToken });
  nextToken += 1;
  return {
    state: Object.freeze({ engaged: false }),
    key,
  };
}

/** Engage from any state. Unconditional — going safe never needs approval. */
export function engageKillSwitch(_state: KillSwitchState): KillSwitchState {
  return Object.freeze({ engaged: true });
}

/**
 * Disengage requires the exact trusted key. Wrong/missing keys fail
 * closed: the switch stays engaged.
 */
export function disengageKillSwitch(
  state: KillSwitchState,
  key: unknown,
  expected: KillSwitchKey,
): KillSwitchState {
  if (
    typeof key === "object" &&
    key !== null &&
    (key as KillSwitchKey).token === expected.token
  ) {
    return Object.freeze({ engaged: false });
  }
  return state;
}

export function isEngaged(state: KillSwitchState): boolean {
  return state.engaged === true;
}
