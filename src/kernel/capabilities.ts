/**
 * Capability declarations: DATA + interfaces only (S3/S15).
 * No implementations. No shell, filesystem, network, or macOS APIs —
 * not even as placeholders. Future tools sit behind these
 * declarations and the policy/confirmation gates.
 */
import type { CapabilityDeclaration, CapabilityId } from "./types.js";

export const CAPABILITIES: ReadonlyArray<CapabilityDeclaration> =
  Object.freeze([
    Object.freeze({
      id: "system.sleep",
      risk: "low",
      requiresConfirmation: false,
      sleepGated: false,
      description:
        "Enter SLEEP. Always available, unconditionally (SL6).",
    } satisfies CapabilityDeclaration),
    Object.freeze({
      id: "audit.append",
      risk: "low",
      requiresConfirmation: false,
      sleepGated: false,
      description:
        "Append to the audit log. Audit stays writable while asleep " +
        "so sleep/wake transitions themselves are recorded (S9).",
    } satisfies CapabilityDeclaration),
    Object.freeze({
      id: "audit.read",
      risk: "low",
      requiresConfirmation: false,
      sleepGated: false,
      description: "Read the audit log.",
    } satisfies CapabilityDeclaration),
  ]);

/** Pure lookup. Unknown ids return undefined (caller must deny). */
export function getCapability(
  id: string,
): CapabilityDeclaration | undefined {
  return CAPABILITIES.find((c: CapabilityDeclaration): boolean => c.id === id);
}

/**
 * Future tool-layer shape. Declared so M2+ has a boundary to
 * implement behind — intentionally NOT implemented in M1.
 */
export interface ToolExecutor {
  readonly capabilityId: CapabilityId;
  execute(_proposal: unknown): Promise<never>;
}
