/**
 * Trusted M10 registry (Tier1 only). Maps the three operations to
 * their M2 capabilities. No Tier2/Tier3 memory capability exists; no
 * generic/admin/execute/export/import/policy capability exists. Risk
 * comes from here alone.
 */
export interface MemoryCapability {
  readonly operation: "memory-read" | "memory-write" | "memory-delete";
  readonly capability: string;
  readonly riskTier: 1;
}

const REGISTRY: Record<string, MemoryCapability> = {
  "memory-read": { operation: "memory-read", capability: "memory.read", riskTier: 1 },
  "memory-write": { operation: "memory-write", capability: "memory.write", riskTier: 1 },
  "memory-delete": { operation: "memory-delete", capability: "memory.delete", riskTier: 1 },
};

export function classifyMemoryOperation(operation: string): MemoryCapability | undefined {
  return REGISTRY[operation];
}

export function knownMemoryCapabilities(): ReadonlyArray<string> {
  return Object.freeze(["memory.read", "memory.write", "memory.delete"]);
}
