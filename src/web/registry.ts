/**
 * Trusted M9 registry (Tier1 only). Maps the two operations to their
 * M2 capabilities. No Tier2/Tier3 web capability exists; no generic
 * network/browser capability exists. Risk comes from here alone.
 */
export interface WebCapability {
  readonly operation: "web-search" | "web-fetch";
  readonly capability: string;
  readonly riskTier: 1;
}

const REGISTRY: Record<string, WebCapability> = {
  "web-search": { operation: "web-search", capability: "web.search", riskTier: 1 },
  "web-fetch": { operation: "web-fetch", capability: "web.fetch", riskTier: 1 },
};

export function classifyWebOperation(operation: string): WebCapability | undefined {
  return REGISTRY[operation];
}

export function knownWebCapabilities(): ReadonlyArray<string> {
  return Object.freeze(["web.search", "web.fetch"]);
}
