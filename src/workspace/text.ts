/**
 * Unicode-safe bounded text (M7 section 11 — fixes the M6 issue where
 * truncation could split multi-byte content).
 *
 * Splits on Unicode CODE POINTS (Array.from), never UTF-16 code units,
 * so truncation can never produce lone surrogates or replacement
 * artifacts. Combining marks may separate from their base — cosmetic,
 * still valid Unicode — and every truncation carries an explicit
 * marker. Deterministic for identical input.
 */
export const TRUNCATION_MARKER = "…[truncated]" as const;

export interface TruncatedText {
  readonly text: string;
  readonly truncated: boolean;
}

export function truncateText(text: string, maxChars: number, marker: string = TRUNCATION_MARKER): TruncatedText {
  if (maxChars < 0) {
    return { text: `${marker}`, truncated: true };
  }
  const points = Array.from(text);
  if (points.length <= maxChars) {
    return { text, truncated: false };
  }
  return { text: `${points.slice(0, maxChars).join("")}${marker}`, truncated: true };
}
