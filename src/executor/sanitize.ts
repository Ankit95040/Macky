/**
 * Result sanitization (M3 section 5).
 *
 * Every adapter result passes through here before returning to the
 * untrusted side. Redaction is DEFENSE-IN-DEPTH, not authorization:
 * sensitive files are already denied by path controls. Regex redaction
 * cannot guarantee secret detection, so binary or ambiguous content
 * fails closed to denial rather than being returned.
 */
import { redactSecrets } from "../kernel/audit.js";

export type SanitizedResult =
  | {
      readonly ok: true;
      readonly text: string;
      readonly redacted: boolean;
    }
  | { readonly ok: false; readonly reason: string };

/**
 * Sanitize decoded text. Binary (NUL bytes) is denied outright.
 * Returns whether redaction changed anything so the audit trail can
 * record "sensitive result redacted" without logging the content.
 */
export function sanitizeText(text: string): SanitizedResult {
  if (text.includes("\0")) {
    return { ok: false, reason: "binary content refused" };
  }
  const redacted = redactSecrets(text);
  return {
    ok: true,
    text: redacted,
    redacted: redacted !== text,
  };
}
