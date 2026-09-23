/**
 * Sensitive-path policy (M3 section 4).
 *
 * Denylist as DEFENSE-IN-DEPTH: primary control is allowlisted roots +
 * M2 grant scopes. These rules deny sensitive locations REGARDLESS of
 * broader grants, so ordinary read access never becomes a
 * secret-extraction primitive.
 *
 * Conservative by design: over-denial is documented and acceptable in
 * M3; under-denial is not. Matching is case-insensitive on basenames
 * because macOS filesystems are often case-insensitive.
 */
import * as os from "node:os";
import * as path from "node:path";

const HOME_PREFIXES = [
  ".ssh",
  ".aws",
  ".gnupg",
  ".pki",
  ".config/gcloud",
  ".docker",
  "Library/Keychains",
] as const;

const SENSITIVE_BASENAMES = [
  // dotenv / env secrets
  ".env",
  // secret-store directory names (anywhere — convention carries risk)
  ".ssh",
  ".aws",
  ".gnupg",
  ".pki",
  // private keys / certs by name
  "id_rsa",
  "id_ed25519",
  "id_ecdsa",
  "authorized_keys",
  // shell / REPL history (may contain pasted secrets)
  ".bash_history",
  ".zsh_history",
  ".node_repl_history",
  ".python_history",
  // credential store files
  ".npmrc",
  ".pypirc",
  ".netrc",
  "_netrc",
  ".git-credentials",
  // browser credential databases (Chrome / Firefox)
  "Login Data",
  "Login Data-journal",
  "Cookies",
  "Web Data",
  "logins.json",
  "key4.db",
  "cert9.db",
] as const;

const SENSITIVE_EXTENSIONS = [".pem", ".key", ".p12", ".pfx"] as const;

export interface SensitivityVerdict {
  readonly sensitive: boolean;
  readonly reason: string;
}

function envBasenameMatch(name: string): boolean {
  const lower = name.toLowerCase();
  if (lower === ".env" || lower.startsWith(".env.")) {
    return true;
  }
  return (SENSITIVE_BASENAMES as ReadonlyArray<string>).includes(lower);
}

/**
 * Evaluate an absolute path. Every path segment is checked against the
 * basename rules; the full path against home-relative secret-store
 * prefixes; the final segment against secret extensions.
 */
export function isSensitivePath(absolutePath: string): SensitivityVerdict {
  const home = os.homedir();
  for (const prefix of HOME_PREFIXES) {
    const full = path.join(home, prefix);
    if (absolutePath === full || absolutePath.startsWith(`${full}/`)) {
      return {
        sensitive: true,
        reason: `inside secret-store location "${prefix}"`,
      };
    }
  }
  const segments = absolutePath.split("/").filter((s) => s.length > 0);
  for (const segment of segments) {
    if (envBasenameMatch(segment)) {
      return {
        sensitive: true,
        reason: `sensitive filename "${segment}"`,
      };
    }
  }
  const last = segments[segments.length - 1] ?? "";
  const dot = last.lastIndexOf(".");
  const ext = dot >= 0 ? last.slice(dot).toLowerCase() : "";
  if ((SENSITIVE_EXTENSIONS as ReadonlyArray<string>).includes(ext)) {
    return { sensitive: true, reason: `sensitive extension "${ext}"` };
  }
  return { sensitive: false, reason: "no sensitive-path rule matched" };
}
