/**
 * Strict provider-response parsing (M12). Byte limit → must-be-string
 * → whole-text JSON.parse → duplicate top-level key rejection →
 * untrusted object out. No repair, no prose extraction, no unknown-
 * field stripping, no guessing, no natural-language inference.
 * Prose-wrapped JSON, multi-object blobs, and huge payloads all fail
 * closed here; anything parseable still faces the M5 boundary.
 */
import { LLM_LIMITS } from "./limits.js";

export type ParsedResponse =
  | { readonly ok: true; readonly value: unknown }
  | { readonly ok: false; readonly reason: string };

/**
 * Detect duplicate keys in the TOP-LEVEL object of raw JSON text.
 * Single-pass scanner (brace depth, escape-aware strings). Returns
 * false for malformed input — malformation is JSON.parse's job;
 * this fires only on well-formed objects with repeated keys.
 * (Duplicate keys would otherwise collapse silently in JSON.parse;
 * M5 strictness neutralizes the collapsed value, but refusing the
 * smuggling shape itself is the conservative M12 policy.)
 */
export function hasDuplicateTopLevelKeys(text: string): boolean {
  const seen = new Set<string>();
  let i = 0;
  const n = text.length;
  const skipWs = (): void => {
    while (i < n && (text[i] === " " || text[i] === "\t" || text[i] === "\n" || text[i] === "\r")) {
      i += 1;
    }
  };
  const readString = (): string | undefined => {
    // Assumes text[i] === '"'. Decodes escapes so equivalent key
    // spellings ("\u0041" vs "A") compare equal.
    const simple: Record<string, string> = { n: "\n", t: "\t", r: "\r", b: "\b", f: "\f", '"': '"', "\\": "\\", "/": "/" };
    let out = "";
    i += 1;
    while (i < n) {
      const ch = text[i];
      if (ch === "\\") {
        const next = text[i + 1];
        if (next === undefined) {
          return undefined;
        }
        if (next === "u") {
          const hex = text.slice(i + 2, i + 6);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) {
            return undefined;
          }
          out += String.fromCharCode(parseInt(hex, 16));
          i += 6;
          continue;
        }
        const mapped = simple[next];
        if (mapped === undefined) {
          return undefined;
        }
        out += mapped;
        i += 2;
        continue;
      }
      if (ch === '"') {
        i += 1;
        return out;
      }
      out += ch;
      i += 1;
    }
    return undefined;
  };
  const skipValue = (): boolean => {
    skipWs();
    if (i >= n) {
      return false;
    }
    const ch = text[i];
    if (ch === '"') {
      return readString() !== undefined;
    }
    if (ch === "{" || ch === "[") {
      const open = ch;
      const close = ch === "{" ? "}" : "]";
      i += 1;
      let depth = 1;
      let inStr = false;
      while (i < n && depth > 0) {
        const c = text[i];
        if (inStr) {
          if (c === "\\") {
            i += 2;
            continue;
          }
          if (c === '"') {
            inStr = false;
          }
          i += 1;
          continue;
        }
        if (c === '"') {
          inStr = true;
          i += 1;
          continue;
        }
        if (c === open) {
          depth += 1;
        } else if (c === close) {
          depth -= 1;
        }
        i += 1;
      }
      return depth === 0;
    }
    while (i < n && text[i] !== "," && text[i] !== "}" && text[i] !== "]") {
      i += 1;
    }
    return true;
  };
  skipWs();
  if (text[i] !== "{") {
    return false;
  }
  i += 1;
  for (;;) {
    skipWs();
    if (i >= n) {
      return false;
    }
    if (text[i] === "}") {
      return false;
    }
    if (text[i] !== '"') {
      return false;
    }
    const key = readString();
    if (key === undefined) {
      return false;
    }
    skipWs();
    if (text[i] !== ":") {
      return false;
    }
    if (seen.has(key)) {
      return true;
    }
    seen.add(key);
    i += 1;
    if (!skipValue()) {
      return false;
    }
    skipWs();
    if (text[i] === ",") {
      i += 1;
      continue;
    }
    if (text[i] === "}") {
      return false;
    }
    return false;
  }
}

export function parseLlmResponse(raw: unknown, maxBytes?: number): ParsedResponse {
  const cap = maxBytes ?? LLM_LIMITS.MAX_RESPONSE_BYTES;
  if (typeof raw !== "string") {
    return { ok: false, reason: "provider response is not text" };
  }
  if (Buffer.byteLength(raw, "utf8") > cap) {
    return { ok: false, reason: "provider response exceeds size limit" };
  }
  const trimmed = raw.trim();
  let value: unknown;
  try {
    value = JSON.parse(trimmed) as unknown;
  } catch {
    return { ok: false, reason: "provider response is not strict JSON" };
  }
  if (hasDuplicateTopLevelKeys(trimmed)) {
    return { ok: false, reason: "duplicate top-level keys rejected" };
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return { ok: false, reason: "provider response must be a JSON object" };
  }
  return { ok: true, value };
}
