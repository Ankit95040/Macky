/**
 * Trusted fetch-URL policy (M9 SSRF defense). HTTPS only, public
 * destinations only, no credentials, no fragments, no explicit ports,
 * no control characters, no IPv6 (refused wholesale in M9 — no use
 * case justifies the parsing risk yet).
 *
 * WHATWG URL parsing normalizes hex/octal/integer IPv4 evasions
 * (0x7f.0.0.1, 2130706433) to dotted decimal BEFORE range checks, and
 * splits userinfo so credential-bearing URLs are structurally
 * visible. Every redirect target is revalidated through this same
 * function by the service. DNS names are accepted syntactically;
 * M9 performs no DNS resolution at all (documented residual for any
 * future real provider: resolve-then-revalidate or equivalent).
 */
import { WEB_LIMITS } from "./limits.js";

export type UrlValidation =
  | { readonly ok: true; readonly url: string }
  | { readonly ok: false; readonly reason: string };

function deny(reason: string): UrlValidation {
  return { ok: false, reason };
}

function ipv4ToInt(host: string): number | undefined {
  const parts = host.split(".");
  if (parts.length !== 4) {
    return undefined;
  }
  let value = 0;
  for (const part of parts) {
    if (!/^\d+$/.test(part)) {
      return undefined;
    }
    const octet = Number(part);
    if (!Number.isInteger(octet) || octet < 0 || octet > 255) {
      return undefined;
    }
    value = value * 256 + octet;
  }
  return value;
}

function inRange(ip: number, base: number, bits: number): boolean {
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return ((ip & mask) >>> 0) === ((base & mask) >>> 0);
}

const IPV4 = (a: number, b: number, c: number, d: number): number =>
  (((((a * 256 + b) * 256 + c) * 256 + d) >>> 0));

function ipv4Denied(ip: number): string | undefined {
  const rules: Array<[number, number, string]> = [
    [IPV4(127, 0, 0, 0), 8, "loopback 127.0.0.0/8"],
    [IPV4(10, 0, 0, 0), 8, "private 10.0.0.0/8"],
    [IPV4(172, 16, 0, 0), 12, "private 172.16.0.0/12"],
    [IPV4(192, 168, 0, 0), 16, "private 192.168.0.0/16"],
    [IPV4(169, 254, 0, 0), 16, "link-local 169.254.0.0/16"],
    [IPV4(100, 64, 0, 0), 10, "shared 100.64.0.0/10"],
    [IPV4(0, 0, 0, 0), 8, "unspecified 0.0.0.0/8"],
    [IPV4(224, 0, 0, 0), 4, "multicast/reserved 224.0.0.0/4"],
  ];
  for (const [base, bits, name] of rules) {
    if (inRange(ip, base, bits)) {
      return name;
    }
  }
  return undefined;
}

const DNS_LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;

export function validateFetchUrl(raw: unknown): UrlValidation {
  if (typeof raw !== "string" || raw.length === 0) {
    return deny("url must be a non-empty string");
  }
  if (raw.length > WEB_LIMITS.MAX_URL_CHARS) {
    return deny("url exceeds length limit");
  }
  if (/[\0-\x1f\x7f]/.test(raw)) {
    return deny("url contains control characters");
  }
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    return deny("malformed URL");
  }
  if (parsed.protocol !== "https:") {
    return deny("only https: allowed");
  }
  if (parsed.username.length > 0 || parsed.password.length > 0) {
    return deny("credential-bearing URLs refused");
  }
  if (parsed.hash.length > 0) {
    return deny("URL fragments refused");
  }
  if (parsed.port !== "") {
    return deny("explicit ports refused");
  }
  let host = parsed.hostname.toLowerCase();
  if (host.endsWith(".")) {
    host = host.slice(0, -1);
  }
  if (host.length === 0) {
    return deny("empty hostname");
  }
  if (host.includes(":")) {
    return deny("IPv6 destinations not supported in M9");
  }
  if (host === "localhost" || host.endsWith(".localhost")) {
    return deny("localhost refused");
  }
  const asInt = ipv4ToInt(host);
  if (asInt !== undefined) {
    const blocked = ipv4Denied(asInt);
    if (blocked !== undefined) {
      return deny(`non-public IPv4 refused (${blocked})`);
    }
    return { ok: true, url: parsed.href };
  }
  // DNS name: conservative shape, must be multi-label (no intranet singles).
  if (!host.includes(".")) {
    return deny("single-label hostnames refused");
  }
  if (host.length > 253) {
    return deny("hostname too long");
  }
  for (const label of host.split(".")) {
    if (!DNS_LABEL.test(label)) {
      return deny("malformed hostname label");
    }
  }
  return { ok: true, url: parsed.href };
}
