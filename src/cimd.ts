import { lookup as dnsLookup } from "node:dns/promises";
import https from "node:https";
import { BlockList, isIP } from "node:net";
import { Readable } from "node:stream";

// Client ID Metadata Documents: the client_id is an https URL that /authorize fetches
// to learn the client's redirect URIs. The URL comes from an unauthenticated caller, so
// the fetch is locked down: https only, every resolved address checked against the
// blocklist and then pinned for the connection, no redirects, one deadline, a size cap.

/** Must connect only to `addresses`, verify TLS against the URL's hostname and not follow redirects. */
export type CimdFetch = (
  url: string,
  init: { signal: AbortSignal; redirect: "manual"; addresses: string[] }
) => Promise<Response>;
export type ResolveHostname = (hostname: string) => Promise<string[]>;

export interface CimdMetadata {
  clientId: string;
  clientName: string;
  redirectUris: string[];
  applicationType: "native" | "web";
}

/**
 * Every failure is this error. `reason` is for logs only: an HTTP response that told
 * failures apart would let callers probe internal hosts.
 */
export class CimdError extends Error {
  public readonly reason: string;
  constructor(reason: string) {
    super(`CIMD fetch failed: ${reason}`);
    this.name = "CimdError";
    this.reason = reason;
  }
}

const DEFAULT_TIMEOUT_MS = 3_000;
const DEFAULT_MAX_BYTES = 65_536;
const DEFAULT_CACHE_TTL_MS = 5 * 60_000;

export interface CimdClientOptions {
  fetch?: CimdFetch;
  resolveHostname?: ResolveHostname;
  now?: () => Date;
  timeoutMs?: number;
  maxBytes?: number;
}

interface CacheEntry {
  metadata: CimdMetadata;
  etag: string | undefined;
  expiresAtMs: number;
}

export function isCandidateCimdClientId(clientId: string): URL | undefined {
  let url: URL;
  try {
    url = new URL(clientId);
  } catch {
    return undefined;
  }
  if (url.protocol !== "https:") {
    return undefined;
  }
  if (url.pathname.length <= 1) {
    return undefined;
  }
  return url;
}

/** An unparseable URI counts as loopback, so it fails the stricter web-client check. */
export function isLoopbackOrCustomSchemeRedirectUri(redirectUri: string): boolean {
  let url: URL;
  try {
    url = new URL(redirectUri);
  } catch {
    return true;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return true;
  }
  const hostname = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  return hostname === "127.0.0.1" || hostname === "::1" || hostname === "localhost";
}

/**
 * Native clients may use loopback, custom-scheme or https redirects. Web clients may not
 * use loopback or custom-scheme ones.
 */
export function isRedirectUriAllowedForApplicationType(redirectUri: string, applicationType: "native" | "web"): boolean {
  if (applicationType === "native") {
    return true;
  }
  return !isLoopbackOrCustomSchemeRedirectUri(redirectUri);
}

const BLOCKED_IPV4: ReadonlyArray<readonly [string, number]> = [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10], // CGNAT
  ["127.0.0.0", 8],
  ["169.254.0.0", 16], // link-local, includes the 169.254.169.254 metadata address
  ["172.16.0.0", 12],
  ["192.168.0.0", 16],
  ["224.0.0.0", 3] // multicast, reserved and broadcast
];

const BLOCKED_IPV6: ReadonlyArray<readonly [string, number]> = [
  ["fc00::", 7], // unique-local
  ["fe80::", 10], // link-local
  ["ff00::", 8], // multicast
  ["64:ff9b:1::", 48] // NAT64 local-use
];

function buildBlockList(): BlockList {
  const list = new BlockList();
  for (const [network, prefix] of BLOCKED_IPV4) {
    list.addSubnet(network, prefix, "ipv4");
    // BlockList already applies IPv4 rules to IPv4-mapped IPv6 (::ffff:a.b.c.d). These
    // other forms also embed an IPv4 address, so they are blocked with it.
    const [a = 0, b = 0, c = 0, d = 0] = network.split(".").map(Number);
    const embedded = `${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
    list.addSubnet(`::${embedded}`, 96 + prefix, "ipv6"); // IPv4-compatible, covers :: and ::1
    list.addSubnet(`64:ff9b::${embedded}`, 96 + prefix, "ipv6"); // NAT64
    list.addSubnet(`2002:${embedded}::`, 16 + prefix, "ipv6"); // 6to4
  }
  for (const [network, prefix] of BLOCKED_IPV6) {
    list.addSubnet(network, prefix, "ipv6");
  }
  return list;
}

const blockList = buildBlockList();

function isBlockedIp(ip: string): boolean {
  const version = isIP(ip);
  if (version === 0) return true; // not an IP at all
  return blockList.check(ip, version === 4 ? "ipv4" : "ipv6");
}

async function defaultResolveHostname(hostname: string): Promise<string[]> {
  const results = await dnsLookup(hostname, { all: true, verbatim: true });
  return results.map((r) => r.address);
}

/**
 * node:https with a DNS lookup that only returns the vetted addresses, so a second
 * resolution can't move the connection somewhere else. `ca` exists for tests.
 */
export function createPinnedFetch(options: { ca?: string } = {}): CimdFetch {
  return (url, { signal, addresses }) =>
    new Promise<Response>((resolve, reject) => {
      const target = new URL(url);
      const host = target.hostname.replace(/^\[|\]$/g, "");
      const req = https.request(
        {
          host,
          port: target.port || 443,
          path: `${target.pathname}${target.search}`,
          headers: { accept: "application/json" },
          agent: false, // no pooled sockets
          servername: isIP(host) ? "" : host, // no SNI for IP literals
          ca: options.ca,
          lookup: (_hostname, lookupOptions, callback) => {
            const entries = addresses.map((address) => ({ address, family: isIP(address) }));
            const first = entries[0];
            if (!first) {
              callback(new Error("no vetted address") as NodeJS.ErrnoException, "", 0);
            } else if (lookupOptions.all) {
              callback(null, entries);
            } else {
              callback(null, first.address, first.family);
            }
          },
          signal
        },
        (res) => {
          try {
            const headers = new Headers();
            for (const [name, value] of Object.entries(res.headers)) {
              if (value !== undefined) for (const v of [value].flat()) headers.append(name, v);
            }
            const status = res.statusCode ?? 0;
            const hasBody = status !== 204 && status !== 205 && status !== 304;
            if (!hasBody) res.resume();
            resolve(
              new Response(hasBody ? (Readable.toWeb(res) as unknown as ReadableStream<Uint8Array>) : null, {
                status,
                headers
              })
            );
          } catch (error) {
            res.destroy();
            reject(error);
          }
        }
      );
      req.once("error", reject);
      req.end();
    });
}

async function withDeadline<T>(ms: number, run: (signal: AbortSignal) => Promise<T>): Promise<T> {
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const expired = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new CimdError("timeout")), ms);
  });
  try {
    // Raced, so a transport that ignores the signal still can't outlive the deadline.
    return await Promise.race([run(controller.signal), expired]);
  } finally {
    clearTimeout(timer);
    controller.abort();
  }
}

async function readBodyWithCap(res: Response, maxBytes: number, signal: AbortSignal): Promise<string> {
  const contentLength = res.headers.get("content-length");
  if (contentLength !== null && Number(contentLength) > maxBytes) {
    throw new CimdError("response_too_large");
  }

  const reader = res.body?.getReader();
  if (!reader) {
    const text = await res.text();
    if (Buffer.byteLength(text, "utf-8") > maxBytes) {
      throw new CimdError("response_too_large");
    }
    return text;
  }

  signal.addEventListener("abort", () => void reader.cancel().catch(() => {}), { once: true });
  let total = 0;
  const chunks: Buffer[] = [];
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        total += value.byteLength;
        if (total > maxBytes) {
          throw new CimdError("response_too_large");
        }
        chunks.push(Buffer.from(value));
      }
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  return Buffer.concat(chunks).toString("utf-8");
}

interface CacheDirectives {
  noStore: boolean;
  maxAgeMs: number | undefined;
}

function parseCacheControl(header: string | null): CacheDirectives {
  if (!header) return { noStore: false, maxAgeMs: undefined };
  const directives = header.split(",").map((d) => d.trim().toLowerCase());
  const noStore = directives.includes("no-store") || directives.includes("no-cache");
  const maxAgeDirective = directives.find((d) => d.startsWith("max-age="));
  const maxAgeSeconds = maxAgeDirective ? Number(maxAgeDirective.slice("max-age=".length)) : undefined;
  const maxAgeMs = maxAgeSeconds !== undefined && Number.isFinite(maxAgeSeconds) && maxAgeSeconds >= 0 ? maxAgeSeconds * 1000 : undefined;
  return { noStore, maxAgeMs };
}

/** Missing or unknown means web: the OIDC default, and the stricter redirect rule. */
function parseApplicationType(value: unknown): "native" | "web" {
  return value === "native" ? "native" : "web";
}

function parseMetadataDocument(raw: unknown, expectedClientId: string): CimdMetadata {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new CimdError("invalid_document_structure");
  }
  const doc = raw as Record<string, unknown>;

  if (typeof doc.client_id !== "string" || doc.client_id.length === 0) {
    throw new CimdError("missing_client_id");
  }
  if (typeof doc.client_name !== "string" || doc.client_name.length === 0) {
    throw new CimdError("missing_client_name");
  }
  if (!Array.isArray(doc.redirect_uris) || doc.redirect_uris.length === 0 || !doc.redirect_uris.every((u) => typeof u === "string")) {
    throw new CimdError("missing_redirect_uris");
  }

  // Exact match, no normalization.
  if (doc.client_id !== expectedClientId) {
    throw new CimdError("client_id_mismatch");
  }

  return {
    clientId: doc.client_id,
    clientName: doc.client_name,
    redirectUris: doc.redirect_uris as string[],
    applicationType: parseApplicationType(doc.application_type)
  };
}

export class CimdClient {
  private readonly fetchImpl: CimdFetch;
  private readonly resolveHostname: ResolveHostname;
  private readonly now: () => Date;
  private readonly timeoutMs: number;
  private readonly maxBytes: number;
  private readonly cache = new Map<string, CacheEntry>();

  constructor(options: CimdClientOptions = {}) {
    this.fetchImpl = options.fetch ?? createPinnedFetch();
    this.resolveHostname = options.resolveHostname ?? defaultResolveHostname;
    this.now = options.now ?? ((): Date => new Date());
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
  }

  async fetchMetadata(clientIdUrl: string): Promise<CimdMetadata> {
    const nowMs = this.now().getTime();
    const cached = this.cache.get(clientIdUrl);
    if (cached && nowMs < cached.expiresAtMs) {
      return cached.metadata;
    }

    const url = isCandidateCimdClientId(clientIdUrl);
    if (!url) {
      throw new CimdError("invalid_client_id_format");
    }

    let res: Response;
    let body: string;
    try {
      ({ res, body } = await withDeadline(this.timeoutMs, async (signal) => {
        const addresses = await this.resolveSafeAddresses(url.hostname);
        const res = await this.fetchImpl(url.toString(), { signal, redirect: "manual", addresses });
        if (!res.ok) {
          throw new CimdError("http_error");
        }
        return { res, body: await readBodyWithCap(res, this.maxBytes, signal) };
      }));
    } catch (error) {
      throw error instanceof CimdError ? error : new CimdError("fetch_failed");
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(body);
    } catch {
      throw new CimdError("invalid_json");
    }

    const metadata = parseMetadataDocument(parsed, clientIdUrl);

    const cacheControl = parseCacheControl(res.headers.get("cache-control"));
    if (!cacheControl.noStore && cacheControl.maxAgeMs !== undefined) {
      this.cache.set(clientIdUrl, {
        metadata,
        etag: res.headers.get("etag") ?? undefined,
        expiresAtMs: nowMs + cacheControl.maxAgeMs
      });
    } else {
      this.cache.delete(clientIdUrl);
    }

    return metadata;
  }

  private async resolveSafeAddresses(hostname: string): Promise<string[]> {
    const host = hostname.replace(/^\[|\]$/g, "");
    let addresses: string[];
    try {
      addresses = isIP(host) ? [host] : await this.resolveHostname(host);
    } catch {
      throw new CimdError("resolution_failed");
    }
    if (addresses.length === 0) {
      throw new CimdError("resolution_failed");
    }
    if (addresses.some((address) => isBlockedIp(address))) {
      throw new CimdError("blocked_address");
    }
    return addresses;
  }
}
