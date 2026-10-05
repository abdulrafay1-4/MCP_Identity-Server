import https from "node:https";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  CimdClient,
  CimdError,
  isCandidateCimdClientId,
  isLoopbackOrCustomSchemeRedirectUri,
  isRedirectUriAllowedForApplicationType,
  type CimdFetch,
  type ResolveHostname
} from "../src/cimd.js";

function stubResolver(overrides: Record<string, string[]> = {}): ResolveHostname {
  const IP_LITERAL = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[0-9a-fA-F:]+)$/;
  return async (host) => {
    if (host in overrides) return overrides[host] ?? [];
    if (IP_LITERAL.test(host)) return [host];
    return ["93.184.216.34"];
  };
}

function jsonResponse(body: unknown, init: { status?: number; headers?: Record<string, string> } = {}): Response {
  return new Response(JSON.stringify(body), {
    status: init.status ?? 200,
    headers: { "content-type": "application/json", ...init.headers }
  });
}

function countingFetch(): { fetch: CimdFetch; calls: () => number } {
  let count = 0;
  const fetch: CimdFetch = async () => {
    count++;
    return jsonResponse(VALID_DOC);
  };
  return { fetch, calls: () => count };
}

const VALID_URL = "https://client.example.com/metadata.json";
const VALID_DOC = {
  client_id: VALID_URL,
  client_name: "Test Agent",
  redirect_uris: ["https://client.example.com/callback"]
};

describe("isCandidateCimdClientId", () => {
  it("accepts an https URL with a path component", () => {
    expect(isCandidateCimdClientId("https://example.com/client.json")).toBeDefined();
  });
  it("rejects a non-https scheme", () => {
    expect(isCandidateCimdClientId("http://example.com/client.json")).toBeUndefined();
  });
  it("rejects a URL with no path component", () => {
    expect(isCandidateCimdClientId("https://example.com")).toBeUndefined();
    expect(isCandidateCimdClientId("https://example.com/")).toBeUndefined();
  });
  it("rejects a non-URL string", () => {
    expect(isCandidateCimdClientId("demo-agent-client")).toBeUndefined();
  });
});

describe("isLoopbackOrCustomSchemeRedirectUri", () => {
  it("treats an IPv4 loopback redirect_uri as loopback", () => {
    expect(isLoopbackOrCustomSchemeRedirectUri("http://127.0.0.1:4000/callback")).toBe(true);
  });
  it("treats a bracketed IPv6 loopback redirect_uri as loopback", () => {
    expect(isLoopbackOrCustomSchemeRedirectUri("http://[::1]:4000/callback")).toBe(true);
  });
  it("treats a localhost redirect_uri as loopback", () => {
    expect(isLoopbackOrCustomSchemeRedirectUri("http://localhost:4000/callback")).toBe(true);
  });
  it("treats a custom URI scheme as loopback-or-custom-scheme", () => {
    expect(isLoopbackOrCustomSchemeRedirectUri("myagent://callback")).toBe(true);
  });
  it("does not treat an ordinary public https redirect_uri as loopback", () => {
    expect(isLoopbackOrCustomSchemeRedirectUri("https://client.example.com/callback")).toBe(false);
  });
  it("fails closed (treats as loopback-or-custom-scheme) for an unparseable redirect_uri", () => {
    expect(isLoopbackOrCustomSchemeRedirectUri("not a uri at all")).toBe(true);
  });
});

describe("isRedirectUriAllowedForApplicationType", () => {
  it("allows a native client to use a loopback redirect_uri", () => {
    expect(isRedirectUriAllowedForApplicationType("http://127.0.0.1:4000/callback", "native")).toBe(true);
  });
  it("allows a native client to use a custom-scheme redirect_uri", () => {
    expect(isRedirectUriAllowedForApplicationType("myagent://callback", "native")).toBe(true);
  });
  it("allows a native client to use an ordinary https redirect_uri too", () => {
    expect(isRedirectUriAllowedForApplicationType("https://client.example.com/callback", "native")).toBe(true);
  });
  it("rejects a web client using a loopback redirect_uri", () => {
    expect(isRedirectUriAllowedForApplicationType("http://127.0.0.1:4000/callback", "web")).toBe(false);
  });
  it("rejects a web client using a custom-scheme redirect_uri", () => {
    expect(isRedirectUriAllowedForApplicationType("myagent://callback", "web")).toBe(false);
  });
  it("allows a web client using an ordinary https redirect_uri", () => {
    expect(isRedirectUriAllowedForApplicationType("https://client.example.com/callback", "web")).toBe(true);
  });
});

describe("CimdClient.fetchMetadata: happy path", () => {
  it("fetches, validates, and returns a well-formed document", async () => {
    const client = new CimdClient({
      fetch: async () => jsonResponse(VALID_DOC),
      resolveHostname: stubResolver()
    });
    const metadata = await client.fetchMetadata(VALID_URL);
    expect(metadata.clientId).toBe(VALID_URL);
    expect(metadata.clientName).toBe("Test Agent");
    expect(metadata.redirectUris).toEqual(["https://client.example.com/callback"]);
    expect(metadata.applicationType).toBe("web");
  });

  it("parses application_type: native", async () => {
    const client = new CimdClient({
      fetch: async () => jsonResponse({ ...VALID_DOC, application_type: "native" }),
      resolveHostname: stubResolver()
    });
    const metadata = await client.fetchMetadata(VALID_URL);
    expect(metadata.applicationType).toBe("native");
  });
});

describe("CimdClient.fetchMetadata: format validation (no network attempted)", () => {
  it("rejects non-https before ever fetching", async () => {
    const { fetch, calls } = countingFetch();
    const client = new CimdClient({ fetch, resolveHostname: stubResolver() });
    await expect(client.fetchMetadata("http://client.example.com/metadata.json")).rejects.toThrow(CimdError);
    expect(calls()).toBe(0);
  });

  it("rejects a URL with no path component before ever fetching", async () => {
    const { fetch, calls } = countingFetch();
    const client = new CimdClient({ fetch, resolveHostname: stubResolver() });
    await expect(client.fetchMetadata("https://client.example.com")).rejects.toThrow(CimdError);
    expect(calls()).toBe(0);
  });
});

describe("CimdClient.fetchMetadata: document validation", () => {
  it("rejects a client_id mismatch (document names a different URL)", async () => {
    const client = new CimdClient({
      fetch: async () => jsonResponse({ ...VALID_DOC, client_id: "https://other.example.com/metadata.json" }),
      resolveHostname: stubResolver()
    });
    await expect(client.fetchMetadata(VALID_URL)).rejects.toThrow(CimdError);
  });

  it("rejects a document missing client_name", async () => {
    const { client_name, ...rest } = VALID_DOC;
    void client_name;
    const client = new CimdClient({ fetch: async () => jsonResponse(rest), resolveHostname: stubResolver() });
    await expect(client.fetchMetadata(VALID_URL)).rejects.toThrow(CimdError);
  });

  it("rejects a document missing redirect_uris", async () => {
    const { redirect_uris, ...rest } = VALID_DOC;
    void redirect_uris;
    const client = new CimdClient({ fetch: async () => jsonResponse(rest), resolveHostname: stubResolver() });
    await expect(client.fetchMetadata(VALID_URL)).rejects.toThrow(CimdError);
  });

  it("rejects a document missing client_id", async () => {
    const { client_id, ...rest } = VALID_DOC;
    void client_id;
    const client = new CimdClient({ fetch: async () => jsonResponse(rest), resolveHostname: stubResolver() });
    await expect(client.fetchMetadata(VALID_URL)).rejects.toThrow(CimdError);
  });

  it("rejects malformed JSON", async () => {
    const client = new CimdClient({
      fetch: async () => new Response("not json{{{", { status: 200 }),
      resolveHostname: stubResolver()
    });
    await expect(client.fetchMetadata(VALID_URL)).rejects.toThrow(CimdError);
  });

  it("rejects a non-2xx response", async () => {
    const client = new CimdClient({
      fetch: async () => jsonResponse(VALID_DOC, { status: 404 }),
      resolveHostname: stubResolver()
    });
    await expect(client.fetchMetadata(VALID_URL)).rejects.toThrow(CimdError);
  });
});

describe("CimdClient.fetchMetadata: SSRF mitigations", () => {
  it("blocks a literal loopback IPv4 host before ever fetching", async () => {
    const { fetch, calls } = countingFetch();
    const client = new CimdClient({ fetch, resolveHostname: stubResolver() });
    await expect(client.fetchMetadata("https://127.0.0.1/client.json")).rejects.toThrow(CimdError);
    expect(calls()).toBe(0);
  });

  it("blocks literal IPv6 loopback ([::1]) before ever fetching", async () => {
    const { fetch, calls } = countingFetch();
    const client = new CimdClient({ fetch, resolveHostname: stubResolver() });
    await expect(client.fetchMetadata("https://[::1]/client.json")).rejects.toThrow(CimdError);
    expect(calls()).toBe(0);
  });

  it("blocks 10.0.0.0/8 before ever fetching", async () => {
    const { fetch, calls } = countingFetch();
    const client = new CimdClient({ fetch, resolveHostname: stubResolver() });
    await expect(client.fetchMetadata("https://10.1.2.3/client.json")).rejects.toThrow(CimdError);
    expect(calls()).toBe(0);
  });

  it("blocks 172.16.0.0/12 before ever fetching", async () => {
    const { fetch, calls } = countingFetch();
    const client = new CimdClient({ fetch, resolveHostname: stubResolver() });
    await expect(client.fetchMetadata("https://172.20.0.5/client.json")).rejects.toThrow(CimdError);
    expect(calls()).toBe(0);
  });

  it("blocks 192.168.0.0/16 before ever fetching", async () => {
    const { fetch, calls } = countingFetch();
    const client = new CimdClient({ fetch, resolveHostname: stubResolver() });
    await expect(client.fetchMetadata("https://192.168.1.1/client.json")).rejects.toThrow(CimdError);
    expect(calls()).toBe(0);
  });

  it("blocks the cloud metadata address 169.254.169.254 before ever fetching", async () => {
    const { fetch, calls } = countingFetch();
    const client = new CimdClient({ fetch, resolveHostname: stubResolver() });
    await expect(client.fetchMetadata("https://169.254.169.254/client.json")).rejects.toThrow(CimdError);
    expect(calls()).toBe(0);
  });

  it("blocks a DNS name that resolves to a loopback address, via the injected resolver, before ever fetching", async () => {
    const { fetch, calls } = countingFetch();
    const client = new CimdClient({
      fetch,
      resolveHostname: stubResolver({ "evil.attacker.example": ["127.0.0.1"] })
    });
    await expect(client.fetchMetadata("https://evil.attacker.example/client.json")).rejects.toThrow(CimdError);
    expect(calls()).toBe(0);
  });

  it("blocks a DNS name that resolves to a private address, via the injected resolver, before ever fetching", async () => {
    const { fetch, calls } = countingFetch();
    const client = new CimdClient({
      fetch,
      resolveHostname: stubResolver({ "evil.attacker.example": ["10.0.0.99"] })
    });
    await expect(client.fetchMetadata("https://evil.attacker.example/client.json")).rejects.toThrow(CimdError);
    expect(calls()).toBe(0);
  });

  it("blocks a hostname when even one of several resolved addresses is internal", async () => {
    const { fetch, calls } = countingFetch();
    const client = new CimdClient({
      fetch,
      resolveHostname: stubResolver({ "multi.example.com": ["93.184.216.34", "127.0.0.1"] })
    });
    await expect(client.fetchMetadata("https://multi.example.com/client.json")).rejects.toThrow(CimdError);
    expect(calls()).toBe(0);
  });

  it("does not follow a redirect: passes redirect: \"manual\" to fetch, and treats an unfollowed 3xx as a failure", async () => {
    let capturedRedirectOption: string | undefined;
    const client = new CimdClient({
      fetch: async (_url, init) => {
        capturedRedirectOption = init.redirect;
        return new Response(null, { status: 302, headers: { location: "https://client.example.com/moved.json" } });
      },
      resolveHostname: stubResolver()
    });
    await expect(client.fetchMetadata(VALID_URL)).rejects.toThrow(CimdError);
    expect(capturedRedirectOption).toBe("manual");
  });

  it("rejects a response over the byte cap", async () => {
    const client = new CimdClient({
      fetch: async () => jsonResponse({ ...VALID_DOC, client_name: "x".repeat(200_000) }),
      resolveHostname: stubResolver(),
      maxBytes: 1024
    });
    await expect(client.fetchMetadata(VALID_URL)).rejects.toThrow(CimdError);
  });

  it("never includes the internal failure reason in the thrown error's message", async () => {
    const { fetch, calls } = countingFetch();
    const client = new CimdClient({ fetch, resolveHostname: stubResolver() });
    try {
      await client.fetchMetadata("https://169.254.169.254/client.json");
      expect.fail("expected fetchMetadata to throw");
    } catch (error) {
      expect(error).toBeInstanceOf(CimdError);
      expect((error as CimdError).reason).toBe("blocked_address");
    }
    expect(calls()).toBe(0);
  });
});

describe("CimdClient.fetchMetadata: address classification", () => {
  async function expectBlockedUrl(url: string): Promise<void> {
    const { fetch, calls } = countingFetch();
    const client = new CimdClient({ fetch, resolveHostname: stubResolver() });
    await expect(client.fetchMetadata(url)).rejects.toMatchObject({ reason: "blocked_address" });
    expect(calls()).toBe(0);
  }

  async function expectBlockedResolution(address: string): Promise<void> {
    const { fetch, calls } = countingFetch();
    const client = new CimdClient({
      fetch,
      resolveHostname: stubResolver({ "evil.attacker.example": [address] })
    });
    await expect(client.fetchMetadata("https://evil.attacker.example/client.json")).rejects.toMatchObject({
      reason: "blocked_address"
    });
    expect(calls()).toBe(0);
  }

  it.each([
    ["IPv4-mapped loopback, hex form", "https://[::ffff:7f00:1]/client.json"],
    ["IPv4-mapped loopback, dotted form", "https://[::ffff:127.0.0.1]/client.json"],
    ["IPv4-mapped cloud metadata address", "https://[::ffff:169.254.169.254]/client.json"],
    ["IPv4-mapped RFC 1918", "https://[::ffff:10.1.2.3]/client.json"],
    ["NAT64 embedding loopback", "https://[64:ff9b::7f00:1]/client.json"],
    ["NAT64 embedding loopback, dotted form", "https://[64:ff9b::127.0.0.1]/client.json"],
    ["NAT64 embedding the metadata address", "https://[64:ff9b::169.254.169.254]/client.json"],
    ["6to4 embedding loopback", "https://[2002:7f00:1::]/client.json"],
    ["6to4 embedding RFC 1918", "https://[2002:c0a8:101::1]/client.json"],
    ["IPv4-compatible loopback", "https://[::7f00:1]/client.json"],
    ["IPv4-compatible RFC 1918, dotted form", "https://[::10.0.0.1]/client.json"],
    ["unspecified IPv4", "https://0.0.0.0/client.json"],
    ["unspecified IPv6", "https://[::]/client.json"],
    ["unique-local fc00::/7 (fd)", "https://[fd00::1]/client.json"],
    ["unique-local fc00::/7 (fc)", "https://[fc00::1]/client.json"],
    ["IPv6 link-local", "https://[fe80::1]/client.json"],
    ["IPv6 multicast", "https://[ff02::1]/client.json"],
    ["NAT64 local-use prefix", "https://[64:ff9b:1::1]/client.json"],
    ["CGNAT 100.64.0.0/10", "https://100.64.0.1/client.json"],
    ["IPv4 multicast", "https://224.0.0.1/client.json"]
  ])("blocks a literal host: %s", async (_label, url) => {
    await expectBlockedUrl(url);
  });

  it.each([
    ["decimal", "https://2130706433/client.json"],
    ["octal", "https://0177.0.0.1/client.json"],
    ["hex", "https://0x7f.0.0.1/client.json"],
    ["hex, single number", "https://0x7f000001/client.json"],
    ["short form", "https://127.1/client.json"]
  ])("blocks a numeric IPv4 spelling (%s) that the URL parser rewrites to 127.0.0.1", async (_label, url) => {
    expect(new URL(url).hostname).toBe("127.0.0.1");
    await expectBlockedUrl(url);
  });

  it.each([
    ["IPv4-mapped loopback", "::ffff:127.0.0.1"],
    ["IPv4-mapped metadata address", "::ffff:169.254.169.254"],
    ["IPv4-mapped CGNAT", "::ffff:100.64.0.1"],
    ["NAT64 embedding RFC 1918", "64:ff9b::10.0.0.1"],
    ["6to4 embedding link-local", "2002:a9fe:a9fe::1"],
    ["IPv4-compatible loopback", "::127.0.0.1"],
    ["IPv6 loopback", "::1"],
    ["scoped link-local", "fe80::1%eth0"],
    ["something that is not an address", "not-an-ip"]
  ])("blocks a DNS name that resolves to %s", async (_label, address) => {
    await expectBlockedResolution(address);
  });

  it.each([
    ["IPv4-mapped public", "::ffff:93.184.216.34"],
    ["NAT64 embedding a public address", "64:ff9b::5db8:d822"],
    ["6to4 embedding a public address", "2002:5db8:d822::1"],
    ["ordinary public IPv6", "2606:2800:220:1:248:1893:25c8:1946"]
  ])("does not block a DNS name that resolves to %s", async (_label, address) => {
    const { fetch, calls } = countingFetch();
    const client = new CimdClient({ fetch, resolveHostname: stubResolver({ "client.example.com": [address] }) });
    await expect(client.fetchMetadata(VALID_URL)).resolves.toMatchObject({ clientId: VALID_URL });
    expect(calls()).toBe(1);
  });
});

describe("CimdClient.fetchMetadata: connection is pinned to the vetted addresses", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("hands the fetch exactly the addresses it vetted, and resolves only once (DNS rebinding)", async () => {
    let resolutions = 0;
    let pinned: string[] | undefined;
    const client = new CimdClient({
      resolveHostname: async () => (++resolutions === 1 ? ["93.184.216.34"] : ["127.0.0.1"]),
      fetch: async (_url, init) => {
        pinned = init.addresses;
        return jsonResponse(VALID_DOC);
      }
    });
    await client.fetchMetadata(VALID_URL);
    expect(pinned).toEqual(["93.184.216.34"]);
    expect(resolutions).toBe(1);
  });

  it("vets a literal IP host as itself and never asks the resolver about it", async () => {
    const { fetch, calls } = countingFetch();
    let resolutions = 0;
    const client = new CimdClient({
      fetch,
      resolveHostname: async () => {
        resolutions++;
        return ["93.184.216.34"];
      }
    });
    await expect(client.fetchMetadata("https://127.0.0.1/client.json")).rejects.toMatchObject({
      reason: "blocked_address"
    });
    expect(calls()).toBe(0);
    expect(resolutions).toBe(0);
  });

  it("pins a permitted literal IP host to that same address", async () => {
    let pinned: string[] | undefined;
    const client = new CimdClient({
      fetch: async (_url, init) => {
        pinned = init.addresses;
        return jsonResponse({ ...VALID_DOC, client_id: "https://93.184.216.34/client.json" });
      }
    });
    await client.fetchMetadata("https://93.184.216.34/client.json");
    expect(pinned).toEqual(["93.184.216.34"]);
  });

  it("the default transport connects only to the vetted address and verifies TLS against the hostname", async () => {
    let resolutions = 0;
    let captured: https.RequestOptions | undefined;
    vi.spyOn(https, "request").mockImplementation(((options: https.RequestOptions) => {
      captured = options;
      throw new Error("no network in tests");
    }) as unknown as typeof https.request);

    const client = new CimdClient({
      resolveHostname: async () => (++resolutions === 1 ? ["93.184.216.34"] : ["127.0.0.1"])
    });
    await expect(client.fetchMetadata("https://pinned.test/metadata.json")).rejects.toMatchObject({
      reason: "fetch_failed"
    });

    expect(captured).toBeDefined();
    const lookup = captured?.lookup as NonNullable<https.RequestOptions["lookup"]>;
    const answers = await new Promise<unknown>((resolve) => lookup("pinned.test", { all: true }, (_err, addrs) => resolve(addrs)));
    expect(answers).toEqual([{ address: "93.184.216.34", family: 4 }]);
    const single = await new Promise<unknown[]>((resolve) =>
      lookup("pinned.test", {}, (_err, address, family) => resolve([address, family]))
    );
    expect(single).toEqual(["93.184.216.34", 4]);
    expect(resolutions).toBe(1);

    expect(captured?.host).toBe("pinned.test");
    expect(captured?.servername).toBe("pinned.test");
    expect(captured?.rejectUnauthorized).not.toBe(false);
    expect(captured?.agent).toBe(false);
  });
});

describe("CimdClient.fetchMetadata: one deadline covers the whole fetch", () => {
  async function outcome(promise: Promise<unknown>, withinMs: number): Promise<string> {
    let guard: ReturnType<typeof setTimeout> | undefined;
    const pending = new Promise<string>((resolve) => {
      guard = setTimeout(() => resolve("still pending"), withinMs);
    });
    try {
      return await Promise.race([
        promise.then(
          () => "resolved",
          (error: unknown) => (error instanceof CimdError ? `rejected: ${error.reason}` : "rejected: not a CimdError")
        ),
        pending
      ]);
    } finally {
      clearTimeout(guard);
    }
  }

  function chunkedResponse(chunks: string[], gapMs: number, onCancel: () => void = () => {}): Response {
    const encoder = new TextEncoder();
    let timer: ReturnType<typeof setInterval> | undefined;
    let sent = 0;
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        timer = setInterval(() => {
          const next = chunks[sent++];
          if (next === undefined) {
            clearInterval(timer);
            controller.close();
            return;
          }
          controller.enqueue(encoder.encode(next));
        }, gapMs);
        timer.unref();
      },
      cancel() {
        clearInterval(timer);
        onCancel();
      }
    });
    return new Response(body, { status: 200 });
  }

  function trickleResponse(onCancel?: () => void): Response {
    return chunkedResponse(["{", ...new Array<string>(100_000).fill(" ")], 20, onCancel);
  }

  it("rejects a body that trickles in after the headers, within roughly timeoutMs", async () => {
    const client = new CimdClient({
      fetch: async () => trickleResponse(),
      resolveHostname: stubResolver(),
      timeoutMs: 300
    });
    const started = performance.now();
    expect(await outcome(client.fetchMetadata(VALID_URL), 2_000)).toBe("rejected: timeout");
    expect(performance.now() - started).toBeLessThan(1_000);
  });

  it("rejects a fetch that never produces headers, even if the transport ignores the abort signal", async () => {
    const client = new CimdClient({
      fetch: () => new Promise<Response>(() => {}),
      resolveHostname: stubResolver(),
      timeoutMs: 200
    });
    expect(await outcome(client.fetchMetadata(VALID_URL), 2_000)).toBe("rejected: timeout");
  });

  it("rejects a resolver that never answers", async () => {
    const { fetch, calls } = countingFetch();
    const client = new CimdClient({
      fetch,
      resolveHostname: () => new Promise<string[]>(() => {}),
      timeoutMs: 200
    });
    expect(await outcome(client.fetchMetadata(VALID_URL), 2_000)).toBe("rejected: timeout");
    expect(calls()).toBe(0);
  });

  it("aborts the transport's signal and stops reading the body when the deadline passes", async () => {
    let signal: AbortSignal | undefined;
    let cancelled = false;
    const client = new CimdClient({
      fetch: async (_url, init) => {
        signal = init.signal;
        return trickleResponse(() => {
          cancelled = true;
        });
      },
      resolveHostname: stubResolver(),
      timeoutMs: 200
    });
    await outcome(client.fetchMetadata(VALID_URL), 2_000);
    expect(signal?.aborted).toBe(true);
    expect(cancelled).toBe(true);
  });

  it("still accepts a body that arrives slowly but inside the deadline", async () => {
    const parts = JSON.stringify(VALID_DOC).match(/.{1,20}/g) ?? [];
    const client = new CimdClient({
      fetch: async () => chunkedResponse(parts, 20),
      resolveHostname: stubResolver(),
      timeoutMs: 2_000
    });
    await expect(client.fetchMetadata(VALID_URL)).resolves.toMatchObject({ clientId: VALID_URL });
  });

  it("enforces the byte cap on a streamed body with no Content-Length", async () => {
    const client = new CimdClient({
      fetch: async () => chunkedResponse(new Array<string>(50).fill("x".repeat(100)), 1),
      resolveHostname: stubResolver(),
      maxBytes: 1_000
    });
    await expect(client.fetchMetadata(VALID_URL)).rejects.toMatchObject({ reason: "response_too_large" });
  });

  it("enforces the byte cap from Content-Length before reading the body", async () => {
    const client = new CimdClient({
      fetch: async () => jsonResponse(VALID_DOC, { headers: { "content-length": "999999" } }),
      resolveHostname: stubResolver(),
      maxBytes: 1_000
    });
    await expect(client.fetchMetadata(VALID_URL)).rejects.toMatchObject({ reason: "response_too_large" });
  });
});

describe("CimdClient.fetchMetadata: caching", () => {
  it("serves a second request from cache within max-age, without refetching", async () => {
    let fetchCount = 0;
    const client = new CimdClient({
      fetch: async () => {
        fetchCount++;
        return jsonResponse(VALID_DOC, { headers: { "cache-control": "max-age=300" } });
      },
      resolveHostname: stubResolver()
    });
    await client.fetchMetadata(VALID_URL);
    await client.fetchMetadata(VALID_URL);
    expect(fetchCount).toBe(1);
  });

  it("refetches once the cached entry expires", async () => {
    let current = new Date("2026-01-01T00:00:00Z");
    let fetchCount = 0;
    const client = new CimdClient({
      fetch: async () => {
        fetchCount++;
        return jsonResponse(VALID_DOC, { headers: { "cache-control": "max-age=60" } });
      },
      resolveHostname: stubResolver(),
      now: () => current
    });
    await client.fetchMetadata(VALID_URL);
    current = new Date(current.getTime() + 61_000);
    await client.fetchMetadata(VALID_URL);
    expect(fetchCount).toBe(2);
  });

  it("does not cache a response with Cache-Control: no-store", async () => {
    let fetchCount = 0;
    const client = new CimdClient({
      fetch: async () => {
        fetchCount++;
        return jsonResponse(VALID_DOC, { headers: { "cache-control": "no-store" } });
      },
      resolveHostname: stubResolver()
    });
    await client.fetchMetadata(VALID_URL);
    await client.fetchMetadata(VALID_URL);
    expect(fetchCount).toBe(2);
  });

  it("does not cache a response with no cache-control header at all", async () => {
    let fetchCount = 0;
    const client = new CimdClient({
      fetch: async () => {
        fetchCount++;
        return jsonResponse(VALID_DOC);
      },
      resolveHostname: stubResolver()
    });
    await client.fetchMetadata(VALID_URL);
    await client.fetchMetadata(VALID_URL);
    expect(fetchCount).toBe(2);
  });
});
