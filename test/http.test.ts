import { randomBytes } from "node:crypto";
import type { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { CimdClient } from "../src/cimd.js";
import { loadDemoClient, type DemoClient } from "../src/config/client.js";
import type { Config } from "../src/config/env.js";
import { createApp } from "../src/http/app.js";
import type { AppEnv } from "../src/http/requestLogging.js";
import { getJwks, loadOrGenerateKeys, type KeyRing } from "../src/keys.js";
import { createLogger, silentSink } from "../src/log.js";
import { computeS256Challenge } from "../src/pkce.js";
import { MemoryTokenStore } from "../src/store/memory.js";
import { verify } from "../src/tokens.js";

const ISSUER = "https://auth.example.com";
const CLIENT: DemoClient = loadDemoClient({
  CLIENT_ID: "demo-agent-client",
  CLIENT_SECRET: "demo-client-secret-change-me",
  CLIENT_REDIRECT_URI: "https://agent.example.com/callback",
  CLIENT_AUDIENCE: "https://mcp.example.com/mcp"
});
const WRONG_CLIENT_SECRET = "not-the-secret";

const PRIVATE_KEY_FIELDS = ["d", "p", "q", "dp", "dq", "qi"];

interface Harness {
  app: Hono<AppEnv>;
  store: MemoryTokenStore;
  keys: KeyRing;
  config: Config;
  setNow: (date: Date) => void;
}

async function buildHarness(initial: Date, cimdClient?: CimdClient): Promise<Harness> {
  let current = initial;
  const now = (): Date => current;
  const keys = await loadOrGenerateKeys();
  const store = new MemoryTokenStore({ now });
  const config: Config = {
    issuer: ISSUER,
    port: 0,
    tokenTtlSeconds: 300,
    pruneIntervalMs: 60_000,
    maxDelegationDepth: 5,
    refreshTokenTtlSeconds: 2_592_000,
    refreshReuseGraceSeconds: 10,
    keyRingPath: ".data/test-keys.json",
    rateLimitMax: 1000,
    rateLimitWindowSeconds: 60,
    logLevel: "info"
  };
  const logger = createLogger({ sink: silentSink, now });
  const app = createApp({ config, keys, store, client: CLIENT, now, logger, cimdClient });
  return { app, store, keys, config, setNow: (date) => (current = date) };
}

function basicAuthHeader(clientId: string, clientSecret: string): string {
  return `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString("base64")}`;
}

function pkcePair(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString("base64url");
  return { verifier, challenge: computeS256Challenge(verifier) };
}

interface AuthorizeOverrides {
  response_type?: string;
  client_id?: string;
  redirect_uri?: string;
  scope?: string;
  state?: string;
  code_challenge?: string;
  code_challenge_method?: string;
  agent_id?: string;
  resource?: string;
}

async function authorize(app: Hono<AppEnv>, overrides: AuthorizeOverrides): Promise<Response> {
  const base: Record<string, string> = {
    response_type: "code",
    client_id: CLIENT.clientId,
    redirect_uri: CLIENT.redirectUri,
    scope: "filings:read",
    state: "xyz-state-123",
    agent_id: "research-bot"
  };
  const definedOverrides = Object.fromEntries(Object.entries(overrides).filter(([, v]) => v !== undefined));
  const merged = { ...base, ...definedOverrides };
  const params = new URLSearchParams(merged);
  return app.request(`/authorize?${params.toString()}`);
}

async function getValidCode(app: Hono<AppEnv>, challenge: string): Promise<{ code: string; state: string }> {
  const res = await authorize(app, { code_challenge: challenge, code_challenge_method: "S256" });
  expect(res.status).toBe(302);
  const location = res.headers.get("Location");
  if (!location) throw new Error("expected a Location header");
  const url = new URL(location);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  if (!code || !state) throw new Error(`expected code+state in redirect, got ${location}`);
  return { code, state };
}

async function requestToken(
  app: Hono<AppEnv>,
  body: Record<string, string>,
  auth: { clientId: string; clientSecret: string } = CLIENT
): Promise<Response> {
  return app.request("/token", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: basicAuthHeader(auth.clientId, auth.clientSecret)
    },
    body: new URLSearchParams(body).toString()
  });
}

describe("GET /.well-known/oauth-authorization-server", () => {
  it("advertises the required discovery fields, including S256", async () => {
    const { app } = await buildHarness(new Date("2026-01-01T00:00:00Z"));
    const res = await app.request("/.well-known/oauth-authorization-server");
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;

    expect(body.issuer).toBe(ISSUER);
    expect(body.authorization_endpoint).toBe(`${ISSUER}/authorize`);
    expect(body.token_endpoint).toBe(`${ISSUER}/token`);
    expect(body.jwks_uri).toBe(`${ISSUER}/jwks.json`);
    expect(body.introspection_endpoint).toBe(`${ISSUER}/introspect`);
    expect(body.revocation_endpoint).toBe(`${ISSUER}/revoke`);
    expect(body.code_challenge_methods_supported).toContain("S256");
    expect(body.code_challenge_methods_supported).not.toContain("plain");
  });
});

describe("GET /jwks.json", () => {
  it("exposes only public key material", async () => {
    const { app, keys } = await buildHarness(new Date("2026-01-01T00:00:00Z"));
    const res = await app.request("/jwks.json");
    expect(res.status).toBe(200);
    const body = (await res.json()) as { keys: Array<Record<string, unknown>> };

    expect(body.keys).toHaveLength(1);
    expect(body.keys[0]?.kid).toBe(keys.keys[0]?.kid);
    expect(body.keys[0]?.kty).toBe("RSA");

    const serialized = JSON.stringify(body);
    for (const field of PRIVATE_KEY_FIELDS) {
      expect(serialized.includes(`"${field}"`)).toBe(false);
    }

    const direct = await getJwks(keys);
    expect(body).toEqual(JSON.parse(JSON.stringify(direct)));
  });
});

describe("full authorize -> token happy path", () => {
  it("issues a verifiable JWT with the right aud/scope/sub, and echoes state", async () => {
    const { app, keys } = await buildHarness(new Date("2026-01-01T00:00:00Z"));
    const { verifier, challenge } = pkcePair();

    const authRes = await authorize(app, {
      code_challenge: challenge,
      code_challenge_method: "S256",
      scope: "filings:read",
      state: "state-abc",
      agent_id: "research-bot"
    });
    expect(authRes.status).toBe(302);
    const location = authRes.headers.get("Location");
    if (!location) throw new Error("missing Location header");
    const redirectUrl = new URL(location);
    expect(redirectUrl.origin + redirectUrl.pathname).toBe(CLIENT.redirectUri);
    expect(redirectUrl.searchParams.get("state")).toBe("state-abc");
    const code = redirectUrl.searchParams.get("code");
    expect(code).toBeTruthy();

    const tokenRes = await requestToken(app, {
      grant_type: "authorization_code",
      code: code ?? "",
      redirect_uri: CLIENT.redirectUri,
      code_verifier: verifier
    });
    expect(tokenRes.status).toBe(200);
    const tokenBody = (await tokenRes.json()) as { access_token: string; token_type: string; scope: string };
    expect(tokenBody.token_type).toBe("Bearer");
    expect(tokenBody.scope).toBe("filings:read");

    const claims = await verify(tokenBody.access_token, {
      keys,
      issuer: ISSUER,
      audience: CLIENT.audience,
      now: () => new Date("2026-01-01T00:00:00Z")
    });
    expect(claims.aud).toBe(CLIENT.audience);
    expect(claims.scope).toBe("filings:read");
    expect(claims.sub.startsWith("agent:research-bot:")).toBe(true);
  });
});

describe("GET /authorize: redirect_uri exact match", () => {
  it("rejects a redirect_uri that is merely a prefix/substring of the registered one", async () => {
    const { app } = await buildHarness(new Date("2026-01-01T00:00:00Z"));
    const { challenge } = pkcePair();

    const res = await authorize(app, {
      redirect_uri: CLIENT.redirectUri.slice(0, -3),
      code_challenge: challenge,
      code_challenge_method: "S256"
    });

    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("invalid_request");
  });
});

describe("PKCE enforcement", () => {
  it("rejects code_challenge_method=plain", async () => {
    const { app } = await buildHarness(new Date("2026-01-01T00:00:00Z"));
    const { challenge } = pkcePair();

    const res = await authorize(app, { code_challenge: challenge, code_challenge_method: "plain" });
    expect(res.status).toBe(302);
    const location = new URL(res.headers.get("Location") ?? "");
    expect(location.searchParams.get("error")).toBe("invalid_request");
    expect(location.searchParams.get("code")).toBeNull();
  });

  it("rejects a missing code_challenge", async () => {
    const { app } = await buildHarness(new Date("2026-01-01T00:00:00Z"));
    const res = await authorize(app, { code_challenge_method: "S256" });
    expect(res.status).toBe(302);
    const location = new URL(res.headers.get("Location") ?? "");
    expect(location.searchParams.get("error")).toBe("invalid_request");
    expect(location.searchParams.get("code")).toBeNull();
  });
});

describe("RFC 9207: iss parameter on /authorize redirects", () => {
  it("advertises support in discovery metadata", async () => {
    const { app } = await buildHarness(new Date("2026-01-01T00:00:00Z"));
    const res = await app.request("/.well-known/oauth-authorization-server");
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.authorization_response_iss_parameter_supported).toBe(true);
  });

  it("includes iss, byte-identical to discovery's issuer, on a successful redirect", async () => {
    const { app } = await buildHarness(new Date("2026-01-01T00:00:00Z"));
    const { challenge } = pkcePair();

    const discoveryRes = await app.request("/.well-known/oauth-authorization-server");
    const discoveryBody = (await discoveryRes.json()) as { issuer: string };

    const res = await authorize(app, { code_challenge: challenge, code_challenge_method: "S256" });
    expect(res.status).toBe(302);
    const location = new URL(res.headers.get("Location") ?? "");
    expect(location.searchParams.get("code")).toBeTruthy();
    expect(location.searchParams.get("iss")).toBe(discoveryBody.issuer);
    expect(location.searchParams.get("iss")).toBe(ISSUER);
  });

  it("includes iss on an error redirect (e.g. bad scope)", async () => {
    const { app } = await buildHarness(new Date("2026-01-01T00:00:00Z"));
    const { challenge } = pkcePair();

    const res = await authorize(app, {
      scope: "",
      code_challenge: challenge,
      code_challenge_method: "S256"
    });
    expect(res.status).toBe(302);
    const location = new URL(res.headers.get("Location") ?? "");
    expect(location.searchParams.get("error")).toBe("invalid_request");
    expect(location.searchParams.get("iss")).toBe(ISSUER);
  });
});

describe("Client ID Metadata Documents (CIMD)", () => {
  const CIMD_CLIENT_ID = "https://cimd-client.example.com/metadata.json";
  const CIMD_REDIRECT_URI = "https://cimd-client.example.com/callback";

  function jsonResponse(body: unknown, init: { status?: number; headers?: Record<string, string> } = {}): Response {
    return new Response(JSON.stringify(body), {
      status: init.status ?? 200,
      headers: { "content-type": "application/json", ...init.headers }
    });
  }

  function buildCimdClient(docOverrides: Record<string, unknown> = {}, fetchInit: { status?: number; headers?: Record<string, string> } = {}): CimdClient {
    return new CimdClient({
      fetch: async () =>
        jsonResponse(
          {
            client_id: CIMD_CLIENT_ID,
            client_name: "CIMD Test Client",
            redirect_uris: [CIMD_REDIRECT_URI],
            ...docOverrides
          },
          fetchInit
        ),
      resolveHostname: async () => ["93.184.216.34"]
    });
  }

  async function getCimdCode(app: Hono<AppEnv>, challenge: string): Promise<{ code: string }> {
    const res = await authorize(app, {
      client_id: CIMD_CLIENT_ID,
      redirect_uri: CIMD_REDIRECT_URI,
      code_challenge: challenge,
      code_challenge_method: "S256"
    });
    expect(res.status).toBe(302);
    const location = res.headers.get("Location");
    if (!location) throw new Error("expected a Location header");
    const code = new URL(location).searchParams.get("code");
    if (!code) throw new Error(`expected a code in redirect, got ${location}`);
    return { code };
  }

  it("completes authorize -> token for a valid CIMD client (public client, no client secret)", async () => {
    const { app, keys } = await buildHarness(new Date("2026-01-01T00:00:00Z"), buildCimdClient());
    const { verifier, challenge } = pkcePair();
    const { code } = await getCimdCode(app, challenge);

    const tokenRes = await app.request("/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: CIMD_REDIRECT_URI,
        code_verifier: verifier,
        client_id: CIMD_CLIENT_ID
      }).toString()
    });
    expect(tokenRes.status).toBe(200);
    const body = (await tokenRes.json()) as { access_token: string; scope: string };
    const claims = await verify(body.access_token, {
      keys,
      issuer: ISSUER,
      audience: CLIENT.audience,
      now: () => new Date("2026-01-01T00:00:00Z")
    });
    expect(claims.scope).toBe("filings:read");
  });

  it("rejects redemption of a CIMD client's code when the wrong client_id is presented", async () => {
    const { app } = await buildHarness(new Date("2026-01-01T00:00:00Z"), buildCimdClient());
    const { verifier, challenge } = pkcePair();
    const { code } = await getCimdCode(app, challenge);

    const tokenRes = await app.request("/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: CIMD_REDIRECT_URI,
        code_verifier: verifier,
        client_id: "https://someone-else.example.com/metadata.json"
      }).toString()
    });
    expect(tokenRes.status).toBe(401);
  });

  it("rejects a document whose client_id does not match the fetch URL exactly", async () => {
    const cimdClient = buildCimdClient({ client_id: "https://different-url.example.com/metadata.json" });
    const { app } = await buildHarness(new Date("2026-01-01T00:00:00Z"), cimdClient);
    const { challenge } = pkcePair();

    const res = await authorize(app, {
      client_id: CIMD_CLIENT_ID,
      redirect_uri: CIMD_REDIRECT_URI,
      code_challenge: challenge,
      code_challenge_method: "S256"
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("invalid_client");
  });

  it("rejects a document missing a required field (client_name)", async () => {
    const cimdClient = buildCimdClient({ client_name: undefined });
    const { app } = await buildHarness(new Date("2026-01-01T00:00:00Z"), cimdClient);
    const { challenge } = pkcePair();

    const res = await authorize(app, {
      client_id: CIMD_CLIENT_ID,
      redirect_uri: CIMD_REDIRECT_URI,
      code_challenge: challenge,
      code_challenge_method: "S256"
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("invalid_client");
  });

  it("rejects a client_id URL with a non-https scheme, without attempting a fetch", async () => {
    let fetchCalls = 0;
    const cimdClient = new CimdClient({
      fetch: async () => {
        fetchCalls++;
        throw new Error("must not be called for a non-https client_id");
      },
      resolveHostname: async () => ["93.184.216.34"]
    });
    const { app } = await buildHarness(new Date("2026-01-01T00:00:00Z"), cimdClient);
    const { challenge } = pkcePair();

    const res = await authorize(app, {
      client_id: "http://cimd-client.example.com/metadata.json",
      redirect_uri: CIMD_REDIRECT_URI,
      code_challenge: challenge,
      code_challenge_method: "S256"
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("invalid_client");
    expect(fetchCalls).toBe(0);
  });

  it("rejects a client_id URL with no path component, without attempting a fetch", async () => {
    let fetchCalls = 0;
    const cimdClient = new CimdClient({
      fetch: async () => {
        fetchCalls++;
        throw new Error("must not be called for a client_id with no path");
      },
      resolveHostname: async () => ["93.184.216.34"]
    });
    const { app } = await buildHarness(new Date("2026-01-01T00:00:00Z"), cimdClient);
    const { challenge } = pkcePair();

    const res = await authorize(app, {
      client_id: "https://cimd-client.example.com",
      redirect_uri: CIMD_REDIRECT_URI,
      code_challenge: challenge,
      code_challenge_method: "S256"
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("invalid_client");
    expect(fetchCalls).toBe(0);
  });

  it("rejects a redirect_uri not present in the metadata document", async () => {
    const { app } = await buildHarness(new Date("2026-01-01T00:00:00Z"), buildCimdClient());
    const { challenge } = pkcePair();

    const res = await authorize(app, {
      client_id: CIMD_CLIENT_ID,
      redirect_uri: "https://cimd-client.example.com/not-registered",
      code_challenge: challenge,
      code_challenge_method: "S256"
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("invalid_request");
  });

  it("refuses an SSRF attempt: client_id pointing at a loopback address is rejected without a network fetch", async () => {
    let fetchCalls = 0;
    const cimdClient = new CimdClient({
      fetch: async () => {
        fetchCalls++;
        throw new Error("must not be called: this client_id must be blocked before any fetch");
      }
    });
    const { app } = await buildHarness(new Date("2026-01-01T00:00:00Z"), cimdClient);
    const { challenge } = pkcePair();

    const res = await authorize(app, {
      client_id: "https://127.0.0.1/client.json",
      redirect_uri: CIMD_REDIRECT_URI,
      code_challenge: challenge,
      code_challenge_method: "S256"
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string; error_description: string };
    expect(body.error).toBe("invalid_client");
    const serialized = JSON.stringify(body);
    expect(serialized).not.toMatch(/127\.0\.0\.1|blocked|private|loopback|ECONNREFUSED/i);
    expect(fetchCalls).toBe(0);
  });

  it("refuses an oversized metadata document", async () => {
    const cimdClient = buildCimdClient({ client_name: "x".repeat(200_000) });
    const { app } = await buildHarness(new Date("2026-01-01T00:00:00Z"), cimdClient);
    const { challenge } = pkcePair();

    const res = await authorize(app, {
      client_id: CIMD_CLIENT_ID,
      redirect_uri: CIMD_REDIRECT_URI,
      code_challenge: challenge,
      code_challenge_method: "S256"
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("invalid_client");
  });

  it("caches the metadata document, respecting Cache-Control: max-age (no refetch on a second /authorize)", async () => {
    let fetchCalls = 0;
    const cimdClient = new CimdClient({
      fetch: async () => {
        fetchCalls++;
        return jsonResponse(
          { client_id: CIMD_CLIENT_ID, client_name: "CIMD Test Client", redirect_uris: [CIMD_REDIRECT_URI] },
          { headers: { "cache-control": "max-age=300" } }
        );
      },
      resolveHostname: async () => ["93.184.216.34"]
    });
    const { app } = await buildHarness(new Date("2026-01-01T00:00:00Z"), cimdClient);
    const { challenge: c1 } = pkcePair();
    const { challenge: c2 } = pkcePair();

    await getCimdCode(app, c1);
    await getCimdCode(app, c2);
    expect(fetchCalls).toBe(1);
  });

  describe("application_type redirect-URI constraints", () => {
    const LOOPBACK_REDIRECT_URI = "http://127.0.0.1:4321/callback";

    it("allows a native client to register a loopback redirect_uri", async () => {
      const cimdClient = buildCimdClient({ application_type: "native", redirect_uris: [LOOPBACK_REDIRECT_URI] });
      const { app } = await buildHarness(new Date("2026-01-01T00:00:00Z"), cimdClient);
      const { challenge } = pkcePair();

      const res = await authorize(app, {
        client_id: CIMD_CLIENT_ID,
        redirect_uri: LOOPBACK_REDIRECT_URI,
        code_challenge: challenge,
        code_challenge_method: "S256"
      });
      expect(res.status).toBe(302);
      const location = new URL(res.headers.get("Location") ?? "");
      expect(location.searchParams.get("code")).toBeTruthy();
    });

    it("rejects a web client that registers a loopback redirect_uri", async () => {
      const cimdClient = buildCimdClient({ application_type: "web", redirect_uris: [LOOPBACK_REDIRECT_URI] });
      const { app } = await buildHarness(new Date("2026-01-01T00:00:00Z"), cimdClient);
      const { challenge } = pkcePair();

      const res = await authorize(app, {
        client_id: CIMD_CLIENT_ID,
        redirect_uri: LOOPBACK_REDIRECT_URI,
        code_challenge: challenge,
        code_challenge_method: "S256"
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as { error: string };
      expect(body.error).toBe("invalid_request");
    });

    it("treats an absent application_type as web and rejects a loopback redirect_uri", async () => {
      const cimdClient = buildCimdClient({ redirect_uris: [LOOPBACK_REDIRECT_URI] });
      const { app } = await buildHarness(new Date("2026-01-01T00:00:00Z"), cimdClient);
      const { challenge } = pkcePair();

      const res = await authorize(app, {
        client_id: CIMD_CLIENT_ID,
        redirect_uri: LOOPBACK_REDIRECT_URI,
        code_challenge: challenge,
        code_challenge_method: "S256"
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as { error: string };
      expect(body.error).toBe("invalid_request");
    });
  });
});

describe("RFC 8707: resource parameter", () => {
  const CUSTOM_RESOURCE = "https://custom-mcp-server.example/mcp";

  it("flows resource through to the minted token's aud", async () => {
    const { app, keys } = await buildHarness(new Date("2026-01-01T00:00:00Z"));
    const { verifier, challenge } = pkcePair();

    const authRes = await authorize(app, {
      code_challenge: challenge,
      code_challenge_method: "S256",
      resource: CUSTOM_RESOURCE
    });
    expect(authRes.status).toBe(302);
    const location = new URL(authRes.headers.get("Location") ?? "");
    const code = location.searchParams.get("code");
    if (!code) throw new Error("expected a code");

    const tokenRes = await app.request("/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: basicAuthHeader(CLIENT.clientId, CLIENT.clientSecret)
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: CLIENT.redirectUri,
        code_verifier: verifier,
        resource: CUSTOM_RESOURCE
      }).toString()
    });
    expect(tokenRes.status).toBe(200);
    const body = (await tokenRes.json()) as { access_token: string };
    const claims = await verify(body.access_token, {
      keys,
      issuer: ISSUER,
      audience: CUSTOM_RESOURCE,
      now: () => new Date("2026-01-01T00:00:00Z")
    });
    expect(claims.aud).toBe(CUSTOM_RESOURCE);
  });

  it("rejects a mismatch between the resource sent at /authorize and at /token", async () => {
    const { app } = await buildHarness(new Date("2026-01-01T00:00:00Z"));
    const { verifier, challenge } = pkcePair();

    const authRes = await authorize(app, {
      code_challenge: challenge,
      code_challenge_method: "S256",
      resource: CUSTOM_RESOURCE
    });
    const location = new URL(authRes.headers.get("Location") ?? "");
    const code = location.searchParams.get("code");
    if (!code) throw new Error("expected a code");

    const tokenRes = await app.request("/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: basicAuthHeader(CLIENT.clientId, CLIENT.clientSecret)
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: CLIENT.redirectUri,
        code_verifier: verifier,
        resource: "https://a-different-mcp-server.example/mcp"
      }).toString()
    });
    expect(tokenRes.status).toBe(400);
    const body = (await tokenRes.json()) as { error: string };
    expect(body.error).toBe("invalid_target");
  });

  it("rejects a resource URI with a fragment at /authorize", async () => {
    const { app } = await buildHarness(new Date("2026-01-01T00:00:00Z"));
    const { challenge } = pkcePair();

    const res = await authorize(app, {
      code_challenge: challenge,
      code_challenge_method: "S256",
      resource: `${CUSTOM_RESOURCE}#section`
    });
    expect(res.status).toBe(302);
    const location = new URL(res.headers.get("Location") ?? "");
    expect(location.searchParams.get("error")).toBe("invalid_target");
  });

  it("rejects a resource URI with a fragment at /token", async () => {
    const { app } = await buildHarness(new Date("2026-01-01T00:00:00Z"));
    const { verifier, challenge } = pkcePair();
    const { code } = await getValidCode(app, challenge);

    const tokenRes = await app.request("/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: basicAuthHeader(CLIENT.clientId, CLIENT.clientSecret)
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: CLIENT.redirectUri,
        code_verifier: verifier,
        resource: `${CLIENT.audience}#frag`
      }).toString()
    });
    expect(tokenRes.status).toBe(400);
    const body = (await tokenRes.json()) as { error: string };
    expect(body.error).toBe("invalid_target");
  });

  it("still works with no resource at all (backwards compatible with the existing demo flow)", async () => {
    const { app, keys } = await buildHarness(new Date("2026-01-01T00:00:00Z"));
    const { verifier, challenge } = pkcePair();
    const { code } = await getValidCode(app, challenge);

    const tokenRes = await requestToken(app, {
      grant_type: "authorization_code",
      code,
      redirect_uri: CLIENT.redirectUri,
      code_verifier: verifier
    });
    expect(tokenRes.status).toBe(200);
    const body = (await tokenRes.json()) as { access_token: string };
    const claims = await verify(body.access_token, {
      keys,
      issuer: ISSUER,
      audience: CLIENT.audience,
      now: () => new Date("2026-01-01T00:00:00Z")
    });
    expect(claims.aud).toBe(CLIENT.audience);
  });

  it("still works when resource was sent at /authorize but omitted at /token (lenient, not required to be resent)", async () => {
    const { app, keys } = await buildHarness(new Date("2026-01-01T00:00:00Z"));
    const { verifier, challenge } = pkcePair();

    const authRes = await authorize(app, {
      code_challenge: challenge,
      code_challenge_method: "S256",
      resource: CUSTOM_RESOURCE
    });
    const location = new URL(authRes.headers.get("Location") ?? "");
    const code = location.searchParams.get("code");
    if (!code) throw new Error("expected a code");

    const tokenRes = await requestToken(app, {
      grant_type: "authorization_code",
      code,
      redirect_uri: CLIENT.redirectUri,
      code_verifier: verifier
    });
    expect(tokenRes.status).toBe(200);
    const body = (await tokenRes.json()) as { access_token: string };
    const claims = await verify(body.access_token, {
      keys,
      issuer: ISSUER,
      audience: CUSTOM_RESOURCE,
      now: () => new Date("2026-01-01T00:00:00Z")
    });
    expect(claims.aud).toBe(CUSTOM_RESOURCE);
  });
});

describe("/token negative paths", () => {
  it("rejects a replayed code with invalid_grant", async () => {
    const { app } = await buildHarness(new Date("2026-01-01T00:00:00Z"));
    const { verifier, challenge } = pkcePair();
    const { code } = await getValidCode(app, challenge);

    const first = await requestToken(app, {
      grant_type: "authorization_code",
      code,
      redirect_uri: CLIENT.redirectUri,
      code_verifier: verifier
    });
    expect(first.status).toBe(200);

    const second = await requestToken(app, {
      grant_type: "authorization_code",
      code,
      redirect_uri: CLIENT.redirectUri,
      code_verifier: verifier
    });
    expect(second.status).toBe(400);
    expect(((await second.json()) as { error: string }).error).toBe("invalid_grant");
  });

  it("rejects a wrong code_verifier with invalid_grant", async () => {
    const { app } = await buildHarness(new Date("2026-01-01T00:00:00Z"));
    const { challenge } = pkcePair();
    const { code } = await getValidCode(app, challenge);

    const res = await requestToken(app, {
      grant_type: "authorization_code",
      code,
      redirect_uri: CLIENT.redirectUri,
      code_verifier: "totally-the-wrong-verifier"
    });
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: string }).error).toBe("invalid_grant");
  });

  it("rejects a redirect_uri mismatch with invalid_grant", async () => {
    const { app } = await buildHarness(new Date("2026-01-01T00:00:00Z"));
    const { verifier, challenge } = pkcePair();
    const { code } = await getValidCode(app, challenge);

    const res = await requestToken(app, {
      grant_type: "authorization_code",
      code,
      redirect_uri: `${CLIENT.redirectUri}/extra-path`,
      code_verifier: verifier
    });
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: string }).error).toBe("invalid_grant");
  });

  it("rejects an expired code with invalid_grant", async () => {
    const harness = await buildHarness(new Date("2026-01-01T00:00:00Z"));
    const { verifier, challenge } = pkcePair();
    const { code } = await getValidCode(harness.app, challenge);

    harness.setNow(new Date("2026-01-01T00:02:00Z"));

    const res = await requestToken(harness.app, {
      grant_type: "authorization_code",
      code,
      redirect_uri: CLIENT.redirectUri,
      code_verifier: verifier
    });
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: string }).error).toBe("invalid_grant");
  });

  it("rejects a token request without client authentication", async () => {
    const { app } = await buildHarness(new Date("2026-01-01T00:00:00Z"));
    const { verifier, challenge } = pkcePair();
    const { code } = await getValidCode(app, challenge);

    const res = await app.request("/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: CLIENT.redirectUri,
        code_verifier: verifier
      }).toString()
    });
    expect(res.status).toBe(401);
  });
});

describe("POST /introspect", () => {
  it("requires client authentication", async () => {
    const { app } = await buildHarness(new Date("2026-01-01T00:00:00Z"));
    const res = await app.request("/introspect", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ token: "whatever" }).toString()
    });
    expect(res.status).toBe(401);
  });

  it("rejects wrong client credentials with 401", async () => {
    const { app } = await buildHarness(new Date("2026-01-01T00:00:00Z"));
    const res = await app.request("/introspect", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: basicAuthHeader(CLIENT.clientId, WRONG_CLIENT_SECRET)
      },
      body: new URLSearchParams({ token: "whatever" }).toString()
    });
    expect(res.status).toBe(401);
  });

  it("reports active:true for a live token, then active:false after revoke", async () => {
    const { app } = await buildHarness(new Date("2026-01-01T00:00:00Z"));
    const { verifier, challenge } = pkcePair();
    const { code } = await getValidCode(app, challenge);
    const tokenRes = await requestToken(app, {
      grant_type: "authorization_code",
      code,
      redirect_uri: CLIENT.redirectUri,
      code_verifier: verifier
    });
    const { access_token: accessToken } = (await tokenRes.json()) as { access_token: string };

    const introspectRes = await app.request("/introspect", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: basicAuthHeader(CLIENT.clientId, CLIENT.clientSecret)
      },
      body: new URLSearchParams({ token: accessToken }).toString()
    });
    expect(introspectRes.status).toBe(200);
    const activeBody = (await introspectRes.json()) as { active: boolean };
    expect(activeBody.active).toBe(true);

    const revokeRes = await app.request("/revoke", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: basicAuthHeader(CLIENT.clientId, CLIENT.clientSecret)
      },
      body: new URLSearchParams({ token: accessToken }).toString()
    });
    expect(revokeRes.status).toBe(200);

    const introspectAfterRevoke = await app.request("/introspect", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: basicAuthHeader(CLIENT.clientId, CLIENT.clientSecret)
      },
      body: new URLSearchParams({ token: accessToken }).toString()
    });
    const inactiveBody = (await introspectAfterRevoke.json()) as Record<string, unknown>;
    expect(inactiveBody).toEqual({ active: false });
  });

  it("returns active:false for garbage input, never an error leaking why", async () => {
    const { app } = await buildHarness(new Date("2026-01-01T00:00:00Z"));
    const res = await app.request("/introspect", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: basicAuthHeader(CLIENT.clientId, CLIENT.clientSecret)
      },
      body: new URLSearchParams({ token: "not.a.jwt" }).toString()
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ active: false });
  });
});

describe("POST /revoke", () => {
  it("requires client authentication", async () => {
    const { app } = await buildHarness(new Date("2026-01-01T00:00:00Z"));
    const res = await app.request("/revoke", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ token: "whatever" }).toString()
    });
    expect(res.status).toBe(401);
  });
});
