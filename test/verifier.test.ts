import { describe, expect, it, vi } from "vitest";
import { OAuthError, requireBearerAuth } from "@modelcontextprotocol/server";
import type { AuthInfo, OAuthTokenVerifier } from "@modelcontextprotocol/server";
import { getActiveKey, retireKey, rotateKeyRing } from "../src/keys.js";
import { MemoryTokenStore } from "../src/store/memory.js";
import { issue } from "../src/tokens.js";
import { McpTokenVerifier, requiredScopeForTool, TOOL_SCOPES } from "../src/verifier.js";
import type { FetchLike } from "../src/verifier.js";
import { BASE_NOW, buildDelegationHarness, CLIENT, ISSUER } from "./support/delegationHarness.js";
import { exchangeToken, mintRootToken, revokeToken, type TokenResponseBody } from "./support/tokenFlow.js";

const LONG_TTL_SECONDS = 3600;

describe("McpTokenVerifier", () => {
  async function setup(options: { tokenTtlSeconds?: number; realTime?: boolean } = {}) {
    const initialNow = options.realTime ? new Date() : BASE_NOW;
    const h = await buildDelegationHarness((now) => new MemoryTokenStore({ now }), {
      tokenTtlSeconds: options.tokenTtlSeconds ?? 300,
      initialNow
    });
    let clock = initialNow;
    const now = (): Date => clock;
    const setClock = (d: Date): void => {
      clock = d;
      h.setNow(d);
    };
    const fetchImpl: FetchLike = (input, init) => Promise.resolve(h.app.request(input, init));
    const verifier = new McpTokenVerifier({
      issuer: ISSUER,
      resource: CLIENT.audience,
      clientId: CLIENT.clientId,
      clientSecret: CLIENT.clientSecret,
      fetch: fetchImpl,
      now,
      jwksCacheTtlMs: 0
    });
    return { h, verifier, now, setClock, fetchImpl };
  }

  function tamperSignature(token: string): string {
    const parts = token.split(".");
    const tamperedSignature = parts[2]
      ?.split("")
      .reverse()
      .join("")
      .replace(/^./, (c) => (c === "A" ? "B" : "A"));
    return `${parts[0]}.${parts[1]}.${tamperedSignature}`;
  }

  it("returns a fully populated AuthInfo for a valid, in-scope token", async () => {
    const { h, verifier } = await setup();
    const root = await mintRootToken(h.app, { scope: "filings:read quotes:read" });

    const authInfo = await verifier.verifyAccessToken(root.accessToken);

    expect(authInfo.token).toBe(root.accessToken);
    expect(authInfo.clientId).toBe(CLIENT.clientId);
    expect(authInfo.scopes.sort()).toEqual(["filings:read", "quotes:read"]);
    expect(authInfo.resource).toBeInstanceOf(URL);
    expect(authInfo.resource?.toString()).toBe(CLIENT.audience);
  });

  it("populates AuthInfo.expiresAt, which the SDK bearer auth requires", async () => {
    const { h, verifier } = await setup({ tokenTtlSeconds: 120 });
    const root = await mintRootToken(h.app, { scope: "filings:read" });

    const authInfo = await verifier.verifyAccessToken(root.accessToken);

    expect(authInfo.expiresAt).toBeDefined();
    expect(typeof authInfo.expiresAt).toBe("number");
    const expectedExp = Math.floor(BASE_NOW.getTime() / 1000) + 120;
    expect(authInfo.expiresAt).toBe(expectedExp);
  });

  it("rejects a token minted for a different resource (RFC 8707 audience binding)", async () => {
    const { h, verifier, now } = await setup();
    const wrongAudienceToken = await issue(
      { sub: "agent:test:0001", aud: "https://not-this-resource.example/mcp", scope: "filings:read", ttlSeconds: 300 },
      { keys: h.keys, issuer: h.config.issuer, now }
    );

    await expect(verifier.verifyAccessToken(wrongAudienceToken)).rejects.toThrow(OAuthError);
  });

  it("rejects an expired token", async () => {
    const { h, verifier, setClock } = await setup({ tokenTtlSeconds: 60 });
    const root = await mintRootToken(h.app, { scope: "filings:read" });

    setClock(new Date(BASE_NOW.getTime() + 61_000));

    await expect(verifier.verifyAccessToken(root.accessToken)).rejects.toThrow(OAuthError);
  });

  it("rejects a revoked token (long TTL, so expiry cannot be the cause)", async () => {
    const { h, verifier } = await setup({ tokenTtlSeconds: LONG_TTL_SECONDS });
    const root = await mintRootToken(h.app, { scope: "filings:read" });

    const revokeRes = await revokeToken(h.app, root.accessToken);
    expect(revokeRes.status).toBe(200);

    await expect(verifier.verifyAccessToken(root.accessToken)).rejects.toThrow(OAuthError);
  });

  it("rejects a tampered signature", async () => {
    const { h, verifier } = await setup();
    const root = await mintRootToken(h.app, { scope: "filings:read" });

    await expect(verifier.verifyAccessToken(tamperSignature(root.accessToken))).rejects.toThrow(OAuthError);
  });

  it("accepts a delegated child token with its own narrowed scope, not the parent's", async () => {
    const { h, verifier } = await setup();
    const root = await mintRootToken(h.app, { scope: "filings:read quotes:read" });

    const exchangeRes = await exchangeToken(h.app, root.accessToken, { scope: "filings:read" });
    expect(exchangeRes.status).toBe(200);
    const childBody = (await exchangeRes.json()) as TokenResponseBody;

    const authInfo = await verifier.verifyAccessToken(childBody.access_token);
    expect(authInfo.scopes).toEqual(["filings:read"]);
    expect(authInfo.scopes).not.toContain("quotes:read");
  });

  it("rejects a delegated child once its parent is revoked, so revocation reaches the resource server", async () => {
    const { h, verifier } = await setup({ tokenTtlSeconds: LONG_TTL_SECONDS });
    const root = await mintRootToken(h.app, { scope: "filings:read" });
    const exchangeRes = await exchangeToken(h.app, root.accessToken, { scope: "filings:read" });
    expect(exchangeRes.status).toBe(200);
    const childBody = (await exchangeRes.json()) as TokenResponseBody;

    await expect(verifier.verifyAccessToken(childBody.access_token)).resolves.toBeDefined();

    const revokeRes = await revokeToken(h.app, root.accessToken);
    expect(revokeRes.status).toBe(200);

    await expect(verifier.verifyAccessToken(childBody.access_token)).rejects.toThrow(OAuthError);
  });

  it("accepts a token signed by a rotated-but-still-published key", async () => {
    const { h, verifier } = await setup();
    const preRotationToken = await mintRootToken(h.app, { scope: "filings:read" });

    const rotated = await rotateKeyRing(h.keys);
    h.keys.keys = rotated.keys;

    await expect(verifier.verifyAccessToken(preRotationToken.accessToken)).resolves.toBeDefined();
  });

  it("rejects a token signed by a retired key", async () => {
    const { h, verifier } = await setup();
    const originalKid = getActiveKey(h.keys).kid;
    const preRotationToken = await mintRootToken(h.app, { scope: "filings:read" });

    const rotated = await rotateKeyRing(h.keys);
    h.keys.keys = rotated.keys;
    await expect(verifier.verifyAccessToken(preRotationToken.accessToken)).resolves.toBeDefined();

    const retired = retireKey(h.keys, originalKid);
    h.keys.keys = retired.keys;

    await expect(verifier.verifyAccessToken(preRotationToken.accessToken)).rejects.toThrow(OAuthError);
  });

  it("plugs into the SDK's requireBearerAuth directly", async () => {
    const { h, verifier } = await setup({ realTime: true });
    const root = await mintRootToken(h.app, { scope: "filings:read" });

    const gate = requireBearerAuth({ verifier, requiredScopes: ["filings:read"] });

    const okResult = await gate(new Request("https://mcp.example/mcp", { headers: { Authorization: `Bearer ${root.accessToken}` } }));
    expect(okResult).not.toBeInstanceOf(Response);
    expect((okResult as AuthInfo).scopes).toContain("filings:read");

    const badResult = await gate(new Request("https://mcp.example/mcp", { headers: { Authorization: "Bearer not-a-real-token" } }));
    expect(badResult).toBeInstanceOf(Response);
    expect((badResult as Response).status).toBe(401);
  });

  it("confirms the SDK itself rejects any AuthInfo missing expiresAt, independent of this verifier", async () => {
    const noExpiryVerifier: OAuthTokenVerifier = {
      verifyAccessToken: async (token: string): Promise<AuthInfo> => ({
        token,
        clientId: CLIENT.clientId,
        scopes: ["filings:read"]
      })
    };
    const gate = requireBearerAuth({ verifier: noExpiryVerifier });

    const result = await gate(new Request("https://mcp.example/mcp", { headers: { Authorization: "Bearer anything" } }));
    expect(result).toBeInstanceOf(Response);
    expect((result as Response).status).toBe(401);
  });
});

describe("McpTokenVerifier: local verification alone (introspection stubbed active)", () => {
  async function setupIsolated(options: { tokenTtlSeconds?: number } = {}) {
    const h = await buildDelegationHarness((now) => new MemoryTokenStore({ now }), {
      tokenTtlSeconds: options.tokenTtlSeconds ?? 300
    });
    let clock = BASE_NOW;
    const now = (): Date => clock;
    const setClock = (d: Date): void => {
      clock = d;
      h.setNow(d);
    };
    const stubbedFetch: FetchLike = (input, init) => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.includes("/introspect")) {
        return Promise.resolve(
          new Response(JSON.stringify({ active: true, client_id: CLIENT.clientId }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          })
        );
      }
      return Promise.resolve(h.app.request(input, init));
    };
    const verifier = new McpTokenVerifier({
      issuer: ISSUER,
      resource: CLIENT.audience,
      clientId: CLIENT.clientId,
      clientSecret: CLIENT.clientSecret,
      fetch: stubbedFetch,
      now,
      jwksCacheTtlMs: 0
    });
    return { h, verifier, now, setClock };
  }

  function tamperSignature(token: string): string {
    const parts = token.split(".");
    const tamperedSignature = parts[2]
      ?.split("")
      .reverse()
      .join("")
      .replace(/^./, (c) => (c === "A" ? "B" : "A"));
    return `${parts[0]}.${parts[1]}.${tamperedSignature}`;
  }

  it("still rejects a wrong-audience token even though introspection would say active", async () => {
    const { h, verifier, now } = await setupIsolated();
    const wrongAudienceToken = await issue(
      { sub: "agent:test:0001", aud: "https://not-this-resource.example/mcp", scope: "filings:read", ttlSeconds: 300 },
      { keys: h.keys, issuer: h.config.issuer, now }
    );
    await expect(verifier.verifyAccessToken(wrongAudienceToken)).rejects.toThrow(OAuthError);
  });

  it("still rejects an expired token even though introspection would say active", async () => {
    const { h, verifier, setClock } = await setupIsolated({ tokenTtlSeconds: 60 });
    const root = await mintRootToken(h.app, { scope: "filings:read" });
    setClock(new Date(BASE_NOW.getTime() + 61_000));
    await expect(verifier.verifyAccessToken(root.accessToken)).rejects.toThrow(OAuthError);
  });

  it("still rejects a tampered signature even though introspection would say active", async () => {
    const { h, verifier } = await setupIsolated();
    const root = await mintRootToken(h.app, { scope: "filings:read" });
    await expect(verifier.verifyAccessToken(tamperSignature(root.accessToken))).rejects.toThrow(OAuthError);
  });

  it("still rejects a retired-key token even though introspection would say active", async () => {
    const { h, verifier } = await setupIsolated();
    const originalKid = getActiveKey(h.keys).kid;
    const preRotationToken = await mintRootToken(h.app, { scope: "filings:read" });
    const rotated = await rotateKeyRing(h.keys);
    h.keys.keys = rotated.keys;
    const retired = retireKey(h.keys, originalKid);
    h.keys.keys = retired.keys;
    await expect(verifier.verifyAccessToken(preRotationToken.accessToken)).rejects.toThrow(OAuthError);
  });
});

describe("McpTokenVerifier transport", () => {
  const base = { resource: CLIENT.audience, clientId: CLIENT.clientId, clientSecret: CLIENT.clientSecret };

  it("refuses an http issuer that is not loopback", () => {
    expect(() => new McpTokenVerifier({ ...base, issuer: "http://auth.example.com" })).toThrow(/issuer/);
  });

  it("refuses an http JWKS URL even when the issuer is https", () => {
    expect(
      () => new McpTokenVerifier({ ...base, issuer: ISSUER, jwksUri: "http://auth.example.com/jwks.json" })
    ).toThrow(/jwksUri/);
  });

  it("refuses an http introspection URL even when the issuer is https", () => {
    expect(
      () => new McpTokenVerifier({ ...base, issuer: ISSUER, introspectionEndpoint: "http://auth.example.com/introspect" })
    ).toThrow(/introspectionEndpoint/);
  });

  it("accepts an https issuer and a loopback http issuer", () => {
    expect(() => new McpTokenVerifier({ ...base, issuer: ISSUER })).not.toThrow();
    expect(() => new McpTokenVerifier({ ...base, issuer: "http://localhost:3000" })).not.toThrow();
    expect(() => new McpTokenVerifier({ ...base, issuer: "http://[::1]:3000" })).not.toThrow();
  });
});

describe("McpTokenVerifier JWKS refetch throttle", () => {
  const DAY_MS = 86_400_000;

  async function setup() {
    const h = await buildDelegationHarness((now) => new MemoryTokenStore({ now }), { tokenTtlSeconds: 300 });
    let clock = BASE_NOW;
    const setClock = (d: Date): void => {
      clock = d;
      h.setNow(d);
    };
    const fetchSpy = vi.fn<FetchLike>((input, init) => Promise.resolve(h.app.request(input, init)));
    const verifier = new McpTokenVerifier({
      issuer: ISSUER,
      resource: CLIENT.audience,
      clientId: CLIENT.clientId,
      clientSecret: CLIENT.clientSecret,
      fetch: fetchSpy,
      now: () => clock,
      jwksCacheTtlMs: DAY_MS
    });
    const jwksFetches = (): number => fetchSpy.mock.calls.filter(([url]) => String(url).endsWith("/jwks.json")).length;
    return { h, verifier, setClock, jwksFetches };
  }

  function tokenWithKid(kid: string): string {
    const part = (o: object): string => Buffer.from(JSON.stringify(o)).toString("base64url");
    return `${part({ alg: "RS256", kid })}.${part({})}.c2ln`;
  }

  it("refetches the JWKS at most once for repeated unknown kids inside the interval", async () => {
    const { h, verifier, jwksFetches } = await setup();
    const known = await mintRootToken(h.app, { scope: "filings:read" });
    await verifier.verifyAccessToken(known.accessToken);
    const afterPrime = jwksFetches();

    for (let i = 0; i < 5; i++) {
      await expect(verifier.verifyAccessToken(tokenWithKid(`unknown-${i}`))).rejects.toThrow(OAuthError);
    }

    expect(jwksFetches() - afterPrime).toBe(1);
  });

  it("picks up a rotated key on first sight when no refetch happened inside the interval", async () => {
    const { h, verifier, jwksFetches } = await setup();
    await verifier.verifyAccessToken((await mintRootToken(h.app, { scope: "filings:read" })).accessToken);

    h.keys.keys = (await rotateKeyRing(h.keys)).keys;
    const postRotation = await mintRootToken(h.app, { scope: "filings:read" });

    await expect(verifier.verifyAccessToken(postRotation.accessToken)).resolves.toBeDefined();
    expect(jwksFetches()).toBe(2);
  });

  it("rejects a rotated key inside the interval and accepts it once the interval has elapsed", async () => {
    const { h, verifier, setClock, jwksFetches } = await setup();
    await verifier.verifyAccessToken((await mintRootToken(h.app, { scope: "filings:read" })).accessToken);
    await expect(verifier.verifyAccessToken(tokenWithKid("unknown"))).rejects.toThrow(OAuthError);
    expect(jwksFetches()).toBe(2);

    h.keys.keys = (await rotateKeyRing(h.keys)).keys;
    const postRotation = await mintRootToken(h.app, { scope: "filings:read" });

    await expect(verifier.verifyAccessToken(postRotation.accessToken)).rejects.toThrow(OAuthError);
    setClock(new Date(BASE_NOW.getTime() + 59_000));
    await expect(verifier.verifyAccessToken(postRotation.accessToken)).rejects.toThrow(OAuthError);
    expect(jwksFetches()).toBe(2);

    setClock(new Date(BASE_NOW.getTime() + 60_000));
    await expect(verifier.verifyAccessToken(postRotation.accessToken)).resolves.toBeDefined();
    expect(jwksFetches()).toBe(3);
  });
});

describe("TOOL_SCOPES / requiredScopeForTool", () => {
  it("maps every entry onto one of the four scopes this AS issues", () => {
    const validScopes = new Set(["filings:read", "quotes:read", "companies:read", "sources:read"]);
    for (const scope of Object.values(TOOL_SCOPES)) {
      expect(validScopes.has(scope)).toBe(true);
    }
  });

  it("requiredScopeForTool looks up TOOL_SCOPES and returns undefined for an unknown tool", () => {
    const [knownTool, knownScope] = Object.entries(TOOL_SCOPES)[0] ?? [];
    expect(knownTool).toBeDefined();
    expect(requiredScopeForTool(knownTool as string)).toBe(knownScope);
    expect(requiredScopeForTool("not_a_real_tool")).toBeUndefined();
  });
});
