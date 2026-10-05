import { describe, expect, it } from "vitest";
import { RateLimiter } from "../src/http/rateLimit.js";
import { MemoryTokenStore } from "../src/store/memory.js";
import { BASE_NOW, basicAuthHeader, buildDelegationHarness, CLIENT } from "./support/delegationHarness.js";
import { introspectActive, mintRootToken, pkcePair, revokeToken } from "./support/tokenFlow.js";

function fromAddress(remoteAddress: string): { incoming: { socket: { remoteAddress: string } } } {
  return { incoming: { socket: { remoteAddress } } };
}

describe("rate limiting", () => {
  it("/introspect returns 429 with a sensible Retry-After once a client exceeds its budget, and recovers after the window", async () => {
    const h = await buildDelegationHarness((now) => new MemoryTokenStore({ now }), {
      rateLimitMax: 2,
      rateLimitWindowSeconds: 5
    });
    const root = await mintRootToken(h.app);

    expect(await introspectActive(h.app, root.accessToken)).toBe(true);
    expect(await introspectActive(h.app, root.accessToken)).toBe(true);

    const res = await h.app.request("/introspect", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${Buffer.from("demo-agent-client:demo-client-secret-change-me").toString("base64")}`
      },
      body: new URLSearchParams({ token: root.accessToken }).toString()
    });
    expect(res.status).toBe(429);
    const retryAfter = res.headers.get("Retry-After");
    expect(retryAfter).not.toBeNull();
    const retryAfterSeconds = Number(retryAfter);
    expect(Number.isFinite(retryAfterSeconds)).toBe(true);
    expect(retryAfterSeconds).toBeGreaterThan(0);
    expect(retryAfterSeconds).toBeLessThanOrEqual(5);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("rate_limit_exceeded");

    h.setNow(new Date(BASE_NOW.getTime() + 6000));
    expect(await introspectActive(h.app, root.accessToken)).toBe(true);
  });

  it("tracks /token, /introspect, and /revoke independently: exhausting one endpoint's budget does not block another", async () => {
    const h = await buildDelegationHarness((now) => new MemoryTokenStore({ now }), {
      rateLimitMax: 1,
      rateLimitWindowSeconds: 60
    });
    const root = await mintRootToken(h.app);

    const secondTokenAttempt = await h.app.request("/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${Buffer.from("demo-agent-client:demo-client-secret-change-me").toString("base64")}`
      },
      body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: root.refreshToken }).toString()
    });
    expect(secondTokenAttempt.status).toBe(429);

    expect(await introspectActive(h.app, root.accessToken)).toBe(true);
    const revokeRes = await revokeToken(h.app, root.accessToken);
    expect(revokeRes.status).toBe(200);
  });

  describe("keyed by who the caller proves to be", () => {
    const limited = { rateLimitMax: 3, rateLimitWindowSeconds: 60 };

    async function introspectAs(
      h: Awaited<ReturnType<typeof buildDelegationHarness>>,
      address: string,
      clientId: string,
      clientSecret: string,
      headers: Record<string, string> = {}
    ): Promise<Response> {
      return h.app.request(
        "/introspect",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            Authorization: basicAuthHeader(clientId, clientSecret),
            ...headers
          },
          body: new URLSearchParams({ token: "whatever" }).toString()
        },
        fromAddress(address)
      );
    }

    it("bad-secret requests naming the real client_id do not lock the real client out", async () => {
      const h = await buildDelegationHarness((now) => new MemoryTokenStore({ now }), limited);

      for (let i = 0; i < 20; i++) {
        await introspectAs(h, "203.0.113.9", CLIENT.clientId, "wrong-secret");
      }
      expect((await introspectAs(h, "203.0.113.9", CLIENT.clientId, "wrong-secret")).status).toBe(429);

      expect((await introspectAs(h, "198.51.100.7", CLIENT.clientId, CLIENT.clientSecret)).status).toBe(200);
      expect((await introspectAs(h, "203.0.113.9", CLIENT.clientId, CLIENT.clientSecret)).status).toBe(200);
    });

    it("limits failed authentication per remote address", async () => {
      const h = await buildDelegationHarness((now) => new MemoryTokenStore({ now }), limited);

      for (let i = 0; i < 3; i++) {
        expect((await introspectAs(h, "203.0.113.9", CLIENT.clientId, "wrong-secret")).status).toBe(401);
      }
      const refused = await introspectAs(h, "203.0.113.9", CLIENT.clientId, "wrong-secret");
      expect(refused.status).toBe(429);
      expect(Number(refused.headers.get("Retry-After"))).toBeGreaterThan(0);

      expect((await introspectAs(h, "198.51.100.7", CLIENT.clientId, "wrong-secret")).status).toBe(401);
    });

    it("does not let an attacker dodge the limit by rotating client_ids", async () => {
      const h = await buildDelegationHarness((now) => new MemoryTokenStore({ now }), limited);

      const statuses: number[] = [];
      for (let i = 0; i < 6; i++) {
        statuses.push((await introspectAs(h, "203.0.113.9", `made-up-${i}`, "x")).status);
      }
      expect(statuses).toEqual([401, 401, 401, 429, 429, 429]);
    });

    it("ignores X-Forwarded-For when choosing the address", async () => {
      const h = await buildDelegationHarness((now) => new MemoryTokenStore({ now }), limited);

      const statuses: number[] = [];
      for (let i = 0; i < 5; i++) {
        statuses.push((await introspectAs(h, "203.0.113.9", CLIENT.clientId, "x", { "X-Forwarded-For": `192.0.2.${i}` })).status);
      }
      expect(statuses).toEqual([401, 401, 401, 429, 429]);
    });

    it("limits successful requests per authenticated client, whatever address they come from", async () => {
      const h = await buildDelegationHarness((now) => new MemoryTokenStore({ now }), { rateLimitMax: 2, rateLimitWindowSeconds: 60 });

      expect((await introspectAs(h, "198.51.100.1", CLIENT.clientId, CLIENT.clientSecret)).status).toBe(200);
      expect((await introspectAs(h, "198.51.100.2", CLIENT.clientId, CLIENT.clientSecret)).status).toBe(200);
      expect((await introspectAs(h, "198.51.100.3", CLIENT.clientId, CLIENT.clientSecret)).status).toBe(429);
    });

    it("applies the same keying to /token and /revoke", async () => {
      const h = await buildDelegationHarness((now) => new MemoryTokenStore({ now }), limited);
      const post = async (path: string, secret: string): Promise<Response> =>
        h.app.request(
          path,
          {
            method: "POST",
            headers: {
              "Content-Type": "application/x-www-form-urlencoded",
              Authorization: basicAuthHeader(CLIENT.clientId, secret)
            },
            body: new URLSearchParams({ token: "whatever", grant_type: "refresh_token", refresh_token: "x" }).toString()
          },
          fromAddress("203.0.113.9")
        );

      for (const path of ["/token", "/revoke"]) {
        for (let i = 0; i < 6; i++) {
          await post(path, "wrong-secret");
        }
        expect((await post(path, "wrong-secret")).status).toBe(429);
        expect((await post(path, CLIENT.clientSecret)).status).not.toBe(429);
      }
    });
  });

  it("caps unauthenticated requests per remote address", async () => {
    const h = await buildDelegationHarness((now) => new MemoryTokenStore({ now }), {
      rateLimitMax: 1,
      rateLimitWindowSeconds: 60
    });
    const noAuth = async (): Promise<Response> =>
      h.app.request("/introspect", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ token: "whatever" }).toString()
      });

    expect((await noAuth()).status).toBe(401);
    const second = await noAuth();
    expect(second.status).toBe(429);
  });

  describe("/authorize", () => {
    async function authorizeFrom(h: Awaited<ReturnType<typeof buildDelegationHarness>>, address: string): Promise<Response> {
      const params = new URLSearchParams({
        response_type: "code",
        client_id: CLIENT.clientId,
        redirect_uri: CLIENT.redirectUri,
        scope: "filings:read",
        code_challenge: pkcePair().challenge,
        code_challenge_method: "S256"
      });
      return await h.app.request(`/authorize?${params.toString()}`, {}, fromAddress(address));
    }

    it("is limited per remote address and recovers after the window", async () => {
      const h = await buildDelegationHarness((now) => new MemoryTokenStore({ now }), {
        rateLimitMax: 2,
        rateLimitWindowSeconds: 5
      });

      expect((await authorizeFrom(h, "203.0.113.9")).status).toBe(302);
      expect((await authorizeFrom(h, "203.0.113.9")).status).toBe(302);
      const refused = await authorizeFrom(h, "203.0.113.9");
      expect(refused.status).toBe(429);
      expect(Number(refused.headers.get("Retry-After"))).toBeGreaterThan(0);

      expect((await authorizeFrom(h, "198.51.100.7")).status).toBe(302);

      h.setNow(new Date(BASE_NOW.getTime() + 6000));
      expect((await authorizeFrom(h, "203.0.113.9")).status).toBe(302);
    });
  });
});

describe("RateLimiter memory", () => {
  const window = 1000;

  it("evicts buckets whose window has elapsed", () => {
    let nowMs = 0;
    const limiter = new RateLimiter({ windowMs: window, max: 5, now: () => new Date(nowMs) });

    for (let i = 0; i < 100; i++) limiter.check(`key-${i}`);
    expect(limiter.size).toBe(100);

    nowMs = window + 1;
    limiter.check("fresh");
    expect(limiter.size).toBe(1);
  });

  it("keeps a bucket that is still inside its window", () => {
    let nowMs = 0;
    const limiter = new RateLimiter({ windowMs: window, max: 1, now: () => new Date(nowMs) });

    limiter.check("a");
    nowMs = window / 2;
    limiter.check("b");
    nowMs = window + 1;
    expect(limiter.check("b").allowed).toBe(false);
    expect(limiter.size).toBe(1);
  });

  it("never holds more than maxKeys buckets, even inside one window", () => {
    const limiter = new RateLimiter({ windowMs: window, max: 5, maxKeys: 50, now: () => new Date(0) });

    for (let i = 0; i < 500; i++) limiter.check(`key-${i}`);
    expect(limiter.size).toBeLessThanOrEqual(50);
  });
});
