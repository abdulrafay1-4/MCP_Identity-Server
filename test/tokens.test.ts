import { beforeEach, describe, expect, it } from "vitest";
import { findKey, getActiveKey, loadOrGenerateKeys, retireKey, rotateKeyRing, type KeyRing } from "../src/keys.js";
import { issue, verify } from "../src/tokens.js";

const ISSUER = "https://auth.example.com";
const AUDIENCE = "https://mcp.example.com/mcp";

describe("issue + verify", () => {
  let keys: KeyRing;

  beforeEach(async () => {
    keys = await loadOrGenerateKeys();
  });

  it("round-trips the expected claims", async () => {
    const now = () => new Date("2026-01-01T00:00:00Z");
    const token = await issue(
      { sub: "agent:research-bot:7f3a", aud: AUDIENCE, scope: "filings:read", ttlSeconds: 300 },
      { keys, issuer: ISSUER, now }
    );

    const result = await verify(token, { keys, issuer: ISSUER, audience: AUDIENCE, now });

    expect(result.iss).toBe(ISSUER);
    expect(result.sub).toBe("agent:research-bot:7f3a");
    expect(result.aud).toBe(AUDIENCE);
    expect(result.scope).toBe("filings:read");
    expect(typeof result.jti).toBe("string");
    expect(result.jti.length).toBeGreaterThan(0);
    expect(result.iat).toBe(Math.floor(now().getTime() / 1000));
    expect(result.exp).toBe(result.iat + 300);
  });

  it("rejects a token minted for a different audience", async () => {
    const now = () => new Date("2026-01-01T00:00:00Z");
    const token = await issue(
      { sub: "agent:x", aud: "https://other-server.example.com/mcp", scope: "filings:read", ttlSeconds: 300 },
      { keys, issuer: ISSUER, now }
    );

    await expect(verify(token, { keys, issuer: ISSUER, audience: AUDIENCE, now })).rejects.toThrow();
  });

  it("skips the audience check only when no audience is given, and still checks everything else", async () => {
    const now = () => new Date("2026-01-01T00:00:00Z");
    const token = await issue(
      { sub: "agent:x", aud: "https://other-server.example.com/mcp", scope: "filings:read", ttlSeconds: 300 },
      { keys, issuer: ISSUER, now }
    );

    const claims = await verify(token, { keys, issuer: ISSUER, now });
    expect(claims.aud).toBe("https://other-server.example.com/mcp");

    await expect(verify(token, { keys, issuer: "https://elsewhere.example.com", now })).rejects.toThrow();
    await expect(verify(token, { keys, issuer: ISSUER, now: () => new Date("2026-01-01T01:00:00Z") })).rejects.toThrow();
  });

  it("rejects an expired token", async () => {
    const issuedAt = () => new Date("2026-01-01T00:00:00Z");
    const token = await issue(
      { sub: "agent:x", aud: AUDIENCE, scope: "filings:read", ttlSeconds: 60 },
      { keys, issuer: ISSUER, now: issuedAt }
    );

    const later = () => new Date("2026-01-01T00:05:00Z");
    await expect(verify(token, { keys, issuer: ISSUER, audience: AUDIENCE, now: later })).rejects.toThrow();
  });

  it("rejects a token with a tampered signature", async () => {
    const now = () => new Date("2026-01-01T00:00:00Z");
    const token = await issue(
      { sub: "agent:x", aud: AUDIENCE, scope: "filings:read", ttlSeconds: 300 },
      { keys, issuer: ISSUER, now }
    );

    const parts = token.split(".");
    const tamperedSignature = parts[2]
      ?.split("")
      .reverse()
      .join("")
      .replace(/^./, (c) => (c === "A" ? "B" : "A"));
    const tampered = `${parts[0]}.${parts[1]}.${tamperedSignature}`;

    await expect(verify(tampered, { keys, issuer: ISSUER, audience: AUDIENCE, now })).rejects.toThrow();
  });

  it("mints a unique jti across two issues of otherwise identical input", async () => {
    const now = () => new Date("2026-01-01T00:00:00Z");
    const params = { sub: "agent:x", aud: AUDIENCE, scope: "filings:read", ttlSeconds: 300 };
    const tokenA = await issue(params, { keys, issuer: ISSUER, now });
    const tokenB = await issue(params, { keys, issuer: ISSUER, now });

    const claimsA = await verify(tokenA, { keys, issuer: ISSUER, audience: AUDIENCE, now });
    const claimsB = await verify(tokenB, { keys, issuer: ISSUER, audience: AUDIENCE, now });

    expect(claimsA.jti).not.toBe(claimsB.jti);
  });

  it("does not leak the token string in a verification error's message", async () => {
    const now = () => new Date("2026-01-01T00:00:00Z");
    const token = await issue(
      { sub: "agent:x", aud: "https://other-server.example.com/mcp", scope: "filings:read", ttlSeconds: 300 },
      { keys, issuer: ISSUER, now }
    );

    try {
      await verify(token, { keys, issuer: ISSUER, audience: AUDIENCE, now });
      expect.unreachable("verify should have thrown");
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      expect(message).not.toContain(token);
    }
  });
});

describe("key rotation", () => {
  const now = () => new Date("2026-01-01T00:00:00Z");

  it("a token signed by the active key still verifies once that key is rotated to published", async () => {
    const ringBeforeRotation = await loadOrGenerateKeys();
    const token = await issue(
      { sub: "agent:x", aud: AUDIENCE, scope: "filings:read", ttlSeconds: 300 },
      { keys: ringBeforeRotation, issuer: ISSUER, now }
    );

    const rotated = await rotateKeyRing(ringBeforeRotation);
    const signingKid = getActiveKey(ringBeforeRotation).kid;
    expect(findKey(rotated, signingKid)?.state).toBe("published");

    const claims = await verify(token, { keys: rotated, issuer: ISSUER, audience: AUDIENCE, now });
    expect(claims.sub).toBe("agent:x");
  });

  it("rotating does not break a token minted seconds before the rotation", async () => {
    const ring0 = await loadOrGenerateKeys();
    const mintedAt = () => new Date("2026-01-01T00:00:00Z");
    const token = await issue(
      { sub: "agent:just-in-time", aud: AUDIENCE, scope: "filings:read", ttlSeconds: 300 },
      { keys: ring0, issuer: ISSUER, now: mintedAt }
    );

    const rotated = await rotateKeyRing(ring0);
    const secondsLater = () => new Date("2026-01-01T00:00:05Z");
    const claims = await verify(token, { keys: rotated, issuer: ISSUER, audience: AUDIENCE, now: secondsLater });
    expect(claims.sub).toBe("agent:just-in-time");
  });

  it("a token signed by a now-retired key is rejected, even though the signature is mathematically valid", async () => {
    const ring0 = await loadOrGenerateKeys();
    const retiredKid = getActiveKey(ring0).kid;
    const token = await issue(
      { sub: "agent:x", aud: AUDIENCE, scope: "filings:read", ttlSeconds: 300 },
      { keys: ring0, issuer: ISSUER, now }
    );

    const rotated = await rotateKeyRing(ring0);
    const retired = retireKey(rotated, retiredKid);
    expect(findKey(retired, retiredKid)?.state).toBe("retired");

    await expect(verify(token, { keys: retired, issuer: ISSUER, audience: AUDIENCE, now })).rejects.toThrow();
  });

  it("a token with an unknown kid is rejected", async () => {
    const ring0 = await loadOrGenerateKeys();
    const token = await issue(
      { sub: "agent:x", aud: AUDIENCE, scope: "filings:read", ttlSeconds: 300 },
      { keys: ring0, issuer: ISSUER, now }
    );

    const foreignRing = await loadOrGenerateKeys();
    await expect(verify(token, { keys: foreignRing, issuer: ISSUER, audience: AUDIENCE, now })).rejects.toThrow();
  });

  it("verifies against whichever of several published keys actually signed the token, not just the newest", async () => {
    let ring = await loadOrGenerateKeys();
    const firstKeyToken = await issue(
      { sub: "agent:first", aud: AUDIENCE, scope: "filings:read", ttlSeconds: 300 },
      { keys: ring, issuer: ISSUER, now }
    );

    ring = await rotateKeyRing(ring);
    ring = await rotateKeyRing(ring);
    expect(ring.keys).toHaveLength(3);

    const claims = await verify(firstKeyToken, { keys: ring, issuer: ISSUER, audience: AUDIENCE, now });
    expect(claims.sub).toBe("agent:first");
  });
});
