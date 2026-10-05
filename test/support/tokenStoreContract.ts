import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { AuthorizationCode, TokenStore } from "../../src/store/types.js";

export interface PrunableTokenStore extends TokenStore {
  pruneExpired(): Promise<void>;
}

export interface TokenStoreHarness {
  store: PrunableTokenStore;
  setNow: (date: Date) => void;
}

function makeAuthCode(overrides: Partial<AuthorizationCode> = {}): AuthorizationCode {
  return {
    code: randomUUID(),
    clientId: "contract-client",
    redirectUri: "https://agent.example.com/callback",
    codeChallenge: "challenge",
    codeChallengeMethod: "S256",
    scope: "filings:read",
    sub: "agent:research-bot:7f3a",
    aud: "https://mcp.example.com/mcp",
    exp: overrides.exp ?? Math.floor(Date.now() / 1000) + 300,
    ...overrides
  };
}

export function runTokenStoreContractTests(implementationName: string, buildHarness: () => Promise<TokenStoreHarness>): void {
  describe(`TokenStore contract: ${implementationName}`, () => {
    it("records a token, and it reads as not revoked", async () => {
      const { store } = await buildHarness();
      const jti = randomUUID();

      await store.record({ jti, exp: Math.floor(Date.now() / 1000) + 300 });

      expect(await store.isRevoked(jti)).toBe(false);
    });

    it("revoke then isRevoked is true", async () => {
      const { store } = await buildHarness();
      const jti = randomUUID();

      await store.record({ jti, exp: Math.floor(Date.now() / 1000) + 300 });
      expect(await store.isRevoked(jti)).toBe(false);

      await store.revoke(jti);
      expect(await store.isRevoked(jti)).toBe(true);
    });

    it("an unknown jti is not revoked", async () => {
      const { store } = await buildHarness();
      expect(await store.isRevoked(`never-seen-${randomUUID()}`)).toBe(false);
    });

    it("revoking an unknown jti is a safe no-op", async () => {
      const { store } = await buildHarness();
      await expect(store.revoke(`never-seen-${randomUUID()}`)).resolves.toEqual({ descendantCount: 0 });
    });

    it("prunes expired tokens and expired authorization codes", async () => {
      let current = new Date("2026-01-01T00:00:00Z");
      const { store, setNow } = await buildHarness();
      setNow(current);
      const nowSeconds = Math.floor(current.getTime() / 1000);

      const jti = randomUUID();
      const code = makeAuthCode({ exp: nowSeconds + 1 });
      await store.record({ jti, exp: nowSeconds + 1 });
      await store.storeAuthorizationCode(code);

      current = new Date(current.getTime() + 5 * 60 * 1000);
      setNow(current);
      await store.pruneExpired();

      expect(await store.isRevoked(jti)).toBe(false);
      expect(await store.consumeAuthorizationCode(code.code)).toBeUndefined();
    });

    it("does not prune a record that has not yet expired", async () => {
      let current = new Date("2026-01-01T00:00:00Z");
      const { store, setNow } = await buildHarness();
      setNow(current);
      const nowSeconds = Math.floor(current.getTime() / 1000);

      const jti = randomUUID();
      await store.record({ jti, exp: nowSeconds + 300 });
      await store.revoke(jti);

      current = new Date(current.getTime() + 10 * 1000);
      setNow(current);
      await store.pruneExpired();

      expect(await store.isRevoked(jti)).toBe(true);
    });

    it("consumes an authorization code exactly once", async () => {
      const { store } = await buildHarness();
      const authCode = makeAuthCode();
      await store.storeAuthorizationCode(authCode);

      const first = await store.consumeAuthorizationCode(authCode.code);
      expect(first?.clientId).toBe(authCode.clientId);
      expect(first?.sub).toBe(authCode.sub);

      const second = await store.consumeAuthorizationCode(authCode.code);
      expect(second).toBeUndefined();
    });

    it("returns undefined for an unknown code", async () => {
      const { store } = await buildHarness();
      expect(await store.consumeAuthorizationCode(`does-not-exist-${randomUUID()}`)).toBeUndefined();
    });

    it("returns undefined for an expired code", async () => {
      let current = new Date("2026-01-01T00:00:00Z");
      const { store, setNow } = await buildHarness();
      setNow(current);
      const nowSeconds = Math.floor(current.getTime() / 1000);

      const authCode = makeAuthCode({ exp: nowSeconds + 5 });
      await store.storeAuthorizationCode(authCode);

      current = new Date(current.getTime() + 60 * 1000);
      setNow(current);
      expect(await store.consumeAuthorizationCode(authCode.code)).toBeUndefined();
    });

    it("concurrent double-consume of a code yields exactly one success", async () => {
      const { store } = await buildHarness();
      const authCode = makeAuthCode();
      await store.storeAuthorizationCode(authCode);

      const [first, second] = await Promise.all([
        store.consumeAuthorizationCode(authCode.code),
        store.consumeAuthorizationCode(authCode.code)
      ]);

      const successes = [first, second].filter((result) => result !== undefined);
      expect(successes).toHaveLength(1);
    });
  });
}
