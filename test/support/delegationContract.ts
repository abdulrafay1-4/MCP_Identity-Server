import { describe, expect, it } from "vitest";
import type { TokenStore } from "../../src/store/types.js";
import { BASE_NOW, buildDelegationHarness, type DelegationHarness, type DelegationHarnessOptions } from "./delegationHarness.js";
import { decodePayload, exchangeToken, jtiOf, mintRootToken, mintUnrecordedToken, revokeToken, type TokenResponseBody } from "./tokenFlow.js";

const ACCESS_TOKEN_TYPE_URN = "urn:ietf:params:oauth:token-type:access_token";

const OTHER_RESOURCE = "https://other-mcp.example/mcp";

export function runDelegationTests(implementationName: string, buildStore: (now: () => Date) => TokenStore): void {
  describe(`Delegation (RFC 8693 token exchange): ${implementationName}`, () => {
    async function harness(options: DelegationHarnessOptions = {}): Promise<DelegationHarness> {
      return buildDelegationHarness(buildStore, options);
    }

    it("narrows scope on exchange and emits act naming the parent's sub", async () => {
      const { app } = await harness();
      const root = await mintRootToken(app, { scope: "filings:read quotes:read" });

      const res = await exchangeToken(app, root.accessToken, { scope: "filings:read" });
      expect(res.status).toBe(200);
      const body = (await res.json()) as TokenResponseBody;
      expect(body.scope).toBe("filings:read");
      expect(body.issued_token_type).toBe(ACCESS_TOKEN_TYPE_URN);

      const payload = decodePayload(body.access_token);
      expect(payload.sub).not.toBe(root.sub);
      expect((payload.act as { sub?: string } | undefined)?.sub).toBe(root.sub);
    });

    it("allows equal scope (subset, not proper subset)", async () => {
      const { app } = await harness();
      const root = await mintRootToken(app, { scope: "filings:read quotes:read" });

      const res = await exchangeToken(app, root.accessToken, { scope: "filings:read quotes:read" });
      expect(res.status).toBe(200);
      const body = (await res.json()) as TokenResponseBody;
      expect(body.scope).toBe("filings:read quotes:read");
    });

    it("refuses a wider scope with invalid_scope, never silently clamping it", async () => {
      const { app } = await harness();
      const root = await mintRootToken(app, { scope: "filings:read" });

      const res = await exchangeToken(app, root.accessToken, { scope: "filings:read quotes:read" });
      expect(res.status).toBe(400);
      const body = (await res.json()) as TokenResponseBody;
      expect(body.error).toBe("invalid_scope");
    });

    it("refuses exchanging an expired subject_token", async () => {
      const h = await harness({ tokenTtlSeconds: 60 });
      const root = await mintRootToken(h.app, { scope: "filings:read" });

      h.setNow(new Date(BASE_NOW.getTime() + 61_000));

      const res = await exchangeToken(h.app, root.accessToken, { scope: "filings:read" });
      expect(res.status).toBe(400);
      const body = (await res.json()) as TokenResponseBody;
      expect(body.error).toBe("invalid_grant");
    });

    it("refuses exchanging a revoked subject_token (long TTL, so expiry cannot be the cause)", async () => {
      const h = await harness({ tokenTtlSeconds: 3600 });
      const root = await mintRootToken(h.app, { scope: "filings:read" });

      const revokeRes = await revokeToken(h.app, root.accessToken);
      expect(revokeRes.status).toBe(200);

      const res = await exchangeToken(h.app, root.accessToken, { scope: "filings:read" });
      expect(res.status).toBe(400);
      const body = (await res.json()) as TokenResponseBody;
      expect(body.error).toBe("invalid_grant");
    });

    it("exchanges a resource-bound token and the child keeps the parent's aud", async () => {
      const { app } = await harness();
      const root = await mintRootToken(app, { scope: "filings:read", resource: OTHER_RESOURCE });

      const res = await exchangeToken(app, root.accessToken, { scope: "filings:read" });
      expect(res.status).toBe(200);
      const body = (await res.json()) as TokenResponseBody;
      expect(decodePayload(body.access_token).aud).toBe(OTHER_RESOURCE);
    });

    it("accepts an exchange resource equal to the parent's aud and refuses a different one with invalid_target", async () => {
      const { app } = await harness();
      const root = await mintRootToken(app, { scope: "filings:read", resource: OTHER_RESOURCE });

      const same = await exchangeToken(app, root.accessToken, { scope: "filings:read", resource: OTHER_RESOURCE });
      expect(same.status).toBe(200);

      const different = await exchangeToken(app, root.accessToken, {
        scope: "filings:read",
        resource: "https://third-mcp.example/mcp"
      });
      expect(different.status).toBe(400);
      expect(((await different.json()) as TokenResponseBody).error).toBe("invalid_target");
    });

    it("refuses exchanging a validly signed token that has no stored record", async () => {
      const h = await harness();
      const token = await mintUnrecordedToken(h.keys, BASE_NOW);

      const res = await exchangeToken(h.app, token, { scope: "filings:read" });
      expect(res.status).toBe(400);
      expect(((await res.json()) as TokenResponseBody).error).toBe("invalid_grant");
    });

    it("refuses at the delegation depth cap, allows just below it", async () => {
      const h = await harness({ maxDelegationDepth: 2 });
      const root = await mintRootToken(h.app, { scope: "filings:read" });

      const firstExchange = await exchangeToken(h.app, root.accessToken, { scope: "filings:read" });
      expect(firstExchange.status).toBe(200);
      const firstBody = (await firstExchange.json()) as TokenResponseBody;

      const secondExchange = await exchangeToken(h.app, firstBody.access_token, { scope: "filings:read" });
      expect(secondExchange.status).toBe(400);
      const secondBody = (await secondExchange.json()) as TokenResponseBody;
      expect(secondBody.error).toBe("invalid_grant");
    });

    it("persists parent_jti and depth correctly", async () => {
      const h = await harness();
      const root = await mintRootToken(h.app, { scope: "filings:read" });
      const rootJti = jtiOf(root.accessToken);

      const exchangeRes = await exchangeToken(h.app, root.accessToken, { scope: "filings:read" });
      expect(exchangeRes.status).toBe(200);
      const body = (await exchangeRes.json()) as TokenResponseBody;
      const childJti = jtiOf(body.access_token);

      const childRecord = await h.store.getRecord(childJti);
      expect(childRecord?.parentJti).toBe(rootJti);
      expect(childRecord?.depth).toBe(1);

      const rootRecord = await h.store.getRecord(rootJti);
      expect(rootRecord?.parentJti).toBeNull();
      expect(rootRecord?.depth).toBe(0);
    });

    it("reconstructs a 3-deep delegation chain from the leaf", async () => {
      const h = await harness({ maxDelegationDepth: 10 });
      const root = await mintRootToken(h.app, { scope: "filings:read" });

      const exchange1 = await exchangeToken(h.app, root.accessToken, { scope: "filings:read" });
      expect(exchange1.status).toBe(200);
      const body1 = (await exchange1.json()) as TokenResponseBody;

      const exchange2 = await exchangeToken(h.app, body1.access_token, { scope: "filings:read" });
      expect(exchange2.status).toBe(200);
      const body2 = (await exchange2.json()) as TokenResponseBody;

      const exchange3 = await exchangeToken(h.app, body2.access_token, { scope: "filings:read" });
      expect(exchange3.status).toBe(200);
      const body3 = (await exchange3.json()) as TokenResponseBody;

      const leafJti = jtiOf(body3.access_token);
      const chain = await h.store.getChain(leafJti);

      expect(chain).toHaveLength(4);
      expect(chain.map((link) => link.depth)).toEqual([0, 1, 2, 3]);
      expect(chain[3]?.jti).toBe(leafJti);
      expect(chain[0]?.parentJti).toBeNull();
      for (let i = 1; i < chain.length; i++) {
        expect(chain[i]?.parentJti).toBe(chain[i - 1]?.jti);
      }
    });

    it("narrows twice: a child of a child composes scope transitively", async () => {
      const h = await harness();
      const root = await mintRootToken(h.app, { scope: "a b c" });

      const child1 = await exchangeToken(h.app, root.accessToken, { scope: "a b" });
      expect(child1.status).toBe(200);
      const child1Body = (await child1.json()) as TokenResponseBody;
      expect(child1Body.scope).toBe("a b");

      const child2 = await exchangeToken(h.app, child1Body.access_token, { scope: "a" });
      expect(child2.status).toBe(200);
      const child2Body = (await child2.json()) as TokenResponseBody;
      expect(child2Body.scope).toBe("a");

      const widenAttempt = await exchangeToken(h.app, child1Body.access_token, { scope: "a c" });
      expect(widenAttempt.status).toBe(400);
      const widenBody = (await widenAttempt.json()) as TokenResponseBody;
      expect(widenBody.error).toBe("invalid_scope");
    });
  });
}
