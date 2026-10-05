import { describe, expect, it } from "vitest";
import type { TokenStore } from "../../src/store/types.js";
import { BASE_NOW, buildDelegationHarness, type DelegationHarness, type DelegationHarnessOptions } from "./delegationHarness.js";
import {
  exchangeToken,
  introspect,
  introspectActive,
  jtiOf,
  mintRootToken,
  mintUnrecordedToken,
  refreshToken,
  revokeToken,
  type TokenResponseBody
} from "./tokenFlow.js";

const LONG_TTL_SECONDS = 3600;

const OTHER_RESOURCE = "https://other-mcp.example/mcp";

export function runRevocationTests(implementationName: string, buildStore: (now: () => Date) => TokenStore): void {
  describe(`Transitive revocation: ${implementationName}`, () => {
    async function harness(options: DelegationHarnessOptions = {}): Promise<DelegationHarness> {
      return buildDelegationHarness(buildStore, { tokenTtlSeconds: LONG_TTL_SECONDS, ...options });
    }

    it("revoking the root revokes the child and grandchild, which never contacted the revoker", async () => {
      const h = await harness();
      const root = await mintRootToken(h.app, { scope: "filings:read" });
      const childRes = await exchangeToken(h.app, root.accessToken, { scope: "filings:read" });
      expect(childRes.status).toBe(200);
      const childBody = (await childRes.json()) as TokenResponseBody;
      const grandchildRes = await exchangeToken(h.app, childBody.access_token, { scope: "filings:read" });
      expect(grandchildRes.status).toBe(200);
      const grandchildBody = (await grandchildRes.json()) as TokenResponseBody;

      expect(await introspectActive(h.app, root.accessToken)).toBe(true);
      expect(await introspectActive(h.app, childBody.access_token)).toBe(true);
      expect(await introspectActive(h.app, grandchildBody.access_token)).toBe(true);

      const revokeRes = await revokeToken(h.app, root.accessToken);
      expect(revokeRes.status).toBe(200);

      expect(await introspectActive(h.app, root.accessToken)).toBe(false);
      expect(await introspectActive(h.app, childBody.access_token)).toBe(false);
      expect(await introspectActive(h.app, grandchildBody.access_token)).toBe(false);
    });

    it("revoking a middle node leaves its parent active and kills its descendants", async () => {
      const h = await harness();
      const root = await mintRootToken(h.app, { scope: "filings:read" });
      const childRes = await exchangeToken(h.app, root.accessToken, { scope: "filings:read" });
      const childBody = (await childRes.json()) as TokenResponseBody;
      const grandchildRes = await exchangeToken(h.app, childBody.access_token, { scope: "filings:read" });
      const grandchildBody = (await grandchildRes.json()) as TokenResponseBody;

      const revokeRes = await revokeToken(h.app, childBody.access_token);
      expect(revokeRes.status).toBe(200);

      expect(await introspectActive(h.app, root.accessToken)).toBe(true);
      expect(await introspectActive(h.app, childBody.access_token)).toBe(false);
      expect(await introspectActive(h.app, grandchildBody.access_token)).toBe(false);
    });

    it("revoking a leaf affects nothing else", async () => {
      const h = await harness();
      const root = await mintRootToken(h.app, { scope: "filings:read" });
      const childRes = await exchangeToken(h.app, root.accessToken, { scope: "filings:read" });
      const childBody = (await childRes.json()) as TokenResponseBody;

      const revokeRes = await revokeToken(h.app, childBody.access_token);
      expect(revokeRes.status).toBe(200);

      expect(await introspectActive(h.app, root.accessToken)).toBe(true);
      expect(await introspectActive(h.app, childBody.access_token)).toBe(false);
    });

    it("revoking twice is idempotent and both calls return 200 (RFC 7009 §2.2)", async () => {
      const h = await harness();
      const root = await mintRootToken(h.app, { scope: "filings:read" });

      const first = await revokeToken(h.app, root.accessToken);
      expect(first.status).toBe(200);
      const second = await revokeToken(h.app, root.accessToken);
      expect(second.status).toBe(200);

      expect(await introspectActive(h.app, root.accessToken)).toBe(false);
    });

    it("a 4-deep chain: revoking at depth 2 kills depths 2/3/4, depth 1 stays alive", async () => {
      const h = await harness({ maxDelegationDepth: 10 });
      const root = await mintRootToken(h.app, { scope: "filings:read" });
      const d1Res = await exchangeToken(h.app, root.accessToken, { scope: "filings:read" });
      const d1Body = (await d1Res.json()) as TokenResponseBody;
      const d2Res = await exchangeToken(h.app, d1Body.access_token, { scope: "filings:read" });
      const d2Body = (await d2Res.json()) as TokenResponseBody;
      const d3Res = await exchangeToken(h.app, d2Body.access_token, { scope: "filings:read" });
      const d3Body = (await d3Res.json()) as TokenResponseBody;
      const d4Res = await exchangeToken(h.app, d3Body.access_token, { scope: "filings:read" });
      const d4Body = (await d4Res.json()) as TokenResponseBody;

      const revokeRes = await revokeToken(h.app, d2Body.access_token);
      expect(revokeRes.status).toBe(200);

      expect(await introspectActive(h.app, root.accessToken)).toBe(true);
      expect(await introspectActive(h.app, d1Body.access_token)).toBe(true);
      expect(await introspectActive(h.app, d2Body.access_token)).toBe(false);
      expect(await introspectActive(h.app, d3Body.access_token)).toBe(false);
      expect(await introspectActive(h.app, d4Body.access_token)).toBe(false);
    });

    it("eager marking sets revoked_at directly on each descendant's own row, not only reachable via ancestor walk", async () => {
      const h = await harness();
      const root = await mintRootToken(h.app, { scope: "filings:read" });
      const rootJti = jtiOf(root.accessToken);
      const childRes = await exchangeToken(h.app, root.accessToken, { scope: "filings:read" });
      const childBody = (await childRes.json()) as TokenResponseBody;
      const childJti = jtiOf(childBody.access_token);
      const grandchildRes = await exchangeToken(h.app, childBody.access_token, { scope: "filings:read" });
      const grandchildBody = (await grandchildRes.json()) as TokenResponseBody;
      const grandchildJti = jtiOf(grandchildBody.access_token);

      const revokeRes = await revokeToken(h.app, root.accessToken);
      expect(revokeRes.status).toBe(200);

      const rootRecord = await h.store.getRecord(rootJti);
      const childRecord = await h.store.getRecord(childJti);
      const grandchildRecord = await h.store.getRecord(grandchildJti);
      expect(rootRecord?.revoked).toBe(true);
      expect(childRecord?.revoked).toBe(true);
      expect(grandchildRecord?.revoked).toBe(true);
    });

    it("records an audit entry: which jti, how many descendants, never the token value", async () => {
      const h = await harness();
      const root = await mintRootToken(h.app, { scope: "filings:read" });
      const rootJti = jtiOf(root.accessToken);
      const childRes = await exchangeToken(h.app, root.accessToken, { scope: "filings:read" });
      const childBody = (await childRes.json()) as TokenResponseBody;
      const grandchildRes = await exchangeToken(h.app, childBody.access_token, { scope: "filings:read" });
      await grandchildRes.json();

      const revokeRes = await revokeToken(h.app, root.accessToken);
      expect(revokeRes.status).toBe(200);

      const entries = await h.store.getAuditLog(rootJti);
      expect(entries.length).toBeGreaterThanOrEqual(1);
      const entry = entries[0];
      expect(entry?.eventType).toBe("revoke");
      expect(entry?.subject).toBe(rootJti);
      expect(entry?.metadata?.descendant_count).toBe(2);
      expect(entry?.createdAt).toBeInstanceOf(Date);

      expect(JSON.stringify(entry)).not.toContain(root.accessToken);
    });

    it("the race: revoking a parent concurrently with exchanging it for a child never leaves the child live", async () => {
      const h = await harness();
      const root = await mintRootToken(h.app, { scope: "filings:read" });

      const [revokeRes, exchangeRes] = await Promise.all([
        revokeToken(h.app, root.accessToken),
        exchangeToken(h.app, root.accessToken, { scope: "filings:read" })
      ]);

      expect(revokeRes.status).toBe(200);
      expect(await introspectActive(h.app, root.accessToken)).toBe(false);

      if (exchangeRes.status === 200) {
        const body = (await exchangeRes.json()) as TokenResponseBody;
        expect(await introspectActive(h.app, body.access_token)).toBe(false);
      } else {
        expect(exchangeRes.status).toBe(400);
        const body = (await exchangeRes.json()) as TokenResponseBody;
        expect(body.error).toBe("invalid_grant");
      }
    });

    it("introspects a token minted for an RFC 8707 resource as active, reporting its aud", async () => {
      const h = await harness();
      const root = await mintRootToken(h.app, { scope: "filings:read", resource: OTHER_RESOURCE });

      const body = await introspect(h.app, root.accessToken);
      expect(body.active).toBe(true);
      expect(body.aud).toBe(OTHER_RESOURCE);
    });

    it("revokes a resource-bound token, and its refresh token stops working", async () => {
      const h = await harness();
      const root = await mintRootToken(h.app, { scope: "filings:read", resource: OTHER_RESOURCE });

      expect((await revokeToken(h.app, root.accessToken)).status).toBe(200);

      expect(await introspectActive(h.app, root.accessToken)).toBe(false);
      const refreshed = await refreshToken(h.app, root.refreshToken);
      expect(refreshed.status).toBe(400);
      expect(((await refreshed.json()) as TokenResponseBody).error).toBe("invalid_grant");
    });

    it("a validly signed token with no stored record introspects inactive", async () => {
      const h = await harness();
      const token = await mintUnrecordedToken(h.keys, BASE_NOW);

      expect(await introspectActive(h.app, token)).toBe(false);
    });

    it("rejects a token that names itself as its own parent", async () => {
      const h = await harness();
      const exp = Math.floor(BASE_NOW.getTime() / 1000) + LONG_TTL_SECONDS;
      const jti = `self-parent-${Math.random().toString(36).slice(2)}`;

      await expect(h.store.record({ jti, exp, parentJti: jti })).rejects.toThrow();
    });

    it("rejects a cycle formed by re-recording an ancestor to point at its own descendant", async () => {
      const h = await harness();
      const exp = Math.floor(BASE_NOW.getTime() / 1000) + LONG_TTL_SECONDS;
      const a = `cycle-a-${Math.random().toString(36).slice(2)}`;
      const b = `cycle-b-${Math.random().toString(36).slice(2)}`;

      await h.store.record({ jti: a, exp });
      await h.store.record({ jti: b, exp, parentJti: a, depth: 1 });

      await expect(h.store.record({ jti: a, exp, parentJti: b, depth: 2 })).rejects.toThrow();
    });
  });
}
