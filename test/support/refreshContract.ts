import { describe, expect, it } from "vitest";
import type { TokenStore } from "../../src/store/types.js";
import { sha256Hex } from "../../src/hash.js";
import { BASE_NOW, buildDelegationHarness, CLIENT, type DelegationHarness, type DelegationHarnessOptions } from "./delegationHarness.js";
import type { PrunableTokenStore } from "./tokenStoreContract.js";
import {
  CIMD_CLIENT_ID,
  exchangeToken,
  introspect,
  introspectActive,
  jtiOf,
  mintCimdToken,
  mintRootToken,
  refreshToken,
  revokeToken,
  stubCimdClient,
  type TokenResponseBody
} from "./tokenFlow.js";

const LONG_TTL_SECONDS = 3600;

export function runRefreshTests(implementationName: string, buildStore: (now: () => Date) => TokenStore): void {
  describe(`Refresh tokens (rotation + reuse detection): ${implementationName}`, () => {
    async function harness(options: DelegationHarnessOptions = {}): Promise<DelegationHarness> {
      return buildDelegationHarness(buildStore, { tokenTtlSeconds: LONG_TTL_SECONDS, ...options });
    }

    it("happy path: refreshing returns a new access token and a new refresh token", async () => {
      const h = await harness();
      const root = await mintRootToken(h.app, { scope: "filings:read" });

      const res = await refreshToken(h.app, root.refreshToken);
      expect(res.status).toBe(200);
      const body = (await res.json()) as TokenResponseBody;

      expect(body.access_token).toBeTruthy();
      expect(body.access_token).not.toBe(root.accessToken);
      expect(body.refresh_token).toBeTruthy();
      expect(body.refresh_token).not.toBe(root.refreshToken);
      expect(body.scope).toBe("filings:read");

      expect(await introspectActive(h.app, body.access_token)).toBe(true);
    });

    it("the old refresh token stops working once the grace window has passed", async () => {
      const h = await harness({ refreshReuseGraceSeconds: 5 });
      const root = await mintRootToken(h.app, { scope: "filings:read" });

      const first = await refreshToken(h.app, root.refreshToken);
      expect(first.status).toBe(200);

      h.setNow(new Date(BASE_NOW.getTime() + 60_000));

      const replay = await refreshToken(h.app, root.refreshToken);
      expect(replay.status).toBe(400);
      const body = (await replay.json()) as TokenResponseBody;
      expect(body.error).toBe("invalid_grant");
    });

    it("replaying a consumed refresh token past the grace window revokes the whole family", async () => {
      const h = await harness({ refreshReuseGraceSeconds: 5 });
      const root = await mintRootToken(h.app, { scope: "filings:read" });
      const rootAccessJti = jtiOf(root.accessToken);

      const rotated = await refreshToken(h.app, root.refreshToken);
      expect(rotated.status).toBe(200);
      const rotatedBody = (await rotated.json()) as TokenResponseBody;

      expect(await introspectActive(h.app, root.accessToken)).toBe(true);
      expect(await introspectActive(h.app, rotatedBody.access_token)).toBe(true);

      h.setNow(new Date(BASE_NOW.getTime() + 60_000));

      const replay = await refreshToken(h.app, root.refreshToken);
      expect(replay.status).toBe(400);
      expect(((await replay.json()) as TokenResponseBody).error).toBe("invalid_grant");

      expect(await introspectActive(h.app, root.accessToken)).toBe(false);
      expect(await introspectActive(h.app, rotatedBody.access_token)).toBe(false);

      const rotatedJti = jtiOf(rotatedBody.access_token);
      const rootEntries = await h.store.getAuditLog(rootAccessJti);
      const rotatedEntries = await h.store.getAuditLog(rotatedJti);
      expect(JSON.stringify(rootEntries)).not.toContain(root.refreshToken);
      expect(JSON.stringify(rotatedEntries)).not.toContain(root.refreshToken);
    });

    it("refresh cannot widen scope", async () => {
      const h = await harness();
      const root = await mintRootToken(h.app, { scope: "filings:read" });

      const res = await refreshToken(h.app, root.refreshToken, { scope: "filings:read quotes:read" });
      expect(res.status).toBe(400);
      const body = (await res.json()) as TokenResponseBody;
      expect(body.error).toBe("invalid_scope");

      const retry = await refreshToken(h.app, root.refreshToken, { scope: "filings:read" });
      expect(retry.status).toBe(200);
    });

    it("refresh of a family whose token chain was revoked fails", async () => {
      const h = await harness();
      const root = await mintRootToken(h.app, { scope: "filings:read" });

      const revokeRes = await revokeToken(h.app, root.accessToken);
      expect(revokeRes.status).toBe(200);

      const res = await refreshToken(h.app, root.refreshToken);
      expect(res.status).toBe(400);
      expect(((await res.json()) as TokenResponseBody).error).toBe("invalid_grant");
    });

    it("an unknown/garbage refresh token is refused without revealing whether it ever existed", async () => {
      const h = await harness();
      const res = await refreshToken(h.app, "totally-made-up-refresh-token-value");
      expect(res.status).toBe(400);
      const body = (await res.json()) as TokenResponseBody;
      expect(body.error).toBe("invalid_grant");
      expect(body.error_description).toBe("invalid refresh token");
    });

    describe("concurrency: grace window", () => {
      it("a legitimate double-submit inside the window succeeds without killing the family", async () => {
        const h = await harness({ refreshReuseGraceSeconds: 10 });
        const root = await mintRootToken(h.app, { scope: "filings:read" });

        const [first, second] = await Promise.all([refreshToken(h.app, root.refreshToken), refreshToken(h.app, root.refreshToken)]);

        const statuses = [first.status, second.status].sort();
        expect(statuses).toEqual([200, 200]);

        const firstBody = (await first.json()) as TokenResponseBody;
        const secondBody = (await second.json()) as TokenResponseBody;

        expect(await introspectActive(h.app, firstBody.access_token)).toBe(true);
        expect(await introspectActive(h.app, secondBody.access_token)).toBe(true);
        expect(await introspectActive(h.app, root.accessToken)).toBe(true);
      });

      it("a genuine replay outside the window still kills the family", async () => {
        const h = await harness({ refreshReuseGraceSeconds: 2 });
        const root = await mintRootToken(h.app, { scope: "filings:read" });

        const rotated = await refreshToken(h.app, root.refreshToken);
        expect(rotated.status).toBe(200);
        const rotatedBody = (await rotated.json()) as TokenResponseBody;

        h.setNow(new Date(BASE_NOW.getTime() + 10_000));

        const replay = await refreshToken(h.app, root.refreshToken);
        expect(replay.status).toBe(400);
        expect(((await replay.json()) as TokenResponseBody).error).toBe("invalid_grant");

        expect(await introspectActive(h.app, root.accessToken)).toBe(false);
        expect(await introspectActive(h.app, rotatedBody.access_token)).toBe(false);
      });

      it("a second replay of an already-graced generation kills the family, even inside the window", async () => {
        const h = await harness({ refreshReuseGraceSeconds: 60 });
        const root = await mintRootToken(h.app, { scope: "filings:read" });

        const first = await refreshToken(h.app, root.refreshToken);
        expect(first.status).toBe(200);
        const second = await refreshToken(h.app, root.refreshToken);
        expect(second.status).toBe(200);
        const third = await refreshToken(h.app, root.refreshToken);
        expect(third.status).toBe(400);
        expect(((await third.json()) as TokenResponseBody).error).toBe("invalid_grant");

        const firstBody = (await first.json()) as TokenResponseBody;
        const secondBody = (await second.json()) as TokenResponseBody;
        expect(await introspectActive(h.app, firstBody.access_token)).toBe(false);
        expect(await introspectActive(h.app, secondBody.access_token)).toBe(false);
        expect(await introspectActive(h.app, root.accessToken)).toBe(false);
      });
    });

    describe("refresh token lifetime is independent of the access token", () => {
      const SHORT_ACCESS_TTL_SECONDS = 60;
      const afterAccessExpiry = new Date(BASE_NOW.getTime() + 120_000);

      const shortHarness = (options: DelegationHarnessOptions = {}): Promise<DelegationHarness> =>
        harness({ tokenTtlSeconds: SHORT_ACCESS_TTL_SECONDS, ...options });

      it("is redeemable after its access token has expired", async () => {
        const h = await shortHarness();
        const root = await mintRootToken(h.app, { scope: "filings:read" });

        h.setNow(afterAccessExpiry);

        const res = await refreshToken(h.app, root.refreshToken);
        expect(res.status).toBe(200);
        const body = (await res.json()) as TokenResponseBody;
        expect(await introspectActive(h.app, body.access_token)).toBe(true);
      });

      it("is redeemable after its expired access token has been pruned", async () => {
        const h = await shortHarness();
        const root = await mintRootToken(h.app, { scope: "filings:read" });

        h.setNow(afterAccessExpiry);
        await (h.store as PrunableTokenStore).pruneExpired();
        expect(await h.store.getRecord(jtiOf(root.accessToken))).toBeUndefined();

        const res = await refreshToken(h.app, root.refreshToken);
        expect(res.status).toBe(200);
      });

      it("stays revoked after the revoked access token has expired and been pruned", async () => {
        const h = await shortHarness();
        const root = await mintRootToken(h.app, { scope: "filings:read" });

        expect((await revokeToken(h.app, root.accessToken)).status).toBe(200);

        h.setNow(afterAccessExpiry);
        const beforePrune = await refreshToken(h.app, root.refreshToken);
        expect(beforePrune.status).toBe(400);

        await (h.store as PrunableTokenStore).pruneExpired();
        const afterPrune = await refreshToken(h.app, root.refreshToken);
        expect(afterPrune.status).toBe(400);
      });

      it("revoking an earlier access token of the family revokes the latest refresh token and access token", async () => {
        const h = await shortHarness();
        const root = await mintRootToken(h.app, { scope: "filings:read" });
        const rotated = await refreshToken(h.app, root.refreshToken);
        const rotatedBody = (await rotated.json()) as TokenResponseBody;
        expect(rotated.status).toBe(200);

        expect((await revokeToken(h.app, root.accessToken)).status).toBe(200);

        expect(await introspectActive(h.app, rotatedBody.access_token)).toBe(false);
        const next = await refreshToken(h.app, rotatedBody.refresh_token ?? "");
        expect(next.status).toBe(400);
        expect(((await next.json()) as TokenResponseBody).error).toBe("invalid_grant");
      });

      it("revoking a delegated child leaves the family alone", async () => {
        const h = await shortHarness();
        const root = await mintRootToken(h.app, { scope: "filings:read" });
        const child = (await (await exchangeToken(h.app, root.accessToken, { scope: "filings:read" })).json()) as TokenResponseBody;

        expect((await revokeToken(h.app, child.access_token)).status).toBe(200);

        expect(await introspectActive(h.app, root.accessToken)).toBe(true);
        expect((await refreshToken(h.app, root.refreshToken)).status).toBe(200);
      });

      it("revoking the refresh token revokes the family, its access tokens and their delegated children", async () => {
        const h = await shortHarness();
        const root = await mintRootToken(h.app, { scope: "filings:read" });
        const rotatedBody = (await (await refreshToken(h.app, root.refreshToken)).json()) as TokenResponseBody;
        const child = (await (await exchangeToken(h.app, root.accessToken, { scope: "filings:read" })).json()) as TokenResponseBody;

        expect((await revokeToken(h.app, rotatedBody.refresh_token ?? "")).status).toBe(200);

        expect(await introspectActive(h.app, root.accessToken)).toBe(false);
        expect(await introspectActive(h.app, rotatedBody.access_token)).toBe(false);
        expect(await introspectActive(h.app, child.access_token)).toBe(false);
        expect((await refreshToken(h.app, rotatedBody.refresh_token ?? "")).status).toBe(400);
      });

      it("revoking an unknown refresh token still answers 200", async () => {
        const h = await shortHarness();
        expect((await revokeToken(h.app, "not-a-token-we-issued")).status).toBe(200);
      });

      it("the family ends at its original lifetime; rotation does not extend it", async () => {
        const h = await shortHarness({ refreshTokenTtlSeconds: 1000 });
        const root = await mintRootToken(h.app, { scope: "filings:read" });

        h.setNow(new Date(BASE_NOW.getTime() + 600_000));
        const second = (await (await refreshToken(h.app, root.refreshToken)).json()) as TokenResponseBody;
        expect(second.refresh_token).toBeTruthy();

        h.setNow(new Date(BASE_NOW.getTime() + 999_000));
        const third = await refreshToken(h.app, second.refresh_token ?? "");
        expect(third.status).toBe(200);
        const thirdBody = (await third.json()) as TokenResponseBody;

        h.setNow(new Date(BASE_NOW.getTime() + 1_001_000));
        const late = await refreshToken(h.app, thirdBody.refresh_token ?? "");
        expect(late.status).toBe(400);
      });
    });

    it("a replay inside the grace window returns an access token only, so the family cannot fork", async () => {
      const h = await harness({ refreshReuseGraceSeconds: 60 });
      const root = await mintRootToken(h.app, { scope: "filings:read" });

      const first = await refreshToken(h.app, root.refreshToken);
      const firstBody = (await first.json()) as TokenResponseBody;
      const graced = await refreshToken(h.app, root.refreshToken);
      expect(graced.status).toBe(200);
      const gracedBody = (await graced.json()) as TokenResponseBody;

      expect(firstBody.refresh_token).toBeTruthy();
      expect(gracedBody.access_token).toBeTruthy();
      expect(gracedBody.refresh_token).toBeUndefined();
      expect(await introspectActive(h.app, gracedBody.access_token)).toBe(true);
    });

    it("an access token issued by a graced replay is revoked with its family", async () => {
      const h = await harness({ refreshReuseGraceSeconds: 60 });
      const root = await mintRootToken(h.app, { scope: "filings:read" });

      const first = (await (await refreshToken(h.app, root.refreshToken)).json()) as TokenResponseBody;
      const graced = (await (await refreshToken(h.app, root.refreshToken)).json()) as TokenResponseBody;

      expect((await revokeToken(h.app, first.access_token)).status).toBe(200);
      expect(await introspectActive(h.app, graced.access_token)).toBe(false);
    });

    describe("client binding", () => {
      it("introspection reports the client the token was issued to", async () => {
        const h = await harness({ cimdClient: stubCimdClient() });
        const demo = await mintRootToken(h.app, { scope: "filings:read" });
        const cimd = await mintCimdToken(h.app);

        expect((await introspect(h.app, demo.accessToken)).client_id).toBe(CLIENT.clientId);
        expect((await introspect(h.app, cimd.accessToken)).client_id).toBe(CIMD_CLIENT_ID);
      });

      it("records the client on the access token and refresh token rows", async () => {
        const h = await harness({ cimdClient: stubCimdClient() });
        const cimd = await mintCimdToken(h.app);

        expect((await h.store.getRecord(jtiOf(cimd.accessToken)))?.clientId).toBe(CIMD_CLIENT_ID);
        expect((await h.store.getRefreshTokenRecord(sha256Hex(cimd.refreshToken)))?.clientId).toBe(CIMD_CLIENT_ID);
      });

      it("the demo client cannot redeem a CIMD client's refresh token, and the attempt does not revoke it", async () => {
        const h = await harness({ cimdClient: stubCimdClient() });
        const cimd = await mintCimdToken(h.app);

        const res = await refreshToken(h.app, cimd.refreshToken);
        expect(res.status).toBe(400);
        expect(((await res.json()) as TokenResponseBody).error).toBe("invalid_grant");
        expect(await introspectActive(h.app, cimd.accessToken)).toBe(true);
      });

      it("the demo client cannot exchange a CIMD client's access token", async () => {
        const h = await harness({ cimdClient: stubCimdClient() });
        const cimd = await mintCimdToken(h.app);

        const res = await exchangeToken(h.app, cimd.accessToken, { scope: "filings:read" });
        expect(res.status).toBe(400);
        expect(((await res.json()) as TokenResponseBody).error).toBe("invalid_grant");
      });

      it("a delegated child keeps its parent's client", async () => {
        const h = await harness();
        const root = await mintRootToken(h.app, { scope: "filings:read" });
        const child = (await (await exchangeToken(h.app, root.accessToken, { scope: "filings:read" })).json()) as TokenResponseBody;

        expect((await introspect(h.app, child.access_token)).client_id).toBe(CLIENT.clientId);
      });

      it("a refreshed access token stays bound to the same client", async () => {
        const h = await harness();
        const root = await mintRootToken(h.app, { scope: "filings:read" });
        const rotated = (await (await refreshToken(h.app, root.refreshToken)).json()) as TokenResponseBody;

        expect((await introspect(h.app, rotated.access_token)).client_id).toBe(CLIENT.clientId);
        const row = await h.store.getRefreshTokenRecord(sha256Hex(rotated.refresh_token ?? ""));
        expect(row?.clientId).toBe(CLIENT.clientId);
      });
    });

    it("a refresh token never appears in an introspection response", async () => {
      const h = await harness();
      const root = await mintRootToken(h.app, { scope: "filings:read" });

      const res = await h.app.request("/introspect", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Authorization: `Basic ${Buffer.from("demo-agent-client:demo-client-secret-change-me").toString("base64")}`
        },
        body: new URLSearchParams({ token: root.refreshToken }).toString()
      });
      const body = await res.json();
      expect(body).toEqual({ active: false });
      expect(JSON.stringify(body)).not.toContain(root.refreshToken);
    });

    it("a refresh token never appears in any /token error body", async () => {
      const h = await harness();
      const root = await mintRootToken(h.app, { scope: "filings:read" });

      const widen = await refreshToken(h.app, root.refreshToken, { scope: "filings:read quotes:read" });
      expect(JSON.stringify(await widen.json())).not.toContain(root.refreshToken);

      const garbage = await refreshToken(h.app, "not-a-real-refresh-token");
      expect(JSON.stringify(await garbage.json())).not.toContain("not-a-real-refresh-token");
    });

    it("a thrown error while handling a refresh request never embeds the refresh token value", async () => {
      const h = await harness();
      const root = await mintRootToken(h.app, { scope: "filings:read" });

      const failingStore: TokenStore = new Proxy(h.store, {
        get(target, prop, receiver) {
          if (prop === "getRefreshTokenRecord") {
            return () => {
              throw new Error("simulated store failure");
            };
          }
          return Reflect.get(target, prop, receiver);
        }
      });

      let caught: unknown;
      try {
        await failingStore.getRefreshTokenRecord(root.refreshToken);
      } catch (error) {
        caught = error;
      }
      expect(caught).toBeInstanceOf(Error);
      expect((caught as Error).message).not.toContain(root.refreshToken);
      expect(String(caught)).not.toContain(root.refreshToken);
    });
  });
}
