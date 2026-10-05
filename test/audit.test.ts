import { describe, expect, it } from "vitest";
import { MemoryTokenStore } from "../src/store/memory.js";
import { BASE_NOW, buildDelegationHarness } from "./support/delegationHarness.js";
import { exchangeToken, introspectActive, jtiOf, mintRootToken, refreshToken, revokeToken } from "./support/tokenFlow.js";

describe("audit log completeness", () => {
  const LONG_TTL_SECONDS = 3600;

  it('records "issue" for a root grant', async () => {
    const h = await buildDelegationHarness((now) => new MemoryTokenStore({ now }));
    const root = await mintRootToken(h.app);
    const jti = jtiOf(root.accessToken);

    const entries = await h.store.getAuditLog(jti);
    const issueEntry = entries.find((e) => e.eventType === "issue");
    expect(issueEntry).toBeDefined();
    expect(issueEntry?.subject).toBe(jti);
    expect(JSON.stringify(entries)).not.toContain(root.accessToken);
    expect(JSON.stringify(entries)).not.toContain(root.refreshToken);
  });

  it('records "exchange" for a delegation (token-exchange)', async () => {
    const h = await buildDelegationHarness((now) => new MemoryTokenStore({ now }));
    const root = await mintRootToken(h.app, { scope: "filings:read" });
    const rootJti = jtiOf(root.accessToken);

    const res = await exchangeToken(h.app, root.accessToken, { scope: "filings:read", agentId: "child" });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { access_token: string };
    const childJti = jtiOf(body.access_token);

    const entries = await h.store.getAuditLog(childJti);
    const exchangeEntry = entries.find((e) => e.eventType === "exchange");
    expect(exchangeEntry).toBeDefined();
    expect(exchangeEntry?.subject).toBe(childJti);
    expect(exchangeEntry?.metadata).toMatchObject({ parent_jti: rootJti, depth: 1 });
    expect(JSON.stringify(entries)).not.toContain(root.accessToken);
    expect(JSON.stringify(entries)).not.toContain(body.access_token);
  });

  it('records "refresh" for a successful rotation', async () => {
    const h = await buildDelegationHarness((now) => new MemoryTokenStore({ now }), { tokenTtlSeconds: LONG_TTL_SECONDS });
    const root = await mintRootToken(h.app);

    const res = await refreshToken(h.app, root.refreshToken);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { access_token: string };
    const newJti = jtiOf(body.access_token);

    const entries = await h.store.getAuditLog(newJti);
    const refreshEntry = entries.find((e) => e.eventType === "refresh");
    expect(refreshEntry).toBeDefined();
    expect(refreshEntry?.metadata).toMatchObject({ graced: false });
    expect(JSON.stringify(entries)).not.toContain(root.refreshToken);
  });

  it('records "reuse_detected" for a replayed refresh token', async () => {
    const h = await buildDelegationHarness((now) => new MemoryTokenStore({ now }), {
      tokenTtlSeconds: LONG_TTL_SECONDS,
      refreshReuseGraceSeconds: 0
    });
    const root = await mintRootToken(h.app);
    const rootJti = jtiOf(root.accessToken);

    const first = await refreshToken(h.app, root.refreshToken);
    expect(first.status).toBe(200);
    h.setNow(new Date(BASE_NOW.getTime() + 1000));
    const replay = await refreshToken(h.app, root.refreshToken);
    expect(replay.status).toBe(400);

    const entries = await h.store.getAuditLog(rootJti);
    const reuseEntry = entries.find((e) => e.eventType === "reuse_detected");
    expect(reuseEntry).toBeDefined();
    expect(JSON.stringify(entries)).not.toContain(root.refreshToken);
    expect(await introspectActive(h.app, root.accessToken)).toBe(false);
  });

  it('records "revoke" for an explicit /revoke call', async () => {
    const h = await buildDelegationHarness((now) => new MemoryTokenStore({ now }));
    const root = await mintRootToken(h.app);
    const jti = jtiOf(root.accessToken);

    const res = await revokeToken(h.app, root.accessToken);
    expect(res.status).toBe(200);

    const entries = await h.store.getAuditLog(jti);
    const revokeEntry = entries.find((e) => e.eventType === "revoke");
    expect(revokeEntry).toBeDefined();
    expect(JSON.stringify(entries)).not.toContain(root.accessToken);
  });
});
