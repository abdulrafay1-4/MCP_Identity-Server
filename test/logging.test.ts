import { describe, expect, it } from "vitest";
import { createLogger } from "../src/log.js";
import { MemoryTokenStore } from "../src/store/memory.js";
import { CLIENT, buildDelegationHarness } from "./support/delegationHarness.js";
import {
  exchangeToken,
  introspectActive,
  mintRootToken,
  postToken,
  refreshToken,
  revokeToken
} from "./support/tokenFlow.js";

describe("structured logging: no secrets ever", () => {
  it("never emits a token, code, refresh token, or client secret across a full HTTP flow", async () => {
    const lines: string[] = [];
    const capturingLogger = createLogger({ sink: (line) => lines.push(line) });

    const h = await buildDelegationHarness((now) => new MemoryTokenStore({ now }), {
      logger: capturingLogger,
      rateLimitMax: 1000,
      rateLimitWindowSeconds: 60
    });

    const root = await mintRootToken(h.app, { scope: "filings:read quotes:read" });

    expect(await introspectActive(h.app, root.accessToken)).toBe(true);

    const exchangeRes = await exchangeToken(h.app, root.accessToken, { scope: "filings:read", agentId: "child" });
    expect(exchangeRes.status).toBe(200);
    const exchangeBody = (await exchangeRes.json()) as { access_token: string };
    const childAccessToken = exchangeBody.access_token;

    const refreshRes = await refreshToken(h.app, root.refreshToken);
    expect(refreshRes.status).toBe(200);
    const refreshBody = (await refreshRes.json()) as { access_token: string; refresh_token: string };

    const badCreds = await h.app.request("/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${Buffer.from(`${CLIENT.clientId}:wrong-secret-guess`).toString("base64")}`
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: "not-a-real-code",
        redirect_uri: CLIENT.redirectUri,
        code_verifier: "irrelevant-verifier"
      }).toString()
    });
    expect(badCreds.status).toBe(401);

    await postToken(h.app, { grant_type: "authorization_code", code: "totally-bogus-code" });
    expect(await introspectActive(h.app, "not.a.valid.jwt.at.all")).toBe(false);

    const revokeRes = await revokeToken(h.app, root.accessToken);
    expect(revokeRes.status).toBe(200);

    expect(lines.length).toBeGreaterThan(0);
    const haystack = lines.join("\n");

    const wrongCredsHeaderValue = Buffer.from(`${CLIENT.clientId}:wrong-secret-guess`).toString("base64");
    const realCredsHeaderValue = Buffer.from(`${CLIENT.clientId}:${CLIENT.clientSecret}`).toString("base64");

    const mustNeverAppear = [
      CLIENT.clientSecret,
      "wrong-secret-guess",
      root.accessToken,
      root.refreshToken,
      childAccessToken,
      refreshBody.access_token,
      refreshBody.refresh_token,
      "not-a-real-code",
      "totally-bogus-code",
      "irrelevant-verifier",
      wrongCredsHeaderValue,
      realCredsHeaderValue
    ];
    for (const secret of mustNeverAppear) {
      expect(haystack.includes(secret)).toBe(false);
    }

    for (const line of lines) {
      const parsed = JSON.parse(line) as Record<string, unknown>;
      expect(typeof parsed.time).toBe("string");
      expect(["debug", "info", "warn", "error"]).toContain(parsed.level);
      expect(typeof parsed.event).toBe("string");
    }

    const httpRequestLines = lines.map((l) => JSON.parse(l) as Record<string, unknown>).filter((l) => l.event === "http_request");
    expect(httpRequestLines.length).toBeGreaterThan(0);
    for (const line of httpRequestLines) {
      expect(typeof line.requestId).toBe("string");
      expect((line.requestId as string).length).toBeGreaterThan(0);
    }
  });

  it("respects an incoming X-Request-Id header instead of always generating one, and echoes it back", async () => {
    const lines: string[] = [];
    const capturingLogger = createLogger({ sink: (line) => lines.push(line) });
    const h = await buildDelegationHarness((now) => new MemoryTokenStore({ now }), { logger: capturingLogger });

    const incomingId = "caller-supplied-correlation-id-123";
    const res = await h.app.request("/healthz", { headers: { "X-Request-Id": incomingId } });
    expect(res.status).toBe(200);
    expect(res.headers.get("X-Request-Id")).toBe(incomingId);

    const httpRequestLine = lines.map((l) => JSON.parse(l) as Record<string, unknown>).find((l) => l.event === "http_request");
    expect(httpRequestLine?.requestId).toBe(incomingId);
  });

  it("drops lines below the configured level", () => {
    const lines: string[] = [];
    const logger = createLogger({ level: "warn", sink: (line) => lines.push(line) });
    logger.debug("should_not_appear", {});
    logger.info("also_should_not_appear", {});
    logger.warn("should_appear", {});
    logger.error("should_also_appear", {});
    expect(lines).toHaveLength(2);
    expect(JSON.parse(lines[0] ?? "{}").event).toBe("should_appear");
    expect(JSON.parse(lines[1] ?? "{}").event).toBe("should_also_appear");
  });
});
