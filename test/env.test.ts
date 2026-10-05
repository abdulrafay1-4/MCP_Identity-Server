import { describe, expect, it } from "vitest";
import { loadDemoClient } from "../src/config/client.js";
import { loadConfig } from "../src/config/env.js";

const baseEnv = {
  ISSUER: "https://auth.example.com",
  PORT: "4000",
  TOKEN_TTL_SECONDS: "300"
};

describe("loadConfig", () => {
  it("returns a well-typed config from valid env", () => {
    const config = loadConfig(baseEnv);
    expect(config).toEqual({
      issuer: "https://auth.example.com",
      port: 4000,
      tokenTtlSeconds: 300,
      signingKey: undefined,
      databaseUrl: undefined,
      pruneIntervalMs: 60_000,
      maxDelegationDepth: 5,
      refreshTokenTtlSeconds: 2_592_000,
      refreshReuseGraceSeconds: 10,
      keyRingPath: ".data/keys.json",
      rateLimitMax: 60,
      rateLimitWindowSeconds: 60,
      logLevel: "info"
    });
  });

  it("passes through SIGNING_KEY when present", () => {
    const config = loadConfig({ ...baseEnv, SIGNING_KEY: "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----" });
    expect(config.signingKey).toContain("BEGIN PRIVATE KEY");
  });

  it("applies defaults when optional vars are absent", () => {
    const config = loadConfig({ ISSUER: "https://auth.example.com" });
    expect(config.port).toBe(3000);
    expect(config.tokenTtlSeconds).toBe(300);
    expect(config.databaseUrl).toBeUndefined();
    expect(config.pruneIntervalMs).toBe(60_000);
    expect(config.maxDelegationDepth).toBe(5);
    expect(config.refreshTokenTtlSeconds).toBe(2_592_000);
    expect(config.refreshReuseGraceSeconds).toBe(10);
  });

  it("passes through DATABASE_URL when present", () => {
    const config = loadConfig({ ...baseEnv, DATABASE_URL: "postgres://user:pass@host:5432/db" });
    expect(config.databaseUrl).toBe("postgres://user:pass@host:5432/db");
  });

  it("throws an error naming DATABASE_URL when it is not a valid URL", () => {
    expect(() => loadConfig({ ...baseEnv, DATABASE_URL: "not-a-url" })).toThrowError(/DATABASE_URL/);
  });

  it("passes through a custom PRUNE_INTERVAL_MS", () => {
    const config = loadConfig({ ...baseEnv, PRUNE_INTERVAL_MS: "5000" });
    expect(config.pruneIntervalMs).toBe(5000);
  });

  it("throws an error naming PRUNE_INTERVAL_MS when it is zero or negative", () => {
    expect(() => loadConfig({ ...baseEnv, PRUNE_INTERVAL_MS: "0" })).toThrowError(/PRUNE_INTERVAL_MS/);
  });

  it("passes through a custom MAX_DELEGATION_DEPTH", () => {
    const config = loadConfig({ ...baseEnv, MAX_DELEGATION_DEPTH: "3" });
    expect(config.maxDelegationDepth).toBe(3);
  });

  it("throws an error naming MAX_DELEGATION_DEPTH when it is zero or negative", () => {
    expect(() => loadConfig({ ...baseEnv, MAX_DELEGATION_DEPTH: "0" })).toThrowError(/MAX_DELEGATION_DEPTH/);
  });

  it("passes through a custom REFRESH_TOKEN_TTL_SECONDS", () => {
    const config = loadConfig({ ...baseEnv, REFRESH_TOKEN_TTL_SECONDS: "3600" });
    expect(config.refreshTokenTtlSeconds).toBe(3600);
  });

  it("throws an error naming REFRESH_TOKEN_TTL_SECONDS when it is zero or negative", () => {
    expect(() => loadConfig({ ...baseEnv, REFRESH_TOKEN_TTL_SECONDS: "0" })).toThrowError(/REFRESH_TOKEN_TTL_SECONDS/);
  });

  it("passes through a custom REFRESH_REUSE_GRACE_SECONDS, including zero", () => {
    const config = loadConfig({ ...baseEnv, REFRESH_REUSE_GRACE_SECONDS: "30" });
    expect(config.refreshReuseGraceSeconds).toBe(30);
    expect(loadConfig({ ...baseEnv, REFRESH_REUSE_GRACE_SECONDS: "0" }).refreshReuseGraceSeconds).toBe(0);
  });

  it("throws an error naming REFRESH_REUSE_GRACE_SECONDS when it is negative", () => {
    expect(() => loadConfig({ ...baseEnv, REFRESH_REUSE_GRACE_SECONDS: "-1" })).toThrowError(/REFRESH_REUSE_GRACE_SECONDS/);
  });

  it("defaults KEY_RING_PATH and passes through a custom value", () => {
    expect(loadConfig(baseEnv).keyRingPath).toBe(".data/keys.json");
    expect(loadConfig({ ...baseEnv, KEY_RING_PATH: "/var/lib/mcp-identity/keys.json" }).keyRingPath).toBe(
      "/var/lib/mcp-identity/keys.json"
    );
  });

  it("throws an error naming KEY_RING_PATH when it is empty", () => {
    expect(() => loadConfig({ ...baseEnv, KEY_RING_PATH: "" })).toThrowError(/KEY_RING_PATH/);
  });

  it("defaults RATE_LIMIT_MAX/RATE_LIMIT_WINDOW_SECONDS and passes through custom values", () => {
    const defaults = loadConfig(baseEnv);
    expect(defaults.rateLimitMax).toBe(60);
    expect(defaults.rateLimitWindowSeconds).toBe(60);

    const custom = loadConfig({ ...baseEnv, RATE_LIMIT_MAX: "5", RATE_LIMIT_WINDOW_SECONDS: "10" });
    expect(custom.rateLimitMax).toBe(5);
    expect(custom.rateLimitWindowSeconds).toBe(10);
  });

  it("throws an error naming RATE_LIMIT_MAX when it is zero or negative", () => {
    expect(() => loadConfig({ ...baseEnv, RATE_LIMIT_MAX: "0" })).toThrowError(/RATE_LIMIT_MAX/);
    expect(() => loadConfig({ ...baseEnv, RATE_LIMIT_MAX: "-1" })).toThrowError(/RATE_LIMIT_MAX/);
  });

  it("throws an error naming RATE_LIMIT_WINDOW_SECONDS when it is zero or negative", () => {
    expect(() => loadConfig({ ...baseEnv, RATE_LIMIT_WINDOW_SECONDS: "0" })).toThrowError(/RATE_LIMIT_WINDOW_SECONDS/);
  });

  it("defaults LOG_LEVEL to info and passes through a valid custom value", () => {
    expect(loadConfig(baseEnv).logLevel).toBe("info");
    expect(loadConfig({ ...baseEnv, LOG_LEVEL: "debug" }).logLevel).toBe("debug");
    expect(loadConfig({ ...baseEnv, LOG_LEVEL: "error" }).logLevel).toBe("error");
  });

  it("throws an error naming LOG_LEVEL when it is not a recognized level", () => {
    expect(() => loadConfig({ ...baseEnv, LOG_LEVEL: "verbose" })).toThrowError(/LOG_LEVEL/);
  });

  it("throws an error naming TOKEN_TTL_SECONDS when it is not a valid number", () => {
    expect(() => loadConfig({ ...baseEnv, TOKEN_TTL_SECONDS: "not-a-number" })).toThrowError(/TOKEN_TTL_SECONDS/);
  });

  it("throws an error naming TOKEN_TTL_SECONDS when it is zero or negative", () => {
    expect(() => loadConfig({ ...baseEnv, TOKEN_TTL_SECONDS: "0" })).toThrowError(/TOKEN_TTL_SECONDS/);
    expect(() => loadConfig({ ...baseEnv, TOKEN_TTL_SECONDS: "-5" })).toThrowError(/TOKEN_TTL_SECONDS/);
  });

  it("throws an error naming ISSUER when it is not a valid URL", () => {
    expect(() => loadConfig({ ...baseEnv, ISSUER: "not-a-url" })).toThrowError(/ISSUER/);
  });

  it("throws an error naming PORT when it is out of range", () => {
    expect(() => loadConfig({ ...baseEnv, PORT: "99999" })).toThrowError(/PORT/);
  });

  it("is pure with respect to its argument (does not read real process.env)", () => {
    const originalIssuer = process.env.ISSUER;
    process.env.ISSUER = "https://should-not-be-used.example.com";
    try {
      const config = loadConfig(baseEnv);
      expect(config.issuer).toBe("https://auth.example.com");
    } finally {
      if (originalIssuer === undefined) {
        delete process.env.ISSUER;
      } else {
        process.env.ISSUER = originalIssuer;
      }
    }
  });
});

describe("loadConfig ISSUER transport", () => {
  it.each(["http://localhost:3000", "http://127.0.0.1:3000", "http://[::1]:3000", "https://localhost:3000"])(
    "accepts the loopback or https issuer %s",
    (issuer) => {
      expect(loadConfig({ ISSUER: issuer }).issuer).toBe(issuer);
    }
  );

  it("accepts an unset ISSUER, which defaults to a loopback http URL", () => {
    expect(loadConfig({}).issuer).toBe("http://localhost:3000");
  });

  it.each([
    "http://auth.example.com",
    "http://localhost.evil.example",
    "http://127.0.0.1.evil.example",
    "http://localhost@evil.example"
  ])("throws an error naming ISSUER for the non-https, non-loopback issuer %s", (issuer) => {
    expect(() => loadConfig({ ISSUER: issuer })).toThrowError(/ISSUER/);
  });
});

describe("loadDemoClient CLIENT_SECRET", () => {
  const PLACEHOLDER = "demo-client-secret-change-me";
  const REAL_SECRET = "a-long-random-secret-value-for-tests";

  it.each([undefined, "http://localhost:3000", "http://127.0.0.1:3000", "http://[::1]:3000"])(
    "loads the placeholder secret, set or unset, when ISSUER is %s",
    (issuer) => {
      expect(loadDemoClient({ ISSUER: issuer }).clientSecret).toBe(PLACEHOLDER);
      expect(loadDemoClient({ ISSUER: issuer, CLIENT_SECRET: PLACEHOLDER }).clientSecret).toBe(PLACEHOLDER);
    }
  );

  it("throws an error naming CLIENT_SECRET when it is unset and ISSUER is https and not loopback", () => {
    expect(() => loadDemoClient({ ISSUER: "https://auth.example.com" })).toThrowError(/CLIENT_SECRET/);
  });

  it("throws an error naming CLIENT_SECRET when it is the placeholder and ISSUER is https and not loopback", () => {
    expect(() => loadDemoClient({ ISSUER: "https://auth.example.com", CLIENT_SECRET: PLACEHOLDER })).toThrowError(
      /CLIENT_SECRET/
    );
  });

  it("throws an error naming CLIENT_SECRET when it is the placeholder and ISSUER is an https loopback URL", () => {
    expect(() => loadDemoClient({ ISSUER: "https://localhost:3000", CLIENT_SECRET: PLACEHOLDER })).toThrowError(
      /CLIENT_SECRET/
    );
  });

  it("throws an error naming CLIENT_SECRET when it is the placeholder and ISSUER is an http non-loopback URL", () => {
    expect(() => loadDemoClient({ ISSUER: "http://auth.example.com", CLIENT_SECRET: PLACEHOLDER })).toThrowError(
      /CLIENT_SECRET/
    );
  });

  it("loads a real secret with an https issuer", () => {
    expect(loadDemoClient({ ISSUER: "https://auth.example.com", CLIENT_SECRET: REAL_SECRET }).clientSecret).toBe(REAL_SECRET);
  });

  it("does not echo the placeholder value in the rejection message", () => {
    let message = "";
    try {
      loadDemoClient({ ISSUER: "https://auth.example.com", CLIENT_SECRET: PLACEHOLDER });
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).toContain("CLIENT_SECRET");
    expect(message).not.toContain(PLACEHOLDER);
  });
});
