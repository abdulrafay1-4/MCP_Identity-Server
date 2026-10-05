import type { Hono } from "hono";
import type { CimdClient } from "../../src/cimd.js";
import { loadDemoClient, type DemoClient } from "../../src/config/client.js";
import type { Config } from "../../src/config/env.js";
import { createApp } from "../../src/http/app.js";
import type { AppEnv } from "../../src/http/requestLogging.js";
import { loadOrGenerateKeys, type KeyRing } from "../../src/keys.js";
import { createLogger, silentSink, type Logger } from "../../src/log.js";
import type { TokenStore } from "../../src/store/types.js";

export const ISSUER = "https://auth.example.com";

export const CLIENT: DemoClient = loadDemoClient({
  CLIENT_ID: "demo-agent-client",
  CLIENT_SECRET: "demo-client-secret-change-me",
  CLIENT_REDIRECT_URI: "https://agent.example.com/callback",
  CLIENT_AUDIENCE: "https://mcp.example.com/mcp"
});

export const BASE_NOW = new Date("2026-01-01T00:00:00Z");

export function basicAuthHeader(clientId: string, clientSecret: string): string {
  return `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString("base64")}`;
}

export interface DelegationHarness {
  app: Hono<AppEnv>;
  store: TokenStore;
  keys: KeyRing;
  config: Config;
  setNow: (date: Date) => void;
}

export interface DelegationHarnessOptions {
  initialNow?: Date;
  tokenTtlSeconds?: number;
  maxDelegationDepth?: number;
  refreshTokenTtlSeconds?: number;
  refreshReuseGraceSeconds?: number;
  rateLimitMax?: number;
  rateLimitWindowSeconds?: number;
  logger?: Logger;
  cimdClient?: CimdClient;
}

export async function buildDelegationHarness(
  buildStore: (now: () => Date) => TokenStore,
  options: DelegationHarnessOptions = {}
): Promise<DelegationHarness> {
  let current = options.initialNow ?? BASE_NOW;
  const now = (): Date => current;
  const keys = await loadOrGenerateKeys();
  const store = buildStore(now);
  const config: Config = {
    issuer: ISSUER,
    port: 0,
    tokenTtlSeconds: options.tokenTtlSeconds ?? 300,
    pruneIntervalMs: 60_000,
    maxDelegationDepth: options.maxDelegationDepth ?? 5,
    refreshTokenTtlSeconds: options.refreshTokenTtlSeconds ?? 2_592_000,
    refreshReuseGraceSeconds: options.refreshReuseGraceSeconds ?? 10,
    keyRingPath: ".data/test-keys.json",
    rateLimitMax: options.rateLimitMax ?? 1000,
    rateLimitWindowSeconds: options.rateLimitWindowSeconds ?? 60,
    logLevel: "info"
  };
  const logger = options.logger ?? createLogger({ sink: silentSink, now });
  const app = createApp({ config, keys, store, client: CLIENT, now, logger, cimdClient: options.cimdClient });
  return { app, store, keys, config, setNow: (date) => (current = date) };
}
