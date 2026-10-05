import { z } from "zod";
import { isHttpsOrLoopbackUrl } from "./loopback.js";

export const DEFAULT_ISSUER = "http://localhost:3000";

export interface Config {
  issuer: string;
  port: number;
  tokenTtlSeconds: number;
  signingKey?: string;
  databaseUrl?: string;
  pruneIntervalMs: number;
  maxDelegationDepth: number;
  refreshTokenTtlSeconds: number;
  /**
   * A rotated refresh token may be presented once more within this window (a client retrying
   * after a lost response). Any later replay revokes the whole family.
   */
  refreshReuseGraceSeconds: number;
  keyRingPath: string;
  rateLimitMax: number;
  rateLimitWindowSeconds: number;
  logLevel: "debug" | "info" | "warn" | "error";
}

const envSchema = z.object({
  ISSUER: z
    .string({ required_error: "ISSUER is required" })
    .url({ message: "ISSUER must be a valid absolute URL" })
    .refine(isHttpsOrLoopbackUrl, {
      message: "ISSUER must be an https URL (http is allowed only for localhost, 127.0.0.1 or [::1])"
    })
    .default(DEFAULT_ISSUER),
  PORT: z.coerce
    .number({ invalid_type_error: "PORT must be a number" })
    .int("PORT must be an integer")
    .min(1, "PORT must be between 1 and 65535")
    .max(65535, "PORT must be between 1 and 65535")
    .default(3000),
  TOKEN_TTL_SECONDS: z.coerce
    .number({ invalid_type_error: "TOKEN_TTL_SECONDS must be a number" })
    .int("TOKEN_TTL_SECONDS must be an integer")
    .positive("TOKEN_TTL_SECONDS must be a positive number")
    .default(300),
  SIGNING_KEY: z.string().optional(),
  DATABASE_URL: z
    .string()
    .url({ message: "DATABASE_URL must be a valid connection string" })
    .optional(),
  PRUNE_INTERVAL_MS: z.coerce
    .number({ invalid_type_error: "PRUNE_INTERVAL_MS must be a number" })
    .int("PRUNE_INTERVAL_MS must be an integer")
    .positive("PRUNE_INTERVAL_MS must be a positive number")
    .default(60_000),
  MAX_DELEGATION_DEPTH: z.coerce
    .number({ invalid_type_error: "MAX_DELEGATION_DEPTH must be a number" })
    .int("MAX_DELEGATION_DEPTH must be an integer")
    .positive("MAX_DELEGATION_DEPTH must be a positive number")
    .default(5),
  REFRESH_TOKEN_TTL_SECONDS: z.coerce
    .number({ invalid_type_error: "REFRESH_TOKEN_TTL_SECONDS must be a number" })
    .int("REFRESH_TOKEN_TTL_SECONDS must be an integer")
    .positive("REFRESH_TOKEN_TTL_SECONDS must be a positive number")
    .default(2_592_000),
  REFRESH_REUSE_GRACE_SECONDS: z.coerce
    .number({ invalid_type_error: "REFRESH_REUSE_GRACE_SECONDS must be a number" })
    .int("REFRESH_REUSE_GRACE_SECONDS must be an integer")
    .nonnegative("REFRESH_REUSE_GRACE_SECONDS must not be negative")
    .default(10),
  KEY_RING_PATH: z.string({ invalid_type_error: "KEY_RING_PATH must be a string" }).min(1, "KEY_RING_PATH must not be empty").default(".data/keys.json"),
  RATE_LIMIT_MAX: z.coerce
    .number({ invalid_type_error: "RATE_LIMIT_MAX must be a number" })
    .int("RATE_LIMIT_MAX must be an integer")
    .positive("RATE_LIMIT_MAX must be a positive number")
    .default(60),
  RATE_LIMIT_WINDOW_SECONDS: z.coerce
    .number({ invalid_type_error: "RATE_LIMIT_WINDOW_SECONDS must be a number" })
    .int("RATE_LIMIT_WINDOW_SECONDS must be an integer")
    .positive("RATE_LIMIT_WINDOW_SECONDS must be a positive number")
    .default(60),
  LOG_LEVEL: z
    .enum(["debug", "info", "warn", "error"], {
      errorMap: () => ({ message: "LOG_LEVEL must be one of debug, info, warn, error" })
    })
    .default("info")
});

export type EnvSource = Record<string, string | undefined>;

export function loadConfig(source: EnvSource = process.env): Config {
  const result = envSchema.safeParse(source);

  if (!result.success) {
    const issue = result.error.issues[0];
    const field = issue?.path.join(".") || "environment";
    const message = issue?.message ?? "invalid configuration";
    throw new Error(`Invalid environment variable ${field}: ${message}`);
  }

  const env = result.data;

  return {
    issuer: env.ISSUER,
    port: env.PORT,
    tokenTtlSeconds: env.TOKEN_TTL_SECONDS,
    signingKey: env.SIGNING_KEY,
    databaseUrl: env.DATABASE_URL,
    pruneIntervalMs: env.PRUNE_INTERVAL_MS,
    maxDelegationDepth: env.MAX_DELEGATION_DEPTH,
    refreshTokenTtlSeconds: env.REFRESH_TOKEN_TTL_SECONDS,
    refreshReuseGraceSeconds: env.REFRESH_REUSE_GRACE_SECONDS,
    keyRingPath: env.KEY_RING_PATH,
    rateLimitMax: env.RATE_LIMIT_MAX,
    rateLimitWindowSeconds: env.RATE_LIMIT_WINDOW_SECONDS,
    logLevel: env.LOG_LEVEL
  };
}
