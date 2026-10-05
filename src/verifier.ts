import { decodeProtectedHeader, importJWK, jwtVerify } from "jose";
import type { JWK, KeyLike } from "jose";
import { OAuthError, OAuthErrorCode } from "@modelcontextprotocol/server";
import type { AuthInfo, OAuthTokenVerifier } from "@modelcontextprotocol/server";
import { isHttpsOrLoopbackUrl } from "./config/loopback.js";

export type FetchLike = (input: string | URL, init?: RequestInit) => Promise<Response>;

export type McpScope = "filings:read" | "quotes:read" | "companies:read" | "sources:read";

/** Example mapping for a filings and quotes server. Replace the tool names with your own. */
export const TOOL_SCOPES: Record<string, McpScope> = {
  get_filing: "filings:read",
  search_filings: "filings:read",
  get_quote: "quotes:read",
  get_company: "companies:read",
  list_sources: "sources:read"
};

export function requiredScopeForTool(tool: string): McpScope | undefined {
  return TOOL_SCOPES[tool];
}

export interface McpTokenVerifierOptions {
  /** Must be https, or http on localhost, 127.0.0.1 or [::1]. */
  issuer: string;
  /** The `aud` this server expects (RFC 8707). */
  resource: string;
  /** Credentials for /introspect. */
  clientId: string;
  clientSecret: string;
  jwksUri?: string;
  introspectionEndpoint?: string;
  fetch?: FetchLike;
  now?: () => Date;
  /** Default 60 s. 0 disables caching. */
  jwksCacheTtlMs?: number;
  /** An unknown kid triggers at most one JWKS refetch per interval. Default 60 s. */
  jwksMinRefetchIntervalMs?: number;
}

interface VerifiedClaims {
  sub: string;
  aud: string;
  scope: string;
  jti: string;
  iat: number;
  exp: number;
  act?: { sub: string };
}

interface IntrospectionResponse {
  active: boolean;
  client_id?: string;
}

interface CachedJwks {
  fetchedAtMs: number;
  keys: JWK[];
}

const DEFAULT_JWKS_CACHE_TTL_MS = 60_000;
const DEFAULT_JWKS_MIN_REFETCH_INTERVAL_MS = 60_000;

/**
 * Every failure gives the same error, so a caller can't tell revoked from expired from
 * wrong audience.
 */
function invalidToken(): OAuthError {
  return new OAuthError(OAuthErrorCode.InvalidToken, "The access token is invalid, expired, or has been revoked.");
}

/**
 * Checks signature, issuer, audience and expiry locally against the published JWKS, then
 * asks /introspect. The second step is what lets a revocation reach the resource server.
 */
export class McpTokenVerifier implements OAuthTokenVerifier {
  private readonly issuer: string;
  private readonly resource: string;
  private readonly clientId: string;
  private readonly clientSecret: string;
  private readonly jwksUri: string;
  private readonly introspectionEndpoint: string;
  private readonly fetchImpl: FetchLike;
  private readonly now: () => Date;
  private readonly jwksCacheTtlMs: number;
  private readonly jwksMinRefetchIntervalMs: number;
  private cachedJwks: CachedJwks | undefined;
  private lastKidRefetchMs = Number.NEGATIVE_INFINITY;

  constructor(options: McpTokenVerifierOptions) {
    this.issuer = options.issuer;
    this.resource = options.resource;
    this.clientId = options.clientId;
    this.clientSecret = options.clientSecret;
    this.jwksUri = options.jwksUri ?? `${options.issuer}/jwks.json`;
    this.introspectionEndpoint = options.introspectionEndpoint ?? `${options.issuer}/introspect`;
    this.fetchImpl = options.fetch ?? ((input, init) => fetch(input, init));
    this.now = options.now ?? ((): Date => new Date());
    this.jwksCacheTtlMs = options.jwksCacheTtlMs ?? DEFAULT_JWKS_CACHE_TTL_MS;
    this.jwksMinRefetchIntervalMs = options.jwksMinRefetchIntervalMs ?? DEFAULT_JWKS_MIN_REFETCH_INTERVAL_MS;

    for (const [name, url] of [
      ["issuer", options.issuer],
      ["jwksUri", this.jwksUri],
      ["introspectionEndpoint", this.introspectionEndpoint]
    ] as const) {
      if (!isHttpsOrLoopbackUrl(url)) {
        throw new Error(`Invalid verifier option ${name}: must be an https URL (http is allowed only for localhost, 127.0.0.1 or [::1])`);
      }
    }
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    let claims: VerifiedClaims;
    try {
      claims = await this.verifyJwt(token);
    } catch {
      throw invalidToken();
    }

    let introspection: IntrospectionResponse;
    try {
      introspection = await this.introspect(token);
    } catch {
      throw invalidToken();
    }
    if (!introspection.active) {
      throw invalidToken();
    }

    const scopes = claims.scope.split(" ").filter((s) => s.length > 0);

    return {
      token,
      clientId: introspection.client_id ?? this.clientId,
      scopes,
      expiresAt: claims.exp, // requireBearerAuth rejects tokens without it
      resource: new URL(claims.aud),
      extra: {
        sub: claims.sub,
        jti: claims.jti,
        ...(claims.act ? { act: claims.act } : {})
      }
    };
  }

  private async verifyJwt(token: string): Promise<VerifiedClaims> {
    let kid: string | undefined;
    try {
      kid = decodeProtectedHeader(token).kid;
    } catch {
      throw new Error("malformed token");
    }
    if (typeof kid !== "string") {
      throw new Error("missing kid");
    }

    const key = await this.resolveKey(kid);

    const { payload } = await jwtVerify(token, key, {
      issuer: this.issuer,
      audience: this.resource,
      currentDate: this.now(),
      requiredClaims: ["sub", "aud", "jti", "iat", "exp", "scope"]
    });

    const { sub, aud, jti, iat, exp, scope, act } = payload;
    if (
      typeof sub !== "string" ||
      typeof aud !== "string" ||
      typeof jti !== "string" ||
      typeof iat !== "number" ||
      typeof exp !== "number" ||
      typeof scope !== "string"
    ) {
      throw new Error("malformed claims");
    }

    if (act === undefined) {
      return { sub, aud, jti, iat, exp, scope };
    }
    if (typeof act !== "object" || act === null || typeof (act as Record<string, unknown>).sub !== "string") {
      throw new Error("malformed act claim");
    }
    return { sub, aud, jti, iat, exp, scope, act: { sub: (act as Record<string, unknown>).sub as string } };
  }

  private async resolveKey(kid: string): Promise<KeyLike | Uint8Array> {
    let keys = await this.getJwks();
    let jwk = keys.find((k) => k.kid === kid);
    if (!jwk && this.claimKidRefetch()) {
      keys = await this.getJwks(true);
      jwk = keys.find((k) => k.kid === kid);
    }
    if (!jwk || typeof jwk.alg !== "string") {
      throw new Error("unknown kid");
    }
    return importJWK(jwk, jwk.alg);
  }

  private claimKidRefetch(): boolean {
    const nowMs = this.now().getTime();
    if (nowMs - this.lastKidRefetchMs < this.jwksMinRefetchIntervalMs) {
      return false;
    }
    this.lastKidRefetchMs = nowMs;
    return true;
  }

  private async getJwks(forceRefresh = false): Promise<JWK[]> {
    const nowMs = this.now().getTime();
    if (!forceRefresh && this.cachedJwks && nowMs - this.cachedJwks.fetchedAtMs < this.jwksCacheTtlMs) {
      return this.cachedJwks.keys;
    }
    const res = await this.fetchImpl(this.jwksUri);
    if (!res.ok) {
      throw new Error("jwks fetch failed");
    }
    const body = (await res.json()) as { keys?: JWK[] };
    const keys = Array.isArray(body.keys) ? body.keys : [];
    this.cachedJwks = { fetchedAtMs: nowMs, keys };
    return keys;
  }

  private async introspect(token: string): Promise<IntrospectionResponse> {
    const credentials = Buffer.from(`${this.clientId}:${this.clientSecret}`).toString("base64");
    const res = await this.fetchImpl(this.introspectionEndpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${credentials}`
      },
      body: new URLSearchParams({ token }).toString()
    });
    if (!res.ok) {
      throw new Error("introspection request failed");
    }
    return (await res.json()) as IntrospectionResponse;
  }
}
