import { randomBytes, randomUUID } from "node:crypto";
import { getConnInfo } from "@hono/node-server/conninfo";
import { Hono, type Context } from "hono";
import { bodyLimit } from "hono/body-limit";
import { HTTPException } from "hono/http-exception";
import { decodeJwt } from "jose";
import type { Config } from "../config/env.js";
import type { DemoClient } from "../config/client.js";
import { CimdClient, isCandidateCimdClientId, isRedirectUriAllowedForApplicationType, type CimdMetadata } from "../cimd.js";
import { sha256Hex } from "../hash.js";
import { isValidResourceUri } from "../resource.js";
import { getJwks, type KeyRing } from "../keys.js";
import { logger as defaultLogger, type Logger } from "../log.js";
import { computeS256Challenge, verifyPkce } from "../pkce.js";
import { RateLimiter } from "./rateLimit.js";
import { requestLogging, type AppEnv } from "./requestLogging.js";
import type { StoredTokenRecord, TokenRecord, TokenStore } from "../store/types.js";
import { issue, verify, type IssueParams, type TokenClaims } from "../tokens.js";
import { isValidClient, parseBasicAuth } from "./clientAuth.js";

const AUTH_CODE_TTL_SECONDS = 60;

const MAX_REQUEST_BODY_BYTES = 16 * 1024;

const TOKEN_EXCHANGE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS_TOKEN_TYPE_URN = "urn:ietf:params:oauth:token-type:access_token";

const REFRESH_TOKEN_GRANT_TYPE = "refresh_token";

/** Opaque and random, not a JWT. Only its SHA-256 hash is stored. */
function generateRefreshToken(): string {
  return randomBytes(32).toString("base64url");
}

export interface AppDeps {
  config: Config;
  keys: KeyRing;
  store: TokenStore;
  client: DemoClient;
  now?: () => Date;
  logger?: Logger;
  cimdClient?: CimdClient;
}

function formString(body: Record<string, string | File>, key: string): string | undefined {
  const value = body[key];
  return typeof value === "string" ? value : undefined;
}

function nowSeconds(deps: AppDeps): number {
  const now = (deps.now ?? (() => new Date()))();
  return Math.floor(now.getTime() / 1000);
}

function scopeSet(scope: string): Set<string> {
  return new Set(scope.split(" ").filter((s) => s.length > 0));
}

/** The requested scope must be a subset of the parent's. Omitted means unchanged. */
function narrowScope(parentScope: string, requestedScope: string | undefined): { ok: true; scope: string } | { ok: false; badScope: string } {
  const parentScopes = scopeSet(parentScope);
  const requestedScopes = requestedScope !== undefined ? scopeSet(requestedScope) : parentScopes;
  for (const scope of requestedScopes) {
    if (!parentScopes.has(scope)) {
      return { ok: false, badScope: scope };
    }
  }
  return { ok: true, scope: Array.from(requestedScopes).join(" ") };
}

/** X-Forwarded-For is ignored because any caller can set it. "unknown" in in-process tests. */
function remoteAddress(c: Context): string {
  try {
    return getConnInfo(c).remote.address ?? "unknown";
  } catch {
    return "unknown";
  }
}

export function createApp(deps: AppDeps): Hono<AppEnv> {
  const app = new Hono<AppEnv>();
  const log = deps.logger ?? defaultLogger;
  const cimdClient = deps.cimdClient ?? new CimdClient();

  app.onError((error, c) => {
    if (error instanceof HTTPException) return error.getResponse();
    log.error("unhandled_error", { requestId: c.get("requestId"), path: c.req.path, error: error.message });
    return c.json({ error: "server_error" }, 500);
  });

  // Signature, issuer, expiry and key status only: the audience belongs to the
  // resource server, and the stored record is what decides whether a token is live.
  const verifyOwnToken = (token: string): ReturnType<typeof verify> =>
    verify(token, { keys: deps.keys, issuer: deps.config.issuer, now: deps.now });

  // A token is live only if it verifies, has a stored record and is not revoked.
  // No record means inactive: after a restart of the in-memory store, nothing
  // issued earlier may be treated as live.
  const loadLiveToken = async (token: string): Promise<{ claims: TokenClaims; record: StoredTokenRecord } | undefined> => {
    let claims: TokenClaims;
    try {
      claims = await verifyOwnToken(token);
    } catch {
      return undefined;
    }
    const record = await deps.store.getRecord(claims.jti);
    if (!record || (await deps.store.isRevoked(claims.jti))) {
      return undefined;
    }
    return { claims, record };
  };

  // Signs an access token and records it, so it can be revoked and its delegation
  // chain walked. Throws rather than hand out a token the store knows nothing about.
  const issueRecorded = async (
    params: IssueParams,
    extra: Pick<TokenRecord, "parentJti" | "depth" | "familyId" | "clientId">
  ): Promise<{ accessToken: string; jti: string }> => {
    const accessToken = await issue(params, { keys: deps.keys, issuer: deps.config.issuer, now: deps.now });
    const claims = decodeJwt(accessToken);
    if (typeof claims.jti !== "string" || typeof claims.exp !== "number") {
      throw new Error("issued token is missing jti or exp");
    }
    await deps.store.record({
      jti: claims.jti,
      exp: claims.exp,
      sub: params.sub,
      aud: params.aud,
      scope: params.scope,
      issuedAt: typeof claims.iat === "number" ? claims.iat : undefined,
      ...extra
    });
    return { accessToken, jti: claims.jti };
  };

  const limiterOptions = {
    windowMs: deps.config.rateLimitWindowSeconds * 1000,
    max: deps.config.rateLimitMax,
    now: deps.now
  };
  // Separate limiters per endpoint, so a burst against one does not spend another's budget.
  // `clients` is keyed by an authenticated client_id; `addresses` by remote address.
  const endpointLimiters = (): { clients: RateLimiter; addresses: RateLimiter } => ({
    clients: new RateLimiter(limiterOptions),
    addresses: new RateLimiter(limiterOptions)
  });
  const tokenLimiters = endpointLimiters();
  const introspectLimiters = endpointLimiters();
  const revokeLimiters = endpointLimiters();
  const authorizeLimiter = new RateLimiter(limiterOptions);

  const tooManyRequests = (c: Context<AppEnv>, route: string, retryAfterSeconds: number): Response => {
    c.header("Retry-After", String(retryAfterSeconds));
    log.warn("rate_limited", { requestId: c.get("requestId"), route, retryAfterSeconds });
    return c.json({ error: "rate_limit_exceeded", error_description: "too many requests" }, 429);
  };

  // A request is charged to its client only once the credentials check out. Everything
  // else is charged to the caller's address, otherwise anyone could spend the real
  // client's budget just by naming it.
  const enforceRateLimit = (c: Context<AppEnv>, limiters: { clients: RateLimiter; addresses: RateLimiter }, route: string): Response | undefined => {
    const credentials = parseBasicAuth(c.req.header("Authorization"));
    const result =
      credentials && isValidClient(credentials, deps.client)
        ? limiters.clients.check(credentials.clientId)
        : limiters.addresses.check(remoteAddress(c));
    return result.allowed ? undefined : tooManyRequests(c, route, result.retryAfterSeconds);
  };

  app.use("*", requestLogging(log));

  app.post(
    "*",
    bodyLimit({
      maxSize: MAX_REQUEST_BODY_BYTES,
      onError: (c) => c.json({ error: "invalid_request", error_description: "request body too large" }, 413)
    })
  );

  // Liveness only. A database outage shouldn't get a healthy process restarted.
  app.get("/healthz", (c) => c.json({ status: "ok" }));

  app.get("/readyz", async (c) => {
    try {
      await deps.store.getRecord("__mcp-identity-readyz-probe__");
      return c.json({ status: "ok" });
    } catch {
      // Not the error itself: it can name a host or other connection detail.
      log.error("readyz_check_failed", { requestId: c.get("requestId") });
      return c.json({ status: "not_ready" }, 503);
    }
  });

  app.get("/.well-known/oauth-authorization-server", (c) => {
    const issuer = deps.config.issuer;
    return c.json({
      issuer,
      authorization_endpoint: `${issuer}/authorize`,
      token_endpoint: `${issuer}/token`,
      jwks_uri: `${issuer}/jwks.json`,
      introspection_endpoint: `${issuer}/introspect`,
      revocation_endpoint: `${issuer}/revoke`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", REFRESH_TOKEN_GRANT_TYPE, TOKEN_EXCHANGE_GRANT_TYPE],
      code_challenge_methods_supported: ["S256"],
      scopes_supported: ["filings:read", "quotes:read", "companies:read", "sources:read"],
      authorization_response_iss_parameter_supported: true,
      token_endpoint_auth_methods_supported: ["client_secret_basic", "none"],
      client_id_metadata_document_supported: true
    });
  });

  app.get("/jwks.json", async (c) => {
    const jwks = await getJwks(deps.keys);
    return c.json(jwks);
  });

  app.get("/authorize", async (c) => {
    // This endpoint can trigger an outbound fetch and a database write.
    const result = authorizeLimiter.check(remoteAddress(c));
    if (!result.allowed) {
      return tooManyRequests(c, "/authorize", result.retryAfterSeconds);
    }

    const query = c.req.query();
    const clientId = query.client_id;
    const redirectUri = query.redirect_uri;

    // client_id and redirect_uri are checked before anything is redirected, so these
    // errors are returned directly and never sent to an unverified URI.
    let cimdMetadata: CimdMetadata | undefined;
    if (clientId === deps.client.clientId) {
      if (redirectUri !== deps.client.redirectUri) {
        return c.json(
          { error: "invalid_request", error_description: "redirect_uri does not match the registered value" },
          400
        );
      }
    } else if (clientId !== undefined && isCandidateCimdClientId(clientId)) {
      try {
        cimdMetadata = await cimdClient.fetchMetadata(clientId);
      } catch {
        // Same answer for every failure, see CimdError.
        return c.json({ error: "invalid_client", error_description: "client_id could not be resolved" }, 400);
      }
      if (redirectUri === undefined || !cimdMetadata.redirectUris.includes(redirectUri)) {
        return c.json(
          { error: "invalid_request", error_description: "redirect_uri is not registered for this client_id" },
          400
        );
      }
      if (!isRedirectUriAllowedForApplicationType(redirectUri, cimdMetadata.applicationType)) {
        return c.json(
          {
            error: "invalid_request",
            error_description: "redirect_uri is not permitted for this client's application_type"
          },
          400
        );
      }
    } else {
      return c.json({ error: "invalid_client", error_description: "unknown client_id" }, 400);
    }

    // From here redirect_uri is trusted, so errors go back to it (RFC 6749 4.1.2.1).
    // Every redirect, success or error, carries iss (RFC 9207).
    const state = query.state;
    const fail = (error: string, description: string): Response => {
      const url = new URL(redirectUri);
      url.searchParams.set("error", error);
      url.searchParams.set("error_description", description);
      if (state !== undefined) {
        url.searchParams.set("state", state);
      }
      url.searchParams.set("iss", deps.config.issuer);
      return c.redirect(url.toString(), 302);
    };

    if (query.response_type !== "code") {
      return fail("unsupported_response_type", "only response_type=code is supported");
    }
    if (!query.scope) {
      return fail("invalid_request", "scope is required");
    }
    if (!query.code_challenge) {
      return fail("invalid_request", "code_challenge is required");
    }
    // A missing method means plain under RFC 7636, so it is refused too.
    if (query.code_challenge_method !== "S256") {
      return fail("invalid_request", "code_challenge_method must be S256");
    }

    // Without `resource` the token is bound to CLIENT_AUDIENCE.
    let aud = deps.client.audience;
    if (query.resource !== undefined) {
      if (!isValidResourceUri(query.resource)) {
        return fail("invalid_target", "resource must be an absolute URI with no fragment");
      }
      aud = query.resource;
    }

    // There is no login screen: the request is approved and agent_id becomes the token's sub.
    const agentId = query.agent_id ?? "demo-agent";
    const sub = `agent:${agentId}:${randomBytes(2).toString("hex")}`;
    const code = randomUUID();

    await deps.store.storeAuthorizationCode({
      code,
      clientId,
      redirectUri,
      codeChallenge: query.code_challenge,
      codeChallengeMethod: "S256",
      scope: query.scope,
      sub,
      aud,
      exp: nowSeconds(deps) + AUTH_CODE_TTL_SECONDS
    });

    const redirectTarget = new URL(redirectUri);
    redirectTarget.searchParams.set("code", code);
    if (state !== undefined) {
      redirectTarget.searchParams.set("state", state);
    }
    redirectTarget.searchParams.set("iss", deps.config.issuer);
    return c.redirect(redirectTarget.toString(), 302);
  });

  app.post("/token", async (c) => {
    const limited = enforceRateLimit(c, tokenLimiters, "/token");
    if (limited) return limited;

    const credentials = parseBasicAuth(c.req.header("Authorization"));
    const body = await c.req.parseBody();
    const grantType = formString(body, "grant_type");

    // Wrong credentials are refused for every grant. A CIMD client is public and sends none;
    // it can only redeem a code, and is matched against the code's client_id below.
    if (credentials && !isValidClient(credentials, deps.client)) {
      c.header("WWW-Authenticate", 'Basic realm="mcp-identity"');
      return c.json({ error: "invalid_client" }, 401);
    }
    if (grantType !== "authorization_code" && !credentials) {
      c.header("WWW-Authenticate", 'Basic realm="mcp-identity"');
      return c.json({ error: "invalid_client" }, 401);
    }

    if (grantType === "authorization_code") {
      const code = formString(body, "code");
      const redirectUri = formString(body, "redirect_uri");
      const codeVerifier = formString(body, "code_verifier");

      if (!code || !redirectUri || !codeVerifier) {
        return c.json(
          { error: "invalid_request", error_description: "code, redirect_uri, and code_verifier are required" },
          400
        );
      }

      // Single use: a replayed code misses here.
      const record = await deps.store.consumeAuthorizationCode(code);
      if (!record) {
        return c.json({ error: "invalid_grant", error_description: "unknown, expired, or already-used code" }, 400);
      }

      if (record.clientId === deps.client.clientId) {
        if (!credentials) {
          c.header("WWW-Authenticate", 'Basic realm="mcp-identity"');
          return c.json({ error: "invalid_client" }, 401);
        }
      } else {
        const bodyClientId = formString(body, "client_id");
        if (credentials || bodyClientId !== record.clientId) {
          c.header("WWW-Authenticate", 'Basic realm="mcp-identity"');
          return c.json({ error: "invalid_client" }, 401);
        }
      }

      if (record.redirectUri !== redirectUri) {
        return c.json(
          { error: "invalid_grant", error_description: "redirect_uri does not match the value used at /authorize" },
          400
        );
      }
      if (!verifyPkce(codeVerifier, record.codeChallenge)) {
        return c.json({ error: "invalid_grant", error_description: "code_verifier does not match code_challenge" }, 400);
      }

      // If resource is sent again it must match the one bound at /authorize.
      const requestedResource = formString(body, "resource");
      if (requestedResource !== undefined) {
        if (!isValidResourceUri(requestedResource)) {
          return c.json(
            { error: "invalid_target", error_description: "resource must be an absolute URI with no fragment" },
            400
          );
        }
        if (requestedResource !== record.aud) {
          return c.json(
            { error: "invalid_target", error_description: "resource does not match the value used at /authorize" },
            400
          );
        }
      }

      // One family per authorization grant: every refresh rotation and the access
      // tokens they mint stay in it, and revoking any of them revokes all.
      const familyId = randomUUID();
      const { accessToken, jti } = await issueRecorded(
        { sub: record.sub, aud: record.aud, scope: record.scope, ttlSeconds: deps.config.tokenTtlSeconds },
        { familyId, clientId: record.clientId }
      );

      // Delegated tokens get no refresh token.
      const refreshToken = generateRefreshToken();
      await deps.store.recordRefreshToken({
        tokenHash: sha256Hex(refreshToken),
        familyId,
        jti,
        exp: nowSeconds(deps) + deps.config.refreshTokenTtlSeconds,
        sub: record.sub,
        aud: record.aud,
        scope: record.scope,
        clientId: record.clientId
      });
      await deps.store.recordAuditEvent("issue", jti, null);

      c.header("Cache-Control", "no-store");
      c.header("Pragma", "no-cache");
      return c.json({
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: deps.config.tokenTtlSeconds,
        scope: record.scope,
        refresh_token: refreshToken
      });
    }

    if (grantType === TOKEN_EXCHANGE_GRANT_TYPE) {
      const subjectToken = formString(body, "subject_token");
      const subjectTokenType = formString(body, "subject_token_type");
      const requestedScope = formString(body, "scope");
      const requestedResource = formString(body, "resource");
      // RFC 8693 leaves the new subject open when delegating, so agent_id names it.
      const agentId = formString(body, "agent_id") ?? "delegate";

      if (!subjectToken) {
        return c.json({ error: "invalid_request", error_description: "subject_token is required" }, 400);
      }
      if (subjectTokenType !== undefined && subjectTokenType !== ACCESS_TOKEN_TYPE_URN) {
        return c.json(
          { error: "invalid_request", error_description: `subject_token_type must be ${ACCESS_TOKEN_TYPE_URN}` },
          400
        );
      }

      const parent = await loadLiveToken(subjectToken);
      if (!parent) {
        return c.json({ error: "invalid_grant", error_description: "subject_token is invalid, expired or revoked" }, 400);
      }
      const { claims: parentClaims, record: parentRecord } = parent;
      // Only the client the token was issued to may exchange it.
      if (parentRecord.clientId !== deps.client.clientId) {
        return c.json({ error: "invalid_grant", error_description: "subject_token was not issued to this client" }, 400);
      }

      // The child inherits the parent's aud, so a resource naming anything else is refused.
      if (requestedResource !== undefined && requestedResource !== parentClaims.aud) {
        return c.json(
          { error: "invalid_target", error_description: "resource does not match the subject_token audience" },
          400
        );
      }

      // Depth comes from the stored record, never from the request.
      const childDepth = parentRecord.depth + 1;
      if (childDepth >= deps.config.maxDelegationDepth) {
        return c.json({ error: "invalid_grant", error_description: "delegation depth limit exceeded" }, 400);
      }

      const parentScopes = scopeSet(parentClaims.scope);
      const requestedScopes = requestedScope !== undefined ? scopeSet(requestedScope) : parentScopes;

      if (requestedScopes.size === 0) {
        return c.json({ error: "invalid_scope", error_description: "requested scope must not be empty" }, 400);
      }
      // A scope the parent lacks is refused, not trimmed, so a caller bug can't hide behind
      // a token that looks fine.
      for (const scope of requestedScopes) {
        if (!parentScopes.has(scope)) {
          return c.json(
            { error: "invalid_scope", error_description: `requested scope "${scope}" is not held by subject_token` },
            400
          );
        }
      }

      // exp(child) <= exp(parent)
      const ttlSeconds = Math.min(deps.config.tokenTtlSeconds, parentClaims.exp - nowSeconds(deps));
      if (ttlSeconds <= 0) {
        return c.json({ error: "invalid_grant", error_description: "subject_token is expired" }, 400);
      }

      const childSub = `agent:${agentId}:${randomBytes(2).toString("hex")}`;
      const childScope = Array.from(requestedScopes).join(" ");

      const { accessToken: childToken, jti: childJti } = await issueRecorded(
        {
          sub: childSub,
          aud: parentClaims.aud,
          scope: childScope,
          ttlSeconds,
          act: { sub: parentClaims.sub } // the immediate delegator only
        },
        { parentJti: parentClaims.jti, depth: childDepth, clientId: deps.client.clientId }
      );
      await deps.store.recordAuditEvent("exchange", childJti, { parent_jti: parentClaims.jti, depth: childDepth });

      c.header("Cache-Control", "no-store");
      c.header("Pragma", "no-cache");
      return c.json({
        access_token: childToken,
        issued_token_type: ACCESS_TOKEN_TYPE_URN,
        token_type: "Bearer",
        expires_in: ttlSeconds,
        scope: childScope
      });
    }

    if (grantType === REFRESH_TOKEN_GRANT_TYPE) {
      const presentedToken = formString(body, "refresh_token");
      const requestedScope = formString(body, "scope");

      if (!presentedToken) {
        return c.json({ error: "invalid_request", error_description: "refresh_token is required" }, 400);
      }

      const tokenHash = sha256Hex(presentedToken);
      // Every rejection returns this exact body, so a refused token never reveals why.
      const invalidGrant = (): Response => c.json({ error: "invalid_grant", error_description: "invalid refresh token" }, 400);

      // Classify read-only first: an expired token or a bad scope request must not
      // burn a good refresh token, and an expired token is not evidence of replay.
      const existing = await deps.store.getRefreshTokenRecord(tokenHash);
      if (!existing || existing.revokedAt !== null || existing.exp <= nowSeconds(deps)) {
        return invalidGrant();
      }
      // Rows written before these columns existed cannot be redeemed.
      const { sub, aud, scope, clientId, familyId } = existing;
      if (sub === null || aud === null || scope === null || clientId === null) {
        return invalidGrant();
      }
      // Only the client the grant was issued to may redeem it.
      if (clientId !== deps.client.clientId) {
        return invalidGrant();
      }

      // Refused outright, never trimmed, as in token exchange.
      const narrowed = narrowScope(scope, requestedScope);
      if (!narrowed.ok) {
        return c.json(
          {
            error: "invalid_scope",
            error_description: `requested scope "${narrowed.badScope}" is not held by the current refresh token`
          },
          400
        );
      }

      const respond = (accessToken: string, refreshToken?: string): Response => {
        c.header("Cache-Control", "no-store");
        c.header("Pragma", "no-cache");
        return c.json({
          access_token: accessToken,
          ...(refreshToken !== undefined ? { refresh_token: refreshToken } : {}),
          token_type: "Bearer",
          expires_in: deps.config.tokenTtlSeconds,
          scope: narrowed.scope
        });
      };
      const mintAccessToken = (): Promise<{ accessToken: string; jti: string }> =>
        issueRecorded({ sub, aud, scope: narrowed.scope, ttlSeconds: deps.config.tokenTtlSeconds }, { familyId, clientId });

      // Atomic claim: whoever wins this is the normal rotation.
      const claimed = await deps.store.consumeRefreshToken(tokenHash);
      if (claimed) {
        const { accessToken, jti } = await mintAccessToken();
        const newRefreshToken = generateRefreshToken();
        await deps.store.recordRefreshToken({
          tokenHash: sha256Hex(newRefreshToken),
          familyId,
          jti,
          rotatedFrom: tokenHash,
          exp: claimed.exp, // rotation never extends the family's lifetime
          sub,
          aud,
          scope: narrowed.scope,
          clientId
        });
        await deps.store.recordAuditEvent("refresh", jti, { family_id: familyId, graced: false });
        return respond(accessToken, newRefreshToken);
      }

      // Lost the claim: a concurrent request, a retry after a lost response, or a replay.
      // Inside the grace window it gets an access token only. A second refresh token
      // here would fork the family into two independent chains.
      const gracedRecord = await deps.store.graceRedeemRefreshToken(tokenHash, deps.config.refreshReuseGraceSeconds);
      if (gracedRecord) {
        const { accessToken, jti } = await mintAccessToken();
        await deps.store.recordAuditEvent("refresh", jti, { family_id: familyId, graced: true });
        return respond(accessToken);
      }

      // Genuine reuse: revoke the whole family.
      await deps.store.recordAuditEvent("reuse_detected", existing.jti, { family_id: familyId });
      await deps.store.revokeRefreshFamily(familyId);
      return invalidGrant();
    }

    return c.json({ error: "unsupported_grant_type" }, 400);
  });

  app.post("/introspect", async (c) => {
    const limited = enforceRateLimit(c, introspectLimiters, "/introspect");
    if (limited) return limited;

    const credentials = parseBasicAuth(c.req.header("Authorization"));
    // An open introspection endpoint is a token oracle.
    if (!isValidClient(credentials, deps.client)) {
      c.header("WWW-Authenticate", 'Basic realm="mcp-identity"');
      return c.json({ error: "invalid_client" }, 401);
    }

    const body = await c.req.parseBody();
    const token = formString(body, "token");
    if (!token) {
      return c.json({ error: "invalid_request", error_description: "token is required" }, 400);
    }

    const live = await loadLiveToken(token);
    if (!live) {
      return c.json({ active: false });
    }
    const { claims } = live;
    return c.json({
      active: true,
      iss: claims.iss,
      sub: claims.sub,
      aud: claims.aud,
      scope: claims.scope,
      jti: claims.jti,
      iat: claims.iat,
      exp: claims.exp,
      token_type: "Bearer",
      ...(live.record.clientId !== null ? { client_id: live.record.clientId } : {})
    });
  });

  app.post("/revoke", async (c) => {
    const limited = enforceRateLimit(c, revokeLimiters, "/revoke");
    if (limited) return limited;

    const credentials = parseBasicAuth(c.req.header("Authorization"));
    if (!isValidClient(credentials, deps.client)) {
      c.header("WWW-Authenticate", 'Basic realm="mcp-identity"');
      return c.json({ error: "invalid_client" }, 401);
    }

    const body = await c.req.parseBody();
    const token = formString(body, "token");
    if (!token) {
      return c.json({ error: "invalid_request", error_description: "token is required" }, 400);
    }

    // RFC 7009: 200 whether or not the token was known, so the answer never reveals
    // which. Revoking a refresh token revokes its whole family.
    const claims = await verifyOwnToken(token).catch(() => undefined);
    if (claims) {
      await deps.store.revoke(claims.jti);
    } else {
      const refresh = await deps.store.getRefreshTokenRecord(sha256Hex(token));
      if (refresh) {
        await deps.store.revokeRefreshFamily(refresh.familyId);
      }
    }

    return c.body(null, 200);
  });

  return app;
}

export { computeS256Challenge };
