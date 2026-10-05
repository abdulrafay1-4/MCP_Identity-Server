import { randomBytes } from "node:crypto";
import type { Hono } from "hono";
import { expect } from "vitest";
import type { AppEnv } from "../../src/http/requestLogging.js";
import { CimdClient } from "../../src/cimd.js";
import type { KeyRing } from "../../src/keys.js";
import { computeS256Challenge } from "../../src/pkce.js";
import { issue } from "../../src/tokens.js";
import { basicAuthHeader, CLIENT, ISSUER } from "./delegationHarness.js";

const TOKEN_EXCHANGE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS_TOKEN_TYPE_URN = "urn:ietf:params:oauth:token-type:access_token";

export interface TokenResponseBody {
  access_token: string;
  scope: string;
  issued_token_type?: string;
  error?: string;
  error_description?: string;
  refresh_token?: string;
}

export interface IntrospectBody {
  active: boolean;
  aud?: string;
  client_id?: string;
}

export function pkcePair(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString("base64url");
  return { verifier, challenge: computeS256Challenge(verifier) };
}

export function decodePayload(token: string): Record<string, unknown> {
  const [, payloadB64] = token.split(".");
  return JSON.parse(Buffer.from(payloadB64 ?? "", "base64url").toString("utf-8")) as Record<string, unknown>;
}

export function jtiOf(token: string): string {
  const jti = decodePayload(token).jti;
  if (typeof jti !== "string") throw new Error("expected a string jti claim");
  return jti;
}

export async function postToken(app: Hono<AppEnv>, body: Record<string, string>): Promise<Response> {
  return app.request("/token", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: basicAuthHeader(CLIENT.clientId, CLIENT.clientSecret)
    },
    body: new URLSearchParams(body).toString()
  });
}

export async function mintRootToken(
  app: Hono<AppEnv>,
  overrides: { scope?: string; agentId?: string; resource?: string } = {}
): Promise<{
  accessToken: string;
  scope: string;
  sub: string;
  refreshToken: string;
}> {
  const { verifier, challenge } = pkcePair();
  const params = new URLSearchParams({
    response_type: "code",
    client_id: CLIENT.clientId,
    redirect_uri: CLIENT.redirectUri,
    scope: overrides.scope ?? "filings:read quotes:read",
    state: "state-abc",
    agent_id: overrides.agentId ?? "root-agent",
    code_challenge: challenge,
    code_challenge_method: "S256"
  });
  if (overrides.resource !== undefined) {
    params.set("resource", overrides.resource);
  }
  const authRes = await app.request(`/authorize?${params.toString()}`);
  expect(authRes.status).toBe(302);
  const location = authRes.headers.get("Location");
  if (!location) throw new Error("expected a Location header");
  const code = new URL(location).searchParams.get("code");
  if (!code) throw new Error("expected a code in the redirect");

  const tokenRes = await postToken(app, {
    grant_type: "authorization_code",
    code,
    redirect_uri: CLIENT.redirectUri,
    code_verifier: verifier
  });
  expect(tokenRes.status).toBe(200);
  const body = (await tokenRes.json()) as TokenResponseBody;

  const sub = decodePayload(body.access_token).sub;
  if (typeof sub !== "string") throw new Error("expected a string sub claim");
  if (typeof body.refresh_token !== "string") throw new Error("expected a refresh_token in a root grant's response");

  return { accessToken: body.access_token, scope: body.scope, sub, refreshToken: body.refresh_token };
}

export async function exchangeToken(
  app: Hono<AppEnv>,
  subjectToken: string,
  overrides: { scope?: string; agentId?: string; subjectTokenType?: string; resource?: string } = {}
): Promise<Response> {
  const body: Record<string, string> = {
    grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
    subject_token: subjectToken,
    subject_token_type: overrides.subjectTokenType ?? ACCESS_TOKEN_TYPE_URN
  };
  if (overrides.scope !== undefined) {
    body.scope = overrides.scope;
  }
  if (overrides.agentId !== undefined) {
    body.agent_id = overrides.agentId;
  }
  if (overrides.resource !== undefined) {
    body.resource = overrides.resource;
  }
  return postToken(app, body);
}

export async function refreshToken(
  app: Hono<AppEnv>,
  presentedRefreshToken: string,
  overrides: { scope?: string } = {}
): Promise<Response> {
  const body: Record<string, string> = {
    grant_type: "refresh_token",
    refresh_token: presentedRefreshToken
  };
  if (overrides.scope !== undefined) {
    body.scope = overrides.scope;
  }
  return postToken(app, body);
}

export async function revokeToken(app: Hono<AppEnv>, token: string): Promise<Response> {
  return app.request("/revoke", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: basicAuthHeader(CLIENT.clientId, CLIENT.clientSecret)
    },
    body: new URLSearchParams({ token }).toString()
  });
}

export function mintUnrecordedToken(keys: KeyRing, now: Date): Promise<string> {
  return issue(
    { sub: "agent:ghost:0000", aud: CLIENT.audience, scope: "filings:read", ttlSeconds: 3600 },
    { keys, issuer: ISSUER, now: () => now }
  );
}

export async function introspect(app: Hono<AppEnv>, token: string): Promise<IntrospectBody> {
  const res = await app.request("/introspect", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: basicAuthHeader(CLIENT.clientId, CLIENT.clientSecret)
    },
    body: new URLSearchParams({ token }).toString()
  });
  return (await res.json()) as IntrospectBody;
}

export async function introspectActive(app: Hono<AppEnv>, token: string): Promise<boolean> {
  return (await introspect(app, token)).active;
}

export const CIMD_CLIENT_ID = "https://cimd-client.example.com/metadata.json";
export const CIMD_REDIRECT_URI = "https://cimd-client.example.com/callback";

export function stubCimdClient(): CimdClient {
  return new CimdClient({
    fetch: async () =>
      new Response(
        JSON.stringify({ client_id: CIMD_CLIENT_ID, client_name: "CIMD Test Client", redirect_uris: [CIMD_REDIRECT_URI] }),
        { status: 200, headers: { "content-type": "application/json" } }
      ),
    resolveHostname: async () => ["93.184.216.34"]
  });
}

export async function mintCimdToken(app: Hono<AppEnv>, scope = "filings:read"): Promise<{ accessToken: string; refreshToken: string }> {
  const { verifier, challenge } = pkcePair();
  const params = new URLSearchParams({
    response_type: "code",
    client_id: CIMD_CLIENT_ID,
    redirect_uri: CIMD_REDIRECT_URI,
    scope,
    code_challenge: challenge,
    code_challenge_method: "S256"
  });
  const authRes = await app.request(`/authorize?${params.toString()}`);
  expect(authRes.status).toBe(302);
  const code = new URL(authRes.headers.get("Location") ?? "").searchParams.get("code");
  if (!code) throw new Error("expected a code in the redirect");

  const tokenRes = await app.request("/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: CIMD_REDIRECT_URI,
      code_verifier: verifier,
      client_id: CIMD_CLIENT_ID
    }).toString()
  });
  expect(tokenRes.status).toBe(200);
  const body = (await tokenRes.json()) as TokenResponseBody;
  if (typeof body.refresh_token !== "string") throw new Error("expected a refresh_token");
  return { accessToken: body.access_token, refreshToken: body.refresh_token };
}
