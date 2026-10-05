import { randomUUID } from "node:crypto";
import { SignJWT, decodeProtectedHeader, errors as joseErrors, jwtVerify } from "jose";
import { findKey, getActiveKey, type KeyRing } from "./keys.js";

export interface IssueParams {
  sub: string;
  aud: string;
  scope: string;
  ttlSeconds: number;
  act?: { sub: string };
}

export interface IssueContext {
  keys: KeyRing;
  issuer: string;
  now?: () => Date;
}

export interface VerifyContext {
  keys: KeyRing;
  issuer: string;
  /** Omit to skip the audience check (the authorization server's own endpoints do; resource servers must set it). */
  audience?: string;
  now?: () => Date;
}

export interface TokenClaims {
  iss: string;
  sub: string;
  aud: string;
  scope: string;
  jti: string;
  iat: number;
  exp: number;
  act?: { sub: string };
}

export async function issue(params: IssueParams, context: IssueContext): Promise<string> {
  const now = (context.now ?? (() => new Date()))();
  const iat = Math.floor(now.getTime() / 1000);
  const exp = iat + params.ttlSeconds;

  const claims: Record<string, unknown> = { scope: params.scope };
  if (params.act) {
    claims.act = params.act;
  }

  const activeKey = getActiveKey(context.keys);
  if (!activeKey.privateKey) {
    throw new Error("active key has no private key material");
  }

  return new SignJWT(claims)
    .setProtectedHeader({ alg: activeKey.alg, kid: activeKey.kid })
    .setIssuer(context.issuer)
    .setSubject(params.sub)
    .setAudience(params.aud)
    .setJti(randomUUID())
    .setIssuedAt(iat)
    .setExpirationTime(exp)
    .sign(activeKey.privateKey);
}

export async function verify(token: string, context: VerifyContext): Promise<TokenClaims> {
  const now = (context.now ?? (() => new Date()))();

  let kid: string | undefined;
  try {
    kid = decodeProtectedHeader(token).kid;
  } catch {
    throw new Error("Token verification failed (ERR_MALFORMED_TOKEN)");
  }
  if (typeof kid !== "string") {
    throw new Error("Token verification failed (ERR_MISSING_KID)");
  }
  const key = findKey(context.keys, kid);
  // Retiring a key has to stop it verifying even valid signatures.
  if (!key || key.state === "retired") {
    throw new Error("Token verification failed (ERR_UNKNOWN_KID)");
  }

  const payload = await jwtVerify(token, key.publicKey, {
    issuer: context.issuer,
    audience: context.audience,
    algorithms: [key.alg],
    currentDate: now,
    requiredClaims: ["sub", "jti", "iat", "exp"]
  })
    .then((result) => result.payload)
    .catch((error: unknown) => {
      const code = error instanceof joseErrors.JOSEError ? error.code : "ERR_JWT_VERIFY_FAILED";
      throw new Error(`Token verification failed (${code})`);
    });

  const { iss, sub, aud, jti, iat, exp, scope, act } = payload;

  if (
    typeof iss !== "string" ||
    typeof sub !== "string" ||
    typeof aud !== "string" ||
    typeof jti !== "string" ||
    typeof iat !== "number" ||
    typeof exp !== "number" ||
    typeof scope !== "string"
  ) {
    throw new Error("Token verification failed (ERR_MALFORMED_CLAIMS)");
  }

  if (act === undefined) {
    return { iss, sub, aud, scope, jti, iat, exp };
  }

  if (typeof act !== "object" || act === null || typeof (act as Record<string, unknown>).sub !== "string") {
    throw new Error("Token verification failed (ERR_MALFORMED_CLAIMS)");
  }

  return { iss, sub, aud, scope, jti, iat, exp, act: { sub: (act as Record<string, unknown>).sub as string } };
}
