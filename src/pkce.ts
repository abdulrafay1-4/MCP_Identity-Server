import { createHash, timingSafeEqual } from "node:crypto";

export function computeS256Challenge(codeVerifier: string): string {
  return createHash("sha256").update(codeVerifier, "ascii").digest("base64url");
}

/** RFC 7636 section 4.1: 43 to 128 characters from the unreserved set. */
export function isValidCodeVerifier(codeVerifier: string): boolean {
  return /^[A-Za-z0-9\-._~]{43,128}$/.test(codeVerifier);
}

export function verifyPkce(codeVerifier: string, codeChallenge: string): boolean {
  if (!isValidCodeVerifier(codeVerifier)) {
    return false;
  }

  const computed = Buffer.from(computeS256Challenge(codeVerifier));
  const expected = Buffer.from(codeChallenge);

  if (computed.length !== expected.length) {
    return false;
  }

  return timingSafeEqual(computed, expected);
}
