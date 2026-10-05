import { describe, expect, it } from "vitest";
import { computeS256Challenge, isValidCodeVerifier, verifyPkce } from "../src/pkce.js";
import { MemoryTokenStore } from "../src/store/memory.js";
import { buildDelegationHarness, CLIENT } from "./support/delegationHarness.js";
import { postToken } from "./support/tokenFlow.js";

const UNRESERVED = "ABCabc012-._~";

describe("code_verifier shape (RFC 7636 section 4.1)", () => {
  it("accepts 43 to 128 unreserved characters", () => {
    expect(isValidCodeVerifier("a".repeat(43))).toBe(true);
    expect(isValidCodeVerifier("a".repeat(128))).toBe(true);
    expect(isValidCodeVerifier(UNRESERVED.repeat(4))).toBe(true);
  });

  it("rejects fewer than 43 or more than 128 characters", () => {
    expect(isValidCodeVerifier("a".repeat(42))).toBe(false);
    expect(isValidCodeVerifier("a".repeat(129))).toBe(false);
    expect(isValidCodeVerifier("")).toBe(false);
  });

  it("rejects characters outside [A-Za-z0-9-._~]", () => {
    for (const bad of ["+", "/", "=", " ", "é", "\n"]) {
      expect(isValidCodeVerifier("a".repeat(42) + bad)).toBe(false);
    }
  });

  it("verifyPkce refuses a malformed verifier even when its challenge matches", () => {
    const short = "a".repeat(42);
    expect(verifyPkce(short, computeS256Challenge(short))).toBe(false);
    const ok = "a".repeat(43);
    expect(verifyPkce(ok, computeS256Challenge(ok))).toBe(true);
  });
});

describe("POST /token enforces the code_verifier shape", () => {
  async function redeemWith(verifier: string): Promise<Response> {
    const h = await buildDelegationHarness((now) => new MemoryTokenStore({ now }));
    const params = new URLSearchParams({
      response_type: "code",
      client_id: CLIENT.clientId,
      redirect_uri: CLIENT.redirectUri,
      scope: "filings:read",
      code_challenge: computeS256Challenge(verifier),
      code_challenge_method: "S256"
    });
    const authRes = await h.app.request(`/authorize?${params.toString()}`);
    const code = new URL(authRes.headers.get("Location") ?? "").searchParams.get("code") ?? "";
    return postToken(h.app, {
      grant_type: "authorization_code",
      code,
      redirect_uri: CLIENT.redirectUri,
      code_verifier: verifier
    });
  }

  it.each([
    ["shorter than 43 characters", "a".repeat(42)],
    ["longer than 128 characters", "a".repeat(129)],
    ["with a character outside the unreserved set", "a".repeat(42) + "+"]
  ])("returns invalid_grant for a verifier %s, though it matches the challenge", async (_name, verifier) => {
    const res = await redeemWith(verifier);
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: string }).error).toBe("invalid_grant");
  });

  it.each([43, 128])("accepts a verifier of %i characters", async (length) => {
    const res = await redeemWith("a".repeat(length));
    expect(res.status).toBe(200);
  });
});
