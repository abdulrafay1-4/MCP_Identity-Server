import { describe, expect, it } from "vitest";
import { MemoryTokenStore } from "../src/store/memory.js";
import { basicAuthHeader, buildDelegationHarness, CLIENT } from "./support/delegationHarness.js";

const LIMIT_BYTES = 16 * 1024;
const ENDPOINTS = ["/token", "/introspect", "/revoke"] as const;

function formOfSize(bytes: number): string {
  const prefix = "token=";
  return prefix + "a".repeat(bytes - prefix.length);
}

describe("request body size limit", () => {
  async function post(path: string, body: string | ReadableStream<Uint8Array>, headers: Record<string, string> = {}): Promise<Response> {
    const h = await buildDelegationHarness((now) => new MemoryTokenStore({ now }));
    return h.app.request(path, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: basicAuthHeader(CLIENT.clientId, CLIENT.clientSecret),
        ...headers
      },
      body,
      ...(typeof body === "string" ? {} : { duplex: "half" })
    } as RequestInit);
  }

  it.each(ENDPOINTS)("%s refuses a body over 16 KiB with 413", async (path) => {
    const res = await post(path, formOfSize(LIMIT_BYTES + 1));
    expect(res.status).toBe(413);
    expect(((await res.json()) as { error: string }).error).toBe("invalid_request");
  });

  it.each(ENDPOINTS)("%s refuses an oversized body that declares Content-Length", async (path) => {
    const body = formOfSize(LIMIT_BYTES + 1);
    const res = await post(path, body, { "Content-Length": String(body.length) });
    expect(res.status).toBe(413);
  });

  it("refuses an oversized streamed body that declares no length", async () => {
    const chunk = new TextEncoder().encode("token=" + "a".repeat(4096));
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        for (let i = 0; i < 5; i++) controller.enqueue(chunk);
        controller.close();
      }
    });
    const res = await post("/introspect", stream);
    expect(res.status).toBe(413);
  });

  it("refuses an oversized body before checking credentials", async () => {
    const res = await post("/introspect", formOfSize(LIMIT_BYTES + 1), { Authorization: "Basic bm9wZTpub3Bl" });
    expect(res.status).toBe(413);
  });

  it.each(ENDPOINTS)("%s accepts a body of exactly 16 KiB", async (path) => {
    const res = await post(path, formOfSize(LIMIT_BYTES));
    expect(res.status).not.toBe(413);
  });
});
