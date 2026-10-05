import { describe, expect, it } from "vitest";
import type { TokenStore } from "../src/store/types.js";
import { MemoryTokenStore } from "../src/store/memory.js";
import { createLogger } from "../src/log.js";
import { BASE_NOW, buildDelegationHarness } from "./support/delegationHarness.js";
import { introspect, mintUnrecordedToken } from "./support/tokenFlow.js";

function brokenStore(real: TokenStore): TokenStore {
  return new Proxy(real, {
    get(target, prop, receiver) {
      if (prop === "getRecord") {
        return async () => {
          throw new Error("connection refused");
        };
      }
      return Reflect.get(target, prop, receiver);
    }
  });
}

describe("GET /healthz", () => {
  it("returns 200 with no dependency on the store", async () => {
    const h = await buildDelegationHarness((now) => brokenStore(new MemoryTokenStore({ now })));
    const res = await h.app.request("/healthz");
    expect(res.status).toBe(200);
    const body = (await res.json()) as { status: string };
    expect(body.status).toBe("ok");
  });
});

describe("GET /readyz", () => {
  it("returns 200 when the store is reachable", async () => {
    const h = await buildDelegationHarness((now) => new MemoryTokenStore({ now }));
    const res = await h.app.request("/readyz");
    expect(res.status).toBe(200);
    const body = (await res.json()) as { status: string };
    expect(body.status).toBe("ok");
  });

  it("returns 503 when the store is unreachable, without leaking the underlying error", async () => {
    const h = await buildDelegationHarness((now) => brokenStore(new MemoryTokenStore({ now })));
    const res = await h.app.request("/readyz");
    expect(res.status).toBe(503);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.status).toBe("not_ready");
    expect(JSON.stringify(body)).not.toContain("connection refused");
  });
});

describe("unhandled errors", () => {
  it("answer 500 server_error, keep the cause out of the body and log it", async () => {
    const lines: string[] = [];
    const h = await buildDelegationHarness((now) => brokenStore(new MemoryTokenStore({ now })), {
      logger: createLogger({ sink: (line) => lines.push(line) })
    });
    const body = await introspect(h.app, await mintUnrecordedToken(h.keys, BASE_NOW));
    expect(body).toEqual({ error: "server_error" });
    expect(lines.some((line) => line.includes('"unhandled_error"') && line.includes("connection refused"))).toBe(true);
  });
});
