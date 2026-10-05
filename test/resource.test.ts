import { describe, expect, it } from "vitest";
import { isValidResourceUri } from "../src/resource.js";

describe("isValidResourceUri", () => {
  it("accepts an absolute https URI", () => {
    expect(isValidResourceUri("https://mcp-server.example/mcp")).toBe(true);
  });

  it("accepts an absolute http URI (local development)", () => {
    expect(isValidResourceUri("http://localhost:4000/mcp")).toBe(true);
  });

  it("rejects a non-absolute value", () => {
    expect(isValidResourceUri("not-a-uri")).toBe(false);
    expect(isValidResourceUri("/relative/path")).toBe(false);
  });

  it("rejects a URI with a fragment component (RFC 8707 §2)", () => {
    expect(isValidResourceUri("https://mcp-server.example/mcp#section")).toBe(false);
  });

  it("rejects a scheme other than http/https", () => {
    expect(isValidResourceUri("ftp://mcp-server.example/mcp")).toBe(false);
    expect(isValidResourceUri("urn:ietf:params:oauth:resource")).toBe(false);
  });
});
