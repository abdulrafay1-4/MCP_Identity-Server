import type { IncomingMessage, ServerResponse } from "node:http";
import https from "node:https";
import type { AddressInfo } from "node:net";
import type { TLSSocket } from "node:tls";
import { afterEach, describe, expect, it } from "vitest";
import { createPinnedFetch } from "../src/cimd.js";
import { TEST_CERT, TEST_KEY } from "./cimd.tls-fixture.js";

interface TestServer {
  port: number;
  requests: () => number;
  hostHeaders: string[];
  urls: string[];
  serverNames: Array<string | false | null>;
}

const servers: https.Server[] = [];

async function startServer(handler: (req: IncomingMessage, res: ServerResponse) => void): Promise<TestServer> {
  let count = 0;
  const hostHeaders: string[] = [];
  const urls: string[] = [];
  const serverNames: Array<string | false | null> = [];
  const server = https.createServer({ key: TEST_KEY, cert: TEST_CERT }, (req, res) => {
    count++;
    hostHeaders.push(req.headers.host ?? "");
    urls.push(req.url ?? "");
    handler(req, res);
  });
  server.on("secureConnection", (socket: TLSSocket) => serverNames.push(socket.servername));
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { port: (server.address() as AddressInfo).port, requests: () => count, hostHeaders, urls, serverNames };
}

afterEach(async () => {
  await Promise.all(
    servers.splice(0).map(
      (server) =>
        new Promise<void>((resolve) => {
          server.close(() => resolve());
          server.closeAllConnections();
        })
    )
  );
});

function init(addresses: string[], signal: AbortSignal = new AbortController().signal) {
  return { signal, redirect: "manual" as const, addresses };
}

describe("createPinnedFetch", () => {
  it("connects to the pinned address for a name that does not resolve, and verifies TLS against that name", async () => {
    const server = await startServer((_req, res) => {
      res.setHeader("content-type", "application/json");
      res.setHeader("set-cookie", ["a=1", "b=2"]);
      res.end(JSON.stringify({ ok: true }));
    });
    const res = await createPinnedFetch({ ca: TEST_CERT })(
      `https://pinned.test:${server.port}/doc.json?v=1`,
      init(["127.0.0.1"])
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
    expect(res.headers.get("content-type")).toBe("application/json");
    expect(res.headers.getSetCookie()).toEqual(["a=1", "b=2"]);
    expect(server.urls).toEqual(["/doc.json?v=1"]);
    expect(server.serverNames).toEqual(["pinned.test"]);
    expect(server.hostHeaders).toEqual([`pinned.test:${server.port}`]);
  });

  it("verifies an IP literal host against the certificate's IP address and sends no SNI", async () => {
    const server = await startServer((_req, res) => res.end("{}"));
    const res = await createPinnedFetch({ ca: TEST_CERT })(
      `https://127.0.0.1:${server.port}/doc.json`,
      init(["127.0.0.1"])
    );
    expect(res.status).toBe(200);
    expect(server.serverNames).toEqual([false]);
  });

  it("refuses to connect when it is given no address", async () => {
    const server = await startServer((_req, res) => res.end("{}"));
    await expect(
      createPinnedFetch({ ca: TEST_CERT })(`https://pinned.test:${server.port}/doc.json`, init([]))
    ).rejects.toThrow("no vetted address");
    expect(server.requests()).toBe(0);
  });

  it("passes a body-less 304 through as a response", async () => {
    const server = await startServer((_req, res) => {
      res.writeHead(304);
      res.end();
    });
    const res = await createPinnedFetch({ ca: TEST_CERT })(
      `https://pinned.test:${server.port}/doc.json`,
      init(["127.0.0.1"])
    );
    expect(res.status).toBe(304);
    expect(res.body).toBeNull();
  });

  it("rejects a certificate that does not cover the requested hostname", async () => {
    const server = await startServer((_req, res) => res.end("{}"));
    await expect(
      createPinnedFetch({ ca: TEST_CERT })(`https://other.test:${server.port}/doc.json`, init(["127.0.0.1"]))
    ).rejects.toMatchObject({ code: "ERR_TLS_CERT_ALTNAME_INVALID" });
    expect(server.requests()).toBe(0);
  });

  it("rejects a certificate that is not signed by a trusted authority", async () => {
    const server = await startServer((_req, res) => res.end("{}"));
    await expect(
      createPinnedFetch()(`https://pinned.test:${server.port}/doc.json`, init(["127.0.0.1"]))
    ).rejects.toMatchObject({ code: expect.stringMatching(/SELF_SIGNED/) as string });
    expect(server.requests()).toBe(0);
  });

  it("returns a redirect as a plain 3xx response and does not follow it", async () => {
    const server = await startServer((req, res) => {
      if (req.url === "/doc.json") {
        res.writeHead(302, { location: `https://pinned.test:${(req.socket.localPort ?? 0).toString()}/elsewhere` });
      }
      res.end();
    });
    const res = await createPinnedFetch({ ca: TEST_CERT })(
      `https://pinned.test:${server.port}/doc.json`,
      init(["127.0.0.1"])
    );
    expect(res.status).toBe(302);
    expect(res.ok).toBe(false);
    expect(server.requests()).toBe(1);
  });

  it("does not connect at all when the signal is already aborted", async () => {
    const server = await startServer((_req, res) => res.end("{}"));
    const controller = new AbortController();
    controller.abort();
    await expect(
      createPinnedFetch({ ca: TEST_CERT })(
        `https://pinned.test:${server.port}/doc.json`,
        init(["127.0.0.1"], controller.signal)
      )
    ).rejects.toBeDefined();
    expect(server.requests()).toBe(0);
  });

  it("drops the connection when the signal aborts while the body is still arriving", async () => {
    let closed: () => void = () => {};
    const serverSawClose = new Promise<void>((resolve) => {
      closed = resolve;
    });
    const server = await startServer((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.write("{");
      const timer = setInterval(() => res.write(" "), 20);
      res.on("close", () => {
        clearInterval(timer);
        closed();
      });
    });
    const controller = new AbortController();
    const res = await createPinnedFetch({ ca: TEST_CERT })(
      `https://pinned.test:${server.port}/doc.json`,
      init(["127.0.0.1"], controller.signal)
    );
    const reading = res.text().then(
      () => "ended",
      () => "errored"
    );
    setTimeout(() => controller.abort(), 100);
    const guard = new Promise<string>((resolve) => setTimeout(() => resolve("still open"), 2_000).unref());
    expect(await Promise.race([serverSawClose.then(() => "closed"), guard])).toBe("closed");
    expect(await Promise.race([reading, guard])).not.toBe("still open");
  });
});
