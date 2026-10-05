import { serve } from "@hono/node-server";
import { loadDemoClient } from "./config/client.js";
import { loadConfig } from "./config/env.js";
import { createApp } from "./http/app.js";
import { loadPersistedKeyRing } from "./keys.js";
import { createLogger } from "./log.js";
import { createStore } from "./store/factory.js";

async function main(): Promise<void> {
  const config = loadConfig();
  const log = createLogger({ level: config.logLevel });
  const client = loadDemoClient();
  const keys = await loadPersistedKeyRing(config.keyRingPath, config.signingKey);
  const { store, pruneExpired, close } = await createStore({ databaseUrl: config.databaseUrl });

  const app = createApp({ config, keys, store, client, logger: log });

  const pruneTimer = setInterval(() => {
    pruneExpired().catch((error: unknown) => {
      log.error("prune_sweep_failed", { reason: error instanceof Error ? error.message : "unknown error" });
    });
  }, config.pruneIntervalMs);
  pruneTimer.unref();

  const server = serve({ fetch: app.fetch, port: config.port }, (info) => {
    log.info("server_started", {
      port: info.port,
      issuer: config.issuer,
      store: config.databaseUrl ? "postgres" : "memory"
    });
  });

  const shutdown = (): void => {
    log.info("server_shutting_down", {});
    clearInterval(pruneTimer);
    server.close();
    close().catch((error: unknown) => {
      log.error("store_close_failed", { reason: error instanceof Error ? error.message : "unknown error" });
    });
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}

main().catch((error: unknown) => {
  // Not the structured logger: it depends on the config, which may be what failed.
  console.error("mcp-identity failed to start:", error);
  process.exitCode = 1;
});
