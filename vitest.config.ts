import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["test/**/*.test.ts"],
    // pglite compiles Postgres to WebAssembly on startup, which can take a while on a busy runner.
    hookTimeout: 60_000
  }
});
