import { afterAll, beforeAll, describe } from "vitest";
import { PgTokenStore } from "../src/store/postgres/pgStore.js";
import { runRefreshTests } from "./support/refreshContract.js";
import { createMigratedPglite, type PgliteHandle } from "./support/pglite.js";

describe("refresh tokens over pglite", () => {
  let handle: PgliteHandle;

  beforeAll(async () => {
    handle = await createMigratedPglite();
  });

  afterAll(async () => {
    await handle?.close();
  });

  runRefreshTests("PgTokenStore (pglite)", (now) => new PgTokenStore(handle.db, { now }));
});
