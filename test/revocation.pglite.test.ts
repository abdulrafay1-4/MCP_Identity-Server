import { afterAll, beforeAll, describe } from "vitest";
import { PgTokenStore } from "../src/store/postgres/pgStore.js";
import { runRevocationTests } from "./support/revocationContract.js";
import { createMigratedPglite, type PgliteHandle } from "./support/pglite.js";

describe("revocation over pglite", () => {
  let handle: PgliteHandle;

  beforeAll(async () => {
    handle = await createMigratedPglite();
  });

  afterAll(async () => {
    await handle?.close();
  });

  runRevocationTests("PgTokenStore (pglite)", (now) => new PgTokenStore(handle.db, { now }));
});
