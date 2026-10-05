import { afterAll, beforeAll, describe } from "vitest";
import { PgTokenStore } from "../src/store/postgres/pgStore.js";
import { runTokenStoreContractTests, type TokenStoreHarness } from "./support/tokenStoreContract.js";
import { createMigratedPglite, type PgliteHandle } from "./support/pglite.js";

describe("Postgres store (pglite, embedded, no server)", () => {
  let handle: PgliteHandle;

  beforeAll(async () => {
    handle = await createMigratedPglite();
  });

  afterAll(async () => {
    await handle?.close();
  });

  async function buildHarness(): Promise<TokenStoreHarness> {
    let current = new Date();
    const store = new PgTokenStore(handle.db, { now: () => current });
    return { store, setNow: (date) => (current = date) };
  }

  runTokenStoreContractTests("PgTokenStore (pglite)", buildHarness);
});
