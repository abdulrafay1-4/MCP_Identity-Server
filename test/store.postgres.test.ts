import { afterAll, beforeAll, describe } from "vitest";
import { PgTokenStore } from "../src/store/postgres/pgStore.js";
import { poolQueryable } from "../src/store/postgres/poolQueryable.js";
import { runTokenStoreContractTests, type TokenStoreHarness } from "./support/tokenStoreContract.js";
import { createTestDatabase, type TestDatabase } from "./support/postgres.js";

const databaseUrl = process.env.DATABASE_URL;

describe.skipIf(!databaseUrl)("Postgres store (live database)", () => {
  let database: TestDatabase | undefined;

  beforeAll(async () => {
    database = await createTestDatabase(databaseUrl!);
  });

  afterAll(async () => {
    await database?.drop();
  });

  async function buildHarness(): Promise<TokenStoreHarness> {
    let current = new Date();
    const store = new PgTokenStore(poolQueryable(database!.pool), { now: () => current });
    return { store, setNow: (date) => (current = date) };
  }

  runTokenStoreContractTests("PgTokenStore", buildHarness);
});
