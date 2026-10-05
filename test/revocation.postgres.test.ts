import { afterAll, beforeAll, describe } from "vitest";
import { PgTokenStore } from "../src/store/postgres/pgStore.js";
import { poolQueryable } from "../src/store/postgres/poolQueryable.js";
import { runRevocationTests } from "./support/revocationContract.js";
import { createTestDatabase, type TestDatabase } from "./support/postgres.js";

const databaseUrl = process.env.DATABASE_URL;

describe.skipIf(!databaseUrl)("revocation over real Postgres", () => {
  let database: TestDatabase | undefined;

  beforeAll(async () => {
    database = await createTestDatabase(databaseUrl!);
  });

  afterAll(async () => {
    await database?.drop();
  });

  runRevocationTests("PgTokenStore (real Postgres)", (now) => new PgTokenStore(poolQueryable(database!.pool), { now }));
});
