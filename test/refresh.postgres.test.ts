import { afterAll, beforeAll, describe } from "vitest";
import { PgTokenStore } from "../src/store/postgres/pgStore.js";
import { poolQueryable } from "../src/store/postgres/poolQueryable.js";
import { runRefreshTests } from "./support/refreshContract.js";
import { createTestDatabase, type TestDatabase } from "./support/postgres.js";

const databaseUrl = process.env.DATABASE_URL;

describe.skipIf(!databaseUrl)("refresh tokens over real Postgres", () => {
  let database: TestDatabase | undefined;

  beforeAll(async () => {
    database = await createTestDatabase(databaseUrl!);
  });

  afterAll(async () => {
    await database?.drop();
  });

  runRefreshTests("PgTokenStore (real Postgres)", (now) => new PgTokenStore(poolQueryable(database!.pool), { now }));
});
