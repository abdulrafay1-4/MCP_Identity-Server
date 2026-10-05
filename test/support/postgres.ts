import { randomUUID } from "node:crypto";
import type { Pool } from "pg";
import { createPool } from "../../src/store/postgres/pool.js";
import { runMigrations } from "../../src/store/postgres/migrate.js";

export interface TestDatabase {
  pool: Pool;
  drop(): Promise<void>;
}

// One database per test file. The suites move a fake clock and prune expired
// rows, and in a shared database that deletes rows another file still needs.
export async function createTestDatabase(databaseUrl: string): Promise<TestDatabase> {
  const admin = createPool(databaseUrl);
  const name = `test_${randomUUID().replaceAll("-", "")}`;
  await admin.query(`CREATE DATABASE ${name}`);
  const url = new URL(databaseUrl);
  url.pathname = `/${name}`;
  const pool = createPool(url.toString());
  await runMigrations(pool);
  return {
    pool,
    async drop() {
      await pool.end();
      await admin.query(`DROP DATABASE ${name} WITH (FORCE)`);
      await admin.end();
    }
  };
}
