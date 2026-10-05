import { readdirSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createPool } from "../src/store/postgres/pool.js";
import { runMigrations } from "../src/store/postgres/migrate.js";

const databaseUrl = process.env.DATABASE_URL;
const migrationFiles = readdirSync(new URL("../migrations", import.meta.url))
  .filter((name) => name.endsWith(".sql"))
  .sort();

describe.skipIf(!databaseUrl)("runMigrations (live database)", () => {
  it("applies each migration exactly once when several instances start together on a fresh database", async () => {
    const admin = createPool(databaseUrl!);
    const name = `migrate_race_${randomUUID().replaceAll("-", "")}`;
    await admin.query(`CREATE DATABASE ${name}`);

    const url = new URL(databaseUrl!);
    url.pathname = `/${name}`;
    const pools = Array.from({ length: 4 }, () => createPool(url.toString()));

    try {
      const applied = await Promise.all(pools.map((pool) => runMigrations(pool)));
      expect(applied.flat().sort()).toEqual(migrationFiles);
    } finally {
      await Promise.all(pools.map((pool) => pool.end()));
      await admin.query(`DROP DATABASE ${name} WITH (FORCE)`);
      await admin.end();
    }
  });
});
