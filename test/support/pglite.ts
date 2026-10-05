import { readdir, readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { PGlite } from "@electric-sql/pglite";
import type { Queryable, QueryResult } from "../../src/store/postgres/queryable.js";

const MIGRATIONS_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "migrations");

function pgliteQueryable(pglite: PGlite): Queryable {
  return {
    query<Row = Record<string, unknown>>(text: string, params?: unknown[]): Promise<QueryResult<Row>> {
      return pglite.query<Row>(text, params);
    },
    transaction<T>(fn: (tx: Queryable) => Promise<T>): Promise<T> {
      return pglite.transaction(async (tx) =>
        fn({
          query<Row = Record<string, unknown>>(text: string, params?: unknown[]): Promise<QueryResult<Row>> {
            return tx.query<Row>(text, params);
          },
          transaction<T2>(_fn: (inner: Queryable) => Promise<T2>): Promise<T2> {
            throw new Error("nested transactions are not supported");
          }
        })
      );
    }
  };
}

export interface PgliteHandle {
  db: Queryable;
  close: () => Promise<void>;
}

export async function createMigratedPglite(): Promise<PgliteHandle> {
  const pglite = new PGlite();

  const entries = await readdir(MIGRATIONS_DIR);
  const migrationFiles = entries.filter((name) => name.endsWith(".sql")).sort();

  for (const file of migrationFiles) {
    const sql = await readFile(join(MIGRATIONS_DIR, file), "utf-8");
    await pglite.exec(sql);
  }

  return {
    db: pgliteQueryable(pglite),
    close: () => pglite.close()
  };
}
