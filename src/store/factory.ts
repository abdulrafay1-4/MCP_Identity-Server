import type { Pool } from "pg";
import { createPool } from "./postgres/pool.js";
import { runMigrations } from "./postgres/migrate.js";
import { PgTokenStore } from "./postgres/pgStore.js";
import { poolQueryable } from "./postgres/poolQueryable.js";
import { MemoryTokenStore } from "./memory.js";
import type { TokenStore } from "./types.js";

export interface CreateStoreOptions {
  databaseUrl?: string;
  now?: () => Date;
}

export interface StoreBundle {
  store: TokenStore;
  pruneExpired: () => Promise<void>;
  close: () => Promise<void>;
}

export async function createStore(options: CreateStoreOptions = {}): Promise<StoreBundle> {
  if (options.databaseUrl) {
    const pool: Pool = createPool(options.databaseUrl);
    await runMigrations(pool);
    const store = new PgTokenStore(poolQueryable(pool), { now: options.now });
    return {
      store,
      pruneExpired: () => store.pruneExpired(),
      close: () => pool.end()
    };
  }

  const store = new MemoryTokenStore({ now: options.now });
  return {
    store,
    pruneExpired: () => store.pruneExpired(),
    close: () => Promise.resolve()
  };
}
