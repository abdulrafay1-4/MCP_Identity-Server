import type { Pool } from "pg";
import type { Queryable, QueryResult } from "./queryable.js";

/**
 * Adds transaction(), which runs on one checked-out client. pool.query() may use a
 * different connection per statement, which would make FOR UPDATE meaningless.
 */
export function poolQueryable(pool: Pool): Queryable {
  return {
    async query<Row = Record<string, unknown>>(text: string, params?: unknown[]): Promise<QueryResult<Row>> {
      const result = await pool.query(text, params);
      return result as unknown as QueryResult<Row>;
    },

    async transaction<T>(fn: (tx: Queryable) => Promise<T>): Promise<T> {
      const client = await pool.connect();
      const tx: Queryable = {
        async query<Row = Record<string, unknown>>(text: string, params?: unknown[]): Promise<QueryResult<Row>> {
          const result = await client.query(text, params);
          return result as unknown as QueryResult<Row>;
        },
        transaction<T2>(_fn: (inner: Queryable) => Promise<T2>): Promise<T2> {
          throw new Error("nested transactions are not supported");
        }
      };
      try {
        await client.query("BEGIN");
        const result = await fn(tx);
        await client.query("COMMIT");
        return result;
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        client.release();
      }
    }
  };
}
