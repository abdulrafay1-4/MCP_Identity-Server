export interface QueryResult<Row = Record<string, unknown>> {
  rows: Row[];
}

/**
 * What PgTokenStore needs from a driver. pg.Pool and PGlite both provide query();
 * transaction() needs a small adapter for each.
 */
export interface Queryable {
  query<Row = Record<string, unknown>>(text: string, params?: unknown[]): Promise<QueryResult<Row>>;

  transaction<T>(fn: (tx: Queryable) => Promise<T>): Promise<T>;
}
