import { Pool } from "pg";

// Local development databases usually don't speak TLS. Anywhere else, require it
// and verify the server certificate. An sslmode in the connection string still wins.
function isLocal(connectionString: string): boolean {
  try {
    const { hostname } = new URL(connectionString);
    return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";
  } catch {
    return false;
  }
}

export function createPool(connectionString: string): Pool {
  return new Pool({ connectionString, ssl: isLocal(connectionString) ? undefined : true });
}
