import { createHash } from "node:crypto";

/**
 * For server-generated random secrets (codes, refresh tokens), so a fast unsalted hash is
 * enough. The point is that reading the database doesn't hand out usable credentials.
 */
export function sha256Hex(value: string): string {
  return createHash("sha256").update(value, "utf-8").digest("hex");
}
