import { sha256Hex } from "../../hash.js";
import type {
  AuditEntry,
  AuthorizationCode,
  RefreshFamilyRevocationResult,
  RefreshTokenRecord,
  RevocationResult,
  StoredRefreshTokenRecord,
  StoredTokenRecord,
  TokenRecord,
  TokenStore
} from "../types.js";
import type { Queryable } from "./queryable.js";

export interface PgTokenStoreOptions {
  now?: () => Date;
}

interface AuthCodeRow {
  client_id: string;
  redirect_uri: string;
  code_challenge: string;
  code_challenge_method: string;
  scope: string;
  sub: string;
  aud: string;
  exp: string; // BIGINT arrives as a string from node-postgres
}

interface TokenRow {
  jti: string;
  sub: string | null;
  aud: string | null;
  scope: string | null;
  exp: string;
  issued_at: string | null;
  parent_jti: string | null;
  depth: number;
  revoked_at: Date | null;
  family_id: string | null;
  client_id: string | null;
}

function mapTokenRow(row: TokenRow): StoredTokenRecord {
  return {
    jti: row.jti,
    exp: Number(row.exp),
    issuedAt: row.issued_at === null ? null : Number(row.issued_at),
    sub: row.sub,
    aud: row.aud,
    scope: row.scope,
    parentJti: row.parent_jti,
    depth: row.depth,
    revoked: row.revoked_at !== null,
    familyId: row.family_id,
    clientId: row.client_id
  };
}

interface AuditLogRow {
  event_type: string;
  subject: string | null;
  metadata: unknown; // pg parses JSONB, pglite may hand back text
  created_at: Date;
}

function parseMetadata(raw: unknown): Record<string, unknown> | null {
  if (raw === null || raw === undefined) {
    return null;
  }
  if (typeof raw === "string") {
    try {
      return JSON.parse(raw) as Record<string, unknown>;
    } catch {
      return null;
    }
  }
  if (typeof raw === "object") {
    return raw as Record<string, unknown>;
  }
  return null;
}

interface RefreshTokenRow {
  token_hash: string;
  family_id: string;
  jti: string | null;
  rotated_from: string | null;
  exp: string;
  sub: string | null;
  aud: string | null;
  scope: string | null;
  client_id: string | null;
  consumed_at: Date | null;
  revoked_at: Date | null;
  graced_at: Date | null;
}

function mapRefreshTokenRow(row: RefreshTokenRow): StoredRefreshTokenRecord {
  return {
    tokenHash: row.token_hash,
    familyId: row.family_id,
    jti: row.jti,
    rotatedFrom: row.rotated_from,
    exp: Number(row.exp),
    sub: row.sub,
    aud: row.aud,
    scope: row.scope,
    clientId: row.client_id,
    consumedAt: row.consumed_at,
    revokedAt: row.revoked_at,
    gracedAt: row.graced_at
  };
}

const REFRESH_TOKEN_COLUMNS = "token_hash, family_id, jti, rotated_from, exp, sub, aud, scope, client_id, consumed_at, revoked_at, graced_at";

const TOKEN_COLUMNS = "jti, sub, aud, scope, exp, issued_at, parent_jti, depth, revoked_at, family_id, client_id";
const TOKEN_COLUMNS_T = TOKEN_COLUMNS.split(", ")
  .map((column) => `t.${column}`)
  .join(", ");

export class PgTokenStore implements TokenStore {
  private readonly pool: Queryable;
  private readonly now: () => Date;

  constructor(pool: Queryable, options: PgTokenStoreOptions = {}) {
    this.pool = pool;
    this.now = options.now ?? (() => new Date());
  }

  private nowSeconds(): number {
    return Math.floor(this.now().getTime() / 1000);
  }

  async record(record: TokenRecord): Promise<void> {
    await this.pool.query(
      `INSERT INTO tokens (jti, sub, aud, scope, exp, issued_at, parent_jti, depth, family_id, client_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       ON CONFLICT (jti) DO UPDATE SET
         sub = excluded.sub,
         aud = excluded.aud,
         scope = excluded.scope,
         exp = excluded.exp,
         issued_at = excluded.issued_at,
         parent_jti = excluded.parent_jti,
         depth = excluded.depth,
         family_id = excluded.family_id,
         client_id = excluded.client_id`,
      [
        record.jti,
        record.sub ?? null,
        record.aud ?? null,
        record.scope ?? null,
        record.exp,
        record.issuedAt ?? null,
        record.parentJti ?? null,
        record.depth ?? 0,
        record.familyId ?? null,
        record.clientId ?? null
      ]
    );
  }

  /**
   * Revoked if the token or any ancestor is. revoke() marks the subtree eagerly; this also
   * catches a child inserted while that walk was running. Expiry is only checked on the
   * token itself, since exp(child) <= exp(parent).
   */
  async isRevoked(jti: string): Promise<boolean> {
    const chain = await this.getChain(jti);
    const self = chain[chain.length - 1];
    if (self === undefined || self.jti !== jti) {
      return false;
    }
    if (self.exp <= this.nowSeconds()) {
      return false;
    }
    return chain.some((link) => link.revoked);
  }

  private async queryDescendants(executor: Queryable, jti: string): Promise<StoredTokenRecord[]> {
    const result = await executor.query<TokenRow>(
      `WITH RECURSIVE descendants AS (
         SELECT ${TOKEN_COLUMNS}
         FROM tokens
         WHERE parent_jti = $1
         UNION ALL
         SELECT ${TOKEN_COLUMNS_T}
         FROM tokens t
         JOIN descendants d ON t.parent_jti = d.jti
       )
       SELECT * FROM descendants`,
      [jti]
    );
    return result.rows.map(mapTokenRow);
  }

  async getDescendants(jti: string): Promise<StoredTokenRecord[]> {
    return this.queryDescendants(this.pool, jti);
  }

  async revoke(jti: string): Promise<RevocationResult> {
    const result = await this.revokeSubtree(jti);
    if (!result) {
      return { descendantCount: 0 };
    }
    if (result.familyId !== null) {
      await this.revokeRefreshFamily(result.familyId);
    }
    return { descendantCount: result.descendantCount };
  }

  private async revokeSubtree(jti: string): Promise<{ descendantCount: number; familyId: string | null } | undefined> {
    return this.pool.transaction(async (tx) => {
      const targetResult = await tx.query<{ jti: string; family_id: string | null }>(
        `SELECT jti, family_id FROM tokens WHERE jti = $1 FOR UPDATE`,
        [jti]
      );
      const target = targetResult.rows[0];
      if (target === undefined) {
        return undefined;
      }

      const descendants = await this.queryDescendants(tx, jti);
      const descendantJtis = descendants.map((descendant) => descendant.jti);

      if (descendantJtis.length > 0) {
        await tx.query(`SELECT jti FROM tokens WHERE jti = ANY($1) FOR UPDATE`, [descendantJtis]);
      }

      const allJtis = [jti, ...descendantJtis];
      await tx.query(`UPDATE tokens SET revoked_at = now() WHERE jti = ANY($1) AND revoked_at IS NULL`, [allJtis]);

      await tx.query(`INSERT INTO audit_log (event_type, subject, metadata) VALUES ($1, $2, $3)`, [
        "revoke",
        jti,
        JSON.stringify({ descendant_count: descendantJtis.length })
      ]);

      return { descendantCount: descendantJtis.length, familyId: target.family_id };
    });
  }

  async getAuditLog(subject: string): Promise<AuditEntry[]> {
    const result = await this.pool.query<AuditLogRow>(
      `SELECT event_type, subject, metadata, created_at
       FROM audit_log
       WHERE subject = $1
       ORDER BY created_at DESC, id DESC`,
      [subject]
    );
    return result.rows.map((row) => ({
      eventType: row.event_type,
      subject: row.subject,
      metadata: parseMetadata(row.metadata),
      createdAt: row.created_at
    }));
  }

  async getRecord(jti: string): Promise<StoredTokenRecord | undefined> {
    const result = await this.pool.query<TokenRow>(
      `SELECT ${TOKEN_COLUMNS} FROM tokens WHERE jti = $1`,
      [jti]
    );
    const row = result.rows[0];
    return row === undefined ? undefined : mapTokenRow(row);
  }

  async getChain(jti: string): Promise<StoredTokenRecord[]> {
    const result = await this.pool.query<TokenRow>(
      `WITH RECURSIVE chain AS (
         SELECT ${TOKEN_COLUMNS}
         FROM tokens
         WHERE jti = $1
         UNION ALL
         SELECT ${TOKEN_COLUMNS_T}
         FROM tokens t
         JOIN chain c ON t.jti = c.parent_jti
       )
       SELECT * FROM chain ORDER BY depth ASC`,
      [jti]
    );
    return result.rows.map(mapTokenRow);
  }

  async storeAuthorizationCode(authorizationCode: AuthorizationCode): Promise<void> {
    const codeHash = sha256Hex(authorizationCode.code);
    await this.pool.query(
      `INSERT INTO auth_codes
         (code_hash, client_id, redirect_uri, code_challenge, code_challenge_method, scope, sub, aud, exp)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       ON CONFLICT (code_hash) DO NOTHING`,
      [
        codeHash,
        authorizationCode.clientId,
        authorizationCode.redirectUri,
        authorizationCode.codeChallenge,
        authorizationCode.codeChallengeMethod,
        authorizationCode.scope,
        authorizationCode.sub,
        authorizationCode.aud,
        authorizationCode.exp
      ]
    );
  }

  /**
   * One UPDATE ... RETURNING, so only one of two concurrent calls gets the row.
   * SELECT then UPDATE would race.
   */
  async consumeAuthorizationCode(code: string): Promise<AuthorizationCode | undefined> {
    const codeHash = sha256Hex(code);

    const result = await this.pool.query<AuthCodeRow>(
      `UPDATE auth_codes
       SET consumed_at = now()
       WHERE code_hash = $1 AND consumed_at IS NULL AND exp > $2
       RETURNING client_id, redirect_uri, code_challenge, code_challenge_method, scope, sub, aud, exp`,
      [codeHash, this.nowSeconds()]
    );

    const row = result.rows[0];
    if (!row) {
      return undefined;
    }

    if (row.code_challenge_method !== "S256") {
      throw new Error(`Unexpected code_challenge_method in storage: ${row.code_challenge_method}`);
    }

    return {
      code,
      clientId: row.client_id,
      redirectUri: row.redirect_uri,
      codeChallenge: row.code_challenge,
      codeChallengeMethod: row.code_challenge_method,
      scope: row.scope,
      sub: row.sub,
      aud: row.aud,
      exp: Number(row.exp)
    };
  }

  // Refresh timestamps come from the injected clock rather than SQL now(), so the grace
  // window follows the same clock as every other expiry check.
  async recordRefreshToken(record: RefreshTokenRecord): Promise<void> {
    await this.pool.query(
      `INSERT INTO refresh_tokens (token_hash, family_id, jti, rotated_from, exp, sub, aud, scope, client_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [
        record.tokenHash,
        record.familyId,
        record.jti,
        record.rotatedFrom ?? null,
        record.exp,
        record.sub,
        record.aud,
        record.scope,
        record.clientId
      ]
    );
  }

  async getRefreshTokenRecord(tokenHash: string): Promise<StoredRefreshTokenRecord | undefined> {
    const result = await this.pool.query<RefreshTokenRow>(
      `SELECT ${REFRESH_TOKEN_COLUMNS} FROM refresh_tokens WHERE token_hash = $1`,
      [tokenHash]
    );
    const row = result.rows[0];
    return row === undefined ? undefined : mapRefreshTokenRow(row);
  }

  async consumeRefreshToken(tokenHash: string): Promise<StoredRefreshTokenRecord | undefined> {
    const result = await this.pool.query<RefreshTokenRow>(
      `UPDATE refresh_tokens
       SET consumed_at = $2
       WHERE token_hash = $1 AND consumed_at IS NULL AND revoked_at IS NULL AND exp > $3
       RETURNING ${REFRESH_TOKEN_COLUMNS}`,
      [tokenHash, this.now(), this.nowSeconds()]
    );
    const row = result.rows[0];
    return row === undefined ? undefined : mapRefreshTokenRow(row);
  }

  /**
   * Succeeds once per generation, and only for a row that was rotated, never graced,
   * not revoked and is still inside the window.
   */
  async graceRedeemRefreshToken(tokenHash: string, graceWindowSeconds: number): Promise<StoredRefreshTokenRecord | undefined> {
    const result = await this.pool.query<RefreshTokenRow>(
      `UPDATE refresh_tokens
       SET graced_at = $2
       WHERE token_hash = $1
         AND consumed_at IS NOT NULL
         AND graced_at IS NULL
         AND revoked_at IS NULL
         AND EXTRACT(EPOCH FROM ($2::timestamptz - consumed_at)) <= $3
       RETURNING ${REFRESH_TOKEN_COLUMNS}`,
      [tokenHash, this.now(), graceWindowSeconds]
    );
    const row = result.rows[0];
    return row === undefined ? undefined : mapRefreshTokenRow(row);
  }

  async revokeRefreshFamily(familyId: string): Promise<RefreshFamilyRevocationResult> {
    const refreshResult = await this.pool.query<{ token_hash: string }>(
      `UPDATE refresh_tokens SET revoked_at = $2 WHERE family_id = $1 AND revoked_at IS NULL RETURNING token_hash`,
      [familyId, this.now()]
    );
    const refreshTokensRevoked = refreshResult.rows.length;

    const tokenResult = await this.pool.query<{ jti: string }>(
      `SELECT jti FROM tokens WHERE family_id = $1 AND revoked_at IS NULL`,
      [familyId]
    );
    let accessTokensRevoked = 0;
    for (const { jti } of tokenResult.rows) {
      const revocation = await this.revokeSubtree(jti);
      accessTokensRevoked += 1 + (revocation?.descendantCount ?? 0);
    }

    await this.recordAuditEvent("refresh_family_revoked", familyId, {
      access_tokens_revoked: accessTokensRevoked,
      refresh_tokens_revoked: refreshTokensRevoked
    });

    return { accessTokensRevoked, refreshTokensRevoked };
  }

  async recordAuditEvent(eventType: string, subject: string | null, metadata: Record<string, unknown> | null = null): Promise<void> {
    await this.pool.query(`INSERT INTO audit_log (event_type, subject, metadata) VALUES ($1, $2, $3)`, [
      eventType,
      subject,
      metadata === null ? null : JSON.stringify(metadata)
    ]);
  }

  async pruneExpired(): Promise<void> {
    const nowSeconds = this.nowSeconds();
    await this.pool.query(`DELETE FROM tokens WHERE exp <= $1`, [nowSeconds]);
    await this.pool.query(`DELETE FROM auth_codes WHERE exp <= $1`, [nowSeconds]);
    await this.pool.query(`DELETE FROM refresh_tokens WHERE exp <= $1`, [nowSeconds]);
  }
}
