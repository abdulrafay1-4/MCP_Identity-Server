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
} from "./types.js";

export interface MemoryTokenStoreOptions {
  now?: () => Date;
}

interface StoredToken {
  exp: number;
  revoked: boolean;
  issuedAt: number | null;
  sub: string | null;
  aud: string | null;
  scope: string | null;
  parentJti: string | null;
  depth: number;
  familyId: string | null;
  clientId: string | null;
}

function toStoredTokenRecord(jti: string, stored: StoredToken): StoredTokenRecord {
  return {
    jti,
    exp: stored.exp,
    issuedAt: stored.issuedAt,
    sub: stored.sub,
    aud: stored.aud,
    scope: stored.scope,
    parentJti: stored.parentJti,
    depth: stored.depth,
    revoked: stored.revoked,
    familyId: stored.familyId,
    clientId: stored.clientId
  };
}

interface StoredRefreshToken {
  familyId: string;
  jti: string;
  rotatedFrom: string | null;
  exp: number;
  sub: string;
  aud: string;
  scope: string;
  clientId: string;
  consumedAt: Date | null;
  revokedAt: Date | null;
  gracedAt: Date | null;
}

function toStoredRefreshTokenRecord(tokenHash: string, stored: StoredRefreshToken): StoredRefreshTokenRecord {
  return {
    tokenHash,
    familyId: stored.familyId,
    jti: stored.jti,
    rotatedFrom: stored.rotatedFrom,
    exp: stored.exp,
    sub: stored.sub,
    aud: stored.aud,
    scope: stored.scope,
    clientId: stored.clientId,
    consumedAt: stored.consumedAt,
    revokedAt: stored.revokedAt,
    gracedAt: stored.gracedAt
  };
}

export class MemoryTokenStore implements TokenStore {
  private readonly now: () => Date;
  private readonly tokens = new Map<string, StoredToken>();
  private readonly authorizationCodes = new Map<string, AuthorizationCode>();
  private readonly refreshTokens = new Map<string, StoredRefreshToken>();
  private readonly audit: AuditEntry[] = [];

  constructor(options: MemoryTokenStoreOptions = {}) {
    this.now = options.now ?? (() => new Date());
  }

  get size(): number {
    return this.tokens.size;
  }

  async record(record: TokenRecord): Promise<void> {
    await this.pruneExpired();

    // Same rule the Postgres trigger enforces: a token can never become its own ancestor.
    if (record.parentJti !== undefined) {
      if (record.parentJti === record.jti) {
        throw new Error(`token ${record.jti} cannot be its own parent`);
      }
      let currentJti: string | undefined = record.parentJti;
      const seen = new Set<string>();
      while (currentJti !== undefined && !seen.has(currentJti)) {
        if (currentJti === record.jti) {
          throw new Error(`recording ${record.jti} with parent ${record.parentJti} would create a delegation cycle`);
        }
        seen.add(currentJti);
        currentJti = this.tokens.get(currentJti)?.parentJti ?? undefined;
      }
    }

    this.tokens.set(record.jti, {
      exp: record.exp,
      revoked: false,
      issuedAt: record.issuedAt ?? null,
      sub: record.sub ?? null,
      aud: record.aud ?? null,
      scope: record.scope ?? null,
      parentJti: record.parentJti ?? null,
      depth: record.depth ?? 0,
      familyId: record.familyId ?? null,
      clientId: record.clientId ?? null
    });
  }

  /**
   * Revoked if the token or any ancestor is. Expiry is only checked on the token itself,
   * since exp(child) <= exp(parent).
   */
  async isRevoked(jti: string): Promise<boolean> {
    await this.pruneExpired();
    const chain = await this.getChain(jti);
    const self = chain[chain.length - 1];
    if (self === undefined || self.jti !== jti) {
      return false;
    }
    const nowSeconds = Math.floor(this.now().getTime() / 1000);
    if (self.exp <= nowSeconds) {
      return false;
    }
    return chain.some((link) => link.revoked);
  }

  async revoke(jti: string): Promise<RevocationResult> {
    await this.pruneExpired();
    const result = this.revokeSubtree(jti);
    if (!result) {
      return { descendantCount: 0 };
    }
    if (result.familyId !== null) {
      await this.revokeRefreshFamily(result.familyId);
    }
    return { descendantCount: result.descendantCount };
  }

  private revokeSubtree(jti: string): { descendantCount: number; familyId: string | null } | undefined {
    const target = this.tokens.get(jti);
    if (!target) {
      return undefined;
    }

    const descendantJtis: string[] = [];
    const frontier: string[] = [jti];
    while (frontier.length > 0) {
      const current = frontier.shift();
      if (current === undefined) {
        break;
      }
      for (const [candidateJti, candidate] of this.tokens) {
        if (candidate.parentJti === current) {
          descendantJtis.push(candidateJti);
          frontier.push(candidateJti);
        }
      }
    }

    target.revoked = true;
    for (const descendantJti of descendantJtis) {
      const descendant = this.tokens.get(descendantJti);
      if (descendant) {
        descendant.revoked = true;
      }
    }

    this.audit.unshift({
      eventType: "revoke",
      subject: jti,
      metadata: { descendant_count: descendantJtis.length },
      createdAt: this.now()
    });

    return { descendantCount: descendantJtis.length, familyId: target.familyId };
  }

  async getDescendants(jti: string): Promise<StoredTokenRecord[]> {
    await this.pruneExpired();
    const descendants: StoredTokenRecord[] = [];
    const frontier: string[] = [jti];
    while (frontier.length > 0) {
      const current = frontier.shift();
      if (current === undefined) {
        break;
      }
      for (const [candidateJti, candidate] of this.tokens) {
        if (candidate.parentJti === current) {
          descendants.push(toStoredTokenRecord(candidateJti, candidate));
          frontier.push(candidateJti);
        }
      }
    }
    return descendants;
  }

  async getAuditLog(subject: string): Promise<AuditEntry[]> {
    return this.audit.filter((entry) => entry.subject === subject);
  }

  async getRecord(jti: string): Promise<StoredTokenRecord | undefined> {
    await this.pruneExpired();
    const stored = this.tokens.get(jti);
    return stored ? toStoredTokenRecord(jti, stored) : undefined;
  }

  async getChain(jti: string): Promise<StoredTokenRecord[]> {
    await this.pruneExpired();
    const chain: StoredTokenRecord[] = [];
    const seen = new Set<string>();
    let currentJti: string | undefined = jti;

    while (currentJti !== undefined && !seen.has(currentJti)) {
      seen.add(currentJti);
      const stored: StoredToken | undefined = this.tokens.get(currentJti);
      if (!stored) {
        break;
      }
      chain.push(toStoredTokenRecord(currentJti, stored));
      currentJti = stored.parentJti ?? undefined;
    }

    return chain.reverse();
  }

  async storeAuthorizationCode(authorizationCode: AuthorizationCode): Promise<void> {
    await this.pruneExpired();
    this.authorizationCodes.set(authorizationCode.code, authorizationCode);
  }

  async consumeAuthorizationCode(code: string): Promise<AuthorizationCode | undefined> {
    await this.pruneExpired();
    const record = this.authorizationCodes.get(code);
    if (!record) {
      return undefined;
    }
    // Nothing awaits before the delete, so overlapping calls can't both succeed.
    this.authorizationCodes.delete(code);
    return record;
  }

  async recordRefreshToken(record: RefreshTokenRecord): Promise<void> {
    await this.pruneExpired();
    this.refreshTokens.set(record.tokenHash, {
      familyId: record.familyId,
      jti: record.jti,
      rotatedFrom: record.rotatedFrom ?? null,
      exp: record.exp,
      sub: record.sub,
      aud: record.aud,
      scope: record.scope,
      clientId: record.clientId,
      consumedAt: null,
      revokedAt: null,
      gracedAt: null
    });
  }

  async getRefreshTokenRecord(tokenHash: string): Promise<StoredRefreshTokenRecord | undefined> {
    await this.pruneExpired();
    const stored = this.refreshTokens.get(tokenHash);
    return stored ? toStoredRefreshTokenRecord(tokenHash, stored) : undefined;
  }

  async consumeRefreshToken(tokenHash: string): Promise<StoredRefreshTokenRecord | undefined> {
    await this.pruneExpired();
    const stored = this.refreshTokens.get(tokenHash);
    if (!stored) {
      return undefined;
    }
    const nowSeconds = Math.floor(this.now().getTime() / 1000);
    if (stored.consumedAt !== null || stored.revokedAt !== null || stored.exp <= nowSeconds) {
      return undefined;
    }
    stored.consumedAt = this.now();
    return toStoredRefreshTokenRecord(tokenHash, stored);
  }

  async graceRedeemRefreshToken(tokenHash: string, graceWindowSeconds: number): Promise<StoredRefreshTokenRecord | undefined> {
    const stored = this.refreshTokens.get(tokenHash);
    if (!stored) {
      return undefined;
    }
    if (stored.consumedAt === null || stored.gracedAt !== null || stored.revokedAt !== null) {
      return undefined;
    }
    const elapsedSeconds = (this.now().getTime() - stored.consumedAt.getTime()) / 1000;
    if (elapsedSeconds > graceWindowSeconds) {
      return undefined;
    }
    stored.gracedAt = this.now();
    return toStoredRefreshTokenRecord(tokenHash, stored);
  }

  async revokeRefreshFamily(familyId: string): Promise<RefreshFamilyRevocationResult> {
    let accessTokensRevoked = 0;
    let refreshTokensRevoked = 0;

    for (const stored of this.refreshTokens.values()) {
      if (stored.familyId === familyId && stored.revokedAt === null) {
        stored.revokedAt = this.now();
        refreshTokensRevoked += 1;
      }
    }

    for (const [jti, token] of this.tokens) {
      if (token.familyId === familyId && !token.revoked) {
        const result = this.revokeSubtree(jti);
        accessTokensRevoked += 1 + (result?.descendantCount ?? 0);
      }
    }

    await this.recordAuditEvent("refresh_family_revoked", familyId, {
      access_tokens_revoked: accessTokensRevoked,
      refresh_tokens_revoked: refreshTokensRevoked
    });

    return { accessTokensRevoked, refreshTokensRevoked };
  }

  async recordAuditEvent(eventType: string, subject: string | null, metadata: Record<string, unknown> | null = null): Promise<void> {
    this.audit.unshift({ eventType, subject, metadata, createdAt: this.now() });
  }

  async pruneExpired(): Promise<void> {
    const nowSeconds = Math.floor(this.now().getTime() / 1000);

    for (const [jti, record] of this.tokens) {
      if (record.exp <= nowSeconds) {
        this.tokens.delete(jti);
      }
    }

    for (const [code, record] of this.authorizationCodes) {
      if (record.exp <= nowSeconds) {
        this.authorizationCodes.delete(code);
      }
    }

    for (const [hash, record] of this.refreshTokens) {
      if (record.exp <= nowSeconds) {
        this.refreshTokens.delete(hash);
      }
    }
  }
}
