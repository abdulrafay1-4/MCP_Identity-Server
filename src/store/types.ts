export interface TokenRecord {
  jti: string;
  exp: number;
  sub?: string;
  aud?: string;
  scope?: string;
  issuedAt?: number;
  parentJti?: string;
  depth?: number;
  familyId?: string;
  clientId?: string;
}

export interface RevocationResult {
  descendantCount: number;
}

export interface RefreshTokenRecord {
  tokenHash: string;
  familyId: string;
  jti: string;
  rotatedFrom?: string;
  exp: number;
  sub: string;
  aud: string;
  scope: string;
  clientId: string;
}

export interface StoredRefreshTokenRecord {
  tokenHash: string;
  familyId: string;
  jti: string | null;
  rotatedFrom: string | null;
  exp: number;
  sub: string | null;
  aud: string | null;
  scope: string | null;
  clientId: string | null;
  consumedAt: Date | null;
  revokedAt: Date | null;
  gracedAt: Date | null;
}

export interface RefreshFamilyRevocationResult {
  accessTokensRevoked: number;
  refreshTokensRevoked: number;
}

export interface AuditEntry {
  eventType: string;
  subject: string | null;
  metadata: Record<string, unknown> | null;
  createdAt: Date;
}

export interface StoredTokenRecord {
  jti: string;
  exp: number;
  issuedAt: number | null;
  sub: string | null;
  aud: string | null;
  scope: string | null;
  parentJti: string | null;
  depth: number;
  revoked: boolean;
  familyId: string | null;
  clientId: string | null;
}

export interface AuthorizationCode {
  code: string;
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  codeChallengeMethod: "S256";
  scope: string;
  sub: string;
  aud: string;
  exp: number;
}

export interface TokenStore {
  record(record: TokenRecord): Promise<void>;

  /** True if the token or any ancestor is revoked. Unknown or expired jtis are not revoked. */
  isRevoked(jti: string): Promise<boolean>;

  /**
   * Revokes the token, its descendants and its refresh family, if any. An unknown jti is a
   * no-op (RFC 7009).
   */
  revoke(jti: string): Promise<RevocationResult>;

  getRecord(jti: string): Promise<StoredTokenRecord | undefined>;

  /** Root first; the last element is `jti` itself. */
  getChain(jti: string): Promise<StoredTokenRecord[]>;

  getDescendants(jti: string): Promise<StoredTokenRecord[]>;

  getAuditLog(subject: string): Promise<AuditEntry[]>;

  storeAuthorizationCode(authorizationCode: AuthorizationCode): Promise<void>;

  /** Must be atomic: two overlapping calls for one code get one success. */
  consumeAuthorizationCode(code: string): Promise<AuthorizationCode | undefined>;

  recordRefreshToken(record: RefreshTokenRecord): Promise<void>;

  /** Read-only, so a request that turns out to be invalid doesn't burn a good token. */
  getRefreshTokenRecord(tokenHash: string): Promise<StoredRefreshTokenRecord | undefined>;

  /** Atomic: only if not already consumed, revoked or expired. */
  consumeRefreshToken(tokenHash: string): Promise<StoredRefreshTokenRecord | undefined>;

  /**
   * One tolerated replay of an already-rotated token inside the window. Atomic, so racing
   * replays get at most one success.
   */
  graceRedeemRefreshToken(tokenHash: string, graceWindowSeconds: number): Promise<StoredRefreshTokenRecord | undefined>;

  revokeRefreshFamily(familyId: string): Promise<RefreshFamilyRevocationResult>;

  recordAuditEvent(eventType: string, subject: string | null, metadata?: Record<string, unknown> | null): Promise<void>;
}
