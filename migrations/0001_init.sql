-- Not used yet: the demo client is configured through the environment.
CREATE TABLE clients (
  id             TEXT PRIMARY KEY,
  hashed_secret  TEXT NOT NULL,
  redirect_uris  TEXT[] NOT NULL,
  allowed_scopes TEXT[] NOT NULL,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Codes, refresh tokens and client secrets are stored only as hashes.
CREATE TABLE auth_codes (
  code_hash             TEXT PRIMARY KEY,
  client_id             TEXT NOT NULL,
  redirect_uri          TEXT NOT NULL,
  code_challenge        TEXT NOT NULL,
  code_challenge_method TEXT NOT NULL DEFAULT 'S256' CHECK (code_challenge_method = 'S256'),
  scope                 TEXT NOT NULL,
  sub                   TEXT NOT NULL,
  aud                   TEXT NOT NULL,
  exp                   BIGINT NOT NULL,
  consumed_at           TIMESTAMPTZ,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_auth_codes_exp ON auth_codes (exp);

-- Metadata for each issued access token, never the token itself. parent_jti and depth
-- hold the delegation tree that revocation walks.
CREATE TABLE tokens (
  jti         TEXT PRIMARY KEY,
  sub         TEXT,
  aud         TEXT,
  scope       TEXT,
  exp         BIGINT NOT NULL,
  issued_at   BIGINT,
  parent_jti  TEXT REFERENCES tokens (jti) ON DELETE CASCADE,
  depth       INTEGER NOT NULL DEFAULT 0,
  revoked_at  TIMESTAMPTZ
);

CREATE INDEX idx_tokens_parent_jti ON tokens (parent_jti);
CREATE INDEX idx_tokens_exp ON tokens (exp);
-- Used by the recursive subtree walk on every level.
CREATE INDEX idx_tokens_parent_jti_revoked_at ON tokens (parent_jti, revoked_at);

CREATE TABLE refresh_tokens (
  token_hash    TEXT PRIMARY KEY,
  family_id     TEXT NOT NULL,
  jti           TEXT REFERENCES tokens (jti) ON DELETE CASCADE,
  rotated_from  TEXT REFERENCES refresh_tokens (token_hash) ON DELETE SET NULL,
  consumed_at   TIMESTAMPTZ,
  exp           BIGINT NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_refresh_tokens_family_id ON refresh_tokens (family_id);
CREATE INDEX idx_refresh_tokens_exp ON refresh_tokens (exp);
CREATE INDEX idx_refresh_tokens_jti ON refresh_tokens (jti);

-- Append-only, enforced by the triggers below. Identifiers and counts only, never a
-- token or secret.
CREATE TABLE audit_log (
  id             BIGSERIAL PRIMARY KEY,
  event_type     TEXT NOT NULL,
  subject        TEXT,
  client_id      TEXT,
  correlation_id TEXT,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_log_created_at ON audit_log (created_at);
CREATE INDEX idx_audit_log_subject ON audit_log (subject);

CREATE OR REPLACE FUNCTION audit_log_append_only() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_log is append-only: % is not permitted', TG_OP;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_log_no_update
  BEFORE UPDATE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION audit_log_append_only();

CREATE TRIGGER audit_log_no_delete
  BEFORE DELETE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION audit_log_append_only();
