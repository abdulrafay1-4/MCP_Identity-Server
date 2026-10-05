-- A refresh token must outlive its access token. The FK cascaded deletes, so pruning an
-- expired access token deleted the refresh token and the record that its family was revoked.
ALTER TABLE refresh_tokens DROP CONSTRAINT refresh_tokens_jti_fkey;

ALTER TABLE refresh_tokens
  ADD COLUMN sub       TEXT,
  ADD COLUMN aud       TEXT,
  ADD COLUMN scope     TEXT,
  ADD COLUMN client_id TEXT;

-- Lets a family revocation reach every access token in it, including ones issued
-- without a refresh token of their own.
ALTER TABLE tokens ADD COLUMN family_id TEXT;
CREATE INDEX idx_tokens_family_id ON tokens (family_id);
UPDATE tokens t SET family_id = r.family_id FROM refresh_tokens r WHERE r.jti = t.jti;
