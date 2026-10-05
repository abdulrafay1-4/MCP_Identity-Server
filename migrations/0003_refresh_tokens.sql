-- consumed_at: rotated normally. revoked_at: the family was revoked. graced_at: the one
-- tolerated replay inside the grace window was used. Reuse detection needs to tell
-- these apart, so each gets its own column.
ALTER TABLE refresh_tokens ADD COLUMN revoked_at TIMESTAMPTZ;

CREATE INDEX idx_refresh_tokens_family_id_revoked_at ON refresh_tokens (family_id, revoked_at);

ALTER TABLE refresh_tokens ADD COLUMN graced_at TIMESTAMPTZ;
