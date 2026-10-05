-- NULL on rows written before this migration. Those tokens stay valid but can't be exchanged.
ALTER TABLE tokens ADD COLUMN client_id TEXT;
