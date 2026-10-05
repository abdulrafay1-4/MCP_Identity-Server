-- Counts and identifiers for an audit row, such as how many descendants a revoke reached.
ALTER TABLE audit_log ADD COLUMN metadata JSONB;

-- A delegation chain must never loop, or walking it would never end. A CHECK covers a
-- token that is its own parent; the trigger below covers longer cycles, which a CHECK
-- can't see because it can't read other rows.
ALTER TABLE tokens
  ADD CONSTRAINT tokens_no_self_parent CHECK (parent_jti IS NULL OR parent_jti <> jti);

CREATE OR REPLACE FUNCTION tokens_prevent_cycle() RETURNS trigger AS $$
DECLARE
  current_jti TEXT;
BEGIN
  IF NEW.parent_jti IS NULL THEN
    RETURN NEW;
  END IF;

  current_jti := NEW.parent_jti;
  WHILE current_jti IS NOT NULL LOOP
    IF current_jti = NEW.jti THEN
      RAISE EXCEPTION 'tokens.parent_jti would create a delegation cycle through %', NEW.jti;
    END IF;
    SELECT parent_jti INTO current_jti FROM tokens WHERE jti = current_jti;
  END LOOP;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER tokens_no_cycle
  BEFORE INSERT OR UPDATE OF parent_jti ON tokens
  FOR EACH ROW EXECUTE FUNCTION tokens_prevent_cycle();
