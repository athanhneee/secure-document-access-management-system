ALTER TABLE departments ADD COLUMN version INTEGER NOT NULL DEFAULT 0;
ALTER TABLE roles ADD COLUMN version INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN version INTEGER NOT NULL DEFAULT 0;

CREATE OR REPLACE FUNCTION prevent_department_cycle()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.parent_id IS NULL THEN
    RETURN NEW;
  END IF;
  IF NEW.id IS NOT NULL AND NEW.parent_id = NEW.id THEN
    RAISE EXCEPTION 'department cannot be its own parent' USING ERRCODE = '23514';
  END IF;
  IF NEW.id IS NOT NULL AND EXISTS (
    WITH RECURSIVE descendants AS (
      SELECT id FROM departments WHERE parent_id = NEW.id
      UNION ALL
      SELECT d.id FROM departments d JOIN descendants x ON d.parent_id = x.id
    )
    SELECT 1 FROM descendants WHERE id = NEW.parent_id
  ) THEN
    RAISE EXCEPTION 'department hierarchy cycle detected' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_prevent_department_cycle
BEFORE INSERT OR UPDATE OF parent_id ON departments
FOR EACH ROW EXECUTE FUNCTION prevent_department_cycle();
