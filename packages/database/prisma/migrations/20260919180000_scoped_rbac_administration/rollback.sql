DROP TRIGGER IF EXISTS trg_prevent_department_cycle ON departments;
DROP FUNCTION IF EXISTS prevent_department_cycle();
ALTER TABLE users DROP COLUMN IF EXISTS version;
ALTER TABLE roles DROP COLUMN IF EXISTS version;
ALTER TABLE departments DROP COLUMN IF EXISTS version;
