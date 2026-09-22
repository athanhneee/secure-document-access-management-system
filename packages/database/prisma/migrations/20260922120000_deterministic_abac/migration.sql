CREATE SEQUENCE abac_policy_version_seq AS BIGINT START WITH 1 INCREMENT BY 1 NO CYCLE;

ALTER TABLE attribute_definitions
  ADD COLUMN version BIGINT NOT NULL DEFAULT nextval('abac_policy_version_seq');

ALTER TABLE policy_rules
  ADD COLUMN obligations JSONB NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN version BIGINT NOT NULL DEFAULT nextval('abac_policy_version_seq'),
  ADD CONSTRAINT ck_policy_rule_obligations_array CHECK (jsonb_typeof(obligations) = 'array');

CREATE OR REPLACE FUNCTION bump_abac_row_version()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    PERFORM nextval('abac_policy_version_seq');
    RETURN OLD;
  END IF;
  IF NEW.version IS DISTINCT FROM OLD.version
    OR (to_jsonb(NEW) - 'updated_at' - 'version')
      IS DISTINCT FROM (to_jsonb(OLD) - 'updated_at' - 'version') THEN
    NEW.version := nextval('abac_policy_version_seq');
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_attribute_definitions_version
BEFORE UPDATE OR DELETE ON attribute_definitions
FOR EACH ROW EXECUTE FUNCTION bump_abac_row_version();

CREATE TRIGGER trg_policy_rules_version
BEFORE UPDATE OR DELETE ON policy_rules
FOR EACH ROW EXECUTE FUNCTION bump_abac_row_version();

CREATE OR REPLACE FUNCTION bump_abac_parent_version()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  parent_id BIGINT;
BEGIN
  IF TG_OP = 'UPDATE' AND to_jsonb(NEW) IS NOT DISTINCT FROM to_jsonb(OLD) THEN
    RETURN NEW;
  END IF;
  IF TG_TABLE_NAME = 'attribute_options' THEN
    IF TG_OP = 'UPDATE' AND OLD.attribute_definition_id <> NEW.attribute_definition_id THEN
      UPDATE attribute_definitions
      SET version = nextval('abac_policy_version_seq')
      WHERE id = OLD.attribute_definition_id;
    END IF;
    parent_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.attribute_definition_id ELSE NEW.attribute_definition_id END;
    UPDATE attribute_definitions
    SET version = nextval('abac_policy_version_seq')
    WHERE id = parent_id;
  ELSE
    IF TG_OP = 'UPDATE' AND OLD.policy_rule_id <> NEW.policy_rule_id THEN
      UPDATE policy_rules
      SET version = nextval('abac_policy_version_seq')
      WHERE id = OLD.policy_rule_id;
    END IF;
    parent_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.policy_rule_id ELSE NEW.policy_rule_id END;
    UPDATE policy_rules
    SET version = nextval('abac_policy_version_seq')
    WHERE id = parent_id;
  END IF;
  IF TG_OP = 'DELETE' THEN
    RETURN OLD;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_attribute_options_version
AFTER INSERT OR UPDATE OR DELETE ON attribute_options
FOR EACH ROW EXECUTE FUNCTION bump_abac_parent_version();

CREATE TRIGGER trg_policy_rule_conditions_version
AFTER INSERT OR UPDATE OR DELETE ON policy_rule_conditions
FOR EACH ROW EXECUTE FUNCTION bump_abac_parent_version();
