-- Initial-deployment rollback only. Production rollback is forward-fix or restore from backup.
-- Run only before the database accepts business data; this script intentionally drops all 31 tables.
BEGIN;

DROP TABLE IF EXISTS
  alert_audit_links,
  incident_actions,
  incident_reports,
  notifications,
  security_alerts,
  watermark_instances,
  audit_logs,
  access_sessions,
  access_grant_permissions,
  access_grants,
  access_request_decisions,
  access_request_permissions,
  access_requests,
  document_classification_history,
  watermark_configs,
  document_versions,
  documents,
  business_categories,
  classification_levels,
  policy_rule_conditions,
  policy_rules,
  user_attribute_assignments,
  attribute_options,
  attribute_definitions,
  role_permissions,
  user_roles,
  permissions,
  roles,
  system_health_snapshots,
  users,
  departments
CASCADE;

DROP FUNCTION IF EXISTS prevent_audit_mutation();
DROP FUNCTION IF EXISTS validate_audit_chain_link();
DROP FUNCTION IF EXISTS validate_user_clearance_for_grant();
DROP FUNCTION IF EXISTS validate_current_document_version();
DROP FUNCTION IF EXISTS set_updated_at();

DROP TYPE IF EXISTS notification_status;
DROP TYPE IF EXISTS incident_status;
DROP TYPE IF EXISTS severity_level;
DROP TYPE IF EXISTS alert_status;
DROP TYPE IF EXISTS session_status;
DROP TYPE IF EXISTS grant_status;
DROP TYPE IF EXISTS grant_source;
DROP TYPE IF EXISTS principal_type;
DROP TYPE IF EXISTS permission_code;
DROP TYPE IF EXISTS request_status;
DROP TYPE IF EXISTS scan_status;
DROP TYPE IF EXISTS document_status;
DROP TYPE IF EXISTS policy_effect;
DROP TYPE IF EXISTS attribute_scope;
DROP TYPE IF EXISTS data_type;
DROP TYPE IF EXISTS user_status;

COMMIT;
