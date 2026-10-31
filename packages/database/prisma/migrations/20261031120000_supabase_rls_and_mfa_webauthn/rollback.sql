-- Rollback for 20261031120000_supabase_rls_and_mfa_webauthn
-- Note: PostgreSQL does not support removing individual enum values from mfa_method_type without recreating the type.

DROP INDEX IF EXISTS uq_access_grants_request;

DROP INDEX IF EXISTS uq_mfa_active_totp_per_user;
CREATE UNIQUE INDEX IF NOT EXISTS uq_mfa_active_totp_per_user
  ON mfa_methods(user_id, method_type)
  WHERE disabled_at IS NULL;

DO $$
DECLARE
  tbl TEXT;
BEGIN
  FOREACH tbl IN ARRAY ARRAY[
    'access_grant_permissions',
    'access_grants',
    'access_request_decisions',
    'access_request_permissions',
    'access_requests',
    'access_sessions',
    'alert_audit_links',
    'async_export_jobs',
    'attribute_definitions',
    'attribute_options',
    'audit_anchors',
    'audit_logs',
    'auth_sessions',
    'business_categories',
    'classification_levels',
    'departments',
    'detection_rule_configs',
    'document_classification_history',
    'document_versions',
    'documents',
    'incident_actions',
    'incident_reports',
    'mfa_methods',
    'notification_outbox',
    'notifications',
    'password_reset_tokens',
    'permissions',
    'policy_rule_conditions',
    'policy_rules',
    'refresh_tokens',
    'role_permissions',
    'roles',
    'security_alerts',
    'system_health_snapshots',
    'user_attribute_assignments',
    'user_roles',
    'users',
    'watermark_configs',
    'watermark_instances'
  ]
  LOOP
    EXECUTE format('ALTER TABLE public.%I DISABLE ROW LEVEL SECURITY', tbl);
  END LOOP;
END $$;

