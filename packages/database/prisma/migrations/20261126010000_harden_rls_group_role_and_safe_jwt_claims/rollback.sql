-- Rollback: Revert Strict Positive Backend RLS Group Role & Safe JWT Claims Helper (20261126010000)

DO $$
DECLARE
  tbl TEXT;
  deny_expr TEXT := 'current_user NOT IN (''anon'', ''authenticated'', ''authenticator'') '
    || 'AND coalesce(current_setting(''request.jwt.claim.role'', true), '''') NOT IN (''anon'', ''authenticated'') '
    || 'AND coalesce(nullif(current_setting(''request.jwt.claims'', true), '''')::jsonb ->> ''role'', '''') NOT IN (''anon'', ''authenticated'')';
  allow_expr TEXT := '(current_user IN (''postgres'', ''service_role'', ''supabase_admin'', ''sda'', ''sda_local'', ''sda_app'', ''prisma'') '
    || 'OR EXISTS (SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname = current_user AND (r.rolsuper OR r.rolbypassrls))) '
    || 'AND coalesce(current_setting(''request.jwt.claim.role'', true), '''') NOT IN (''anon'', ''authenticated'')';
BEGIN
  FOREACH tbl IN ARRAY ARRAY[
    'access_grant_permissions', 'access_grants', 'access_request_decisions', 'access_request_permissions',
    'access_requests', 'access_sessions', 'alert_audit_links', 'async_export_jobs',
    'attribute_definitions', 'attribute_options', 'audit_anchors', 'audit_logs',
    'auth_sessions', 'business_categories', 'classification_levels', 'departments',
    'detection_rule_configs', 'document_classification_history', 'document_versions', 'documents',
    'incident_actions', 'incident_reports', 'mfa_methods', 'notification_outbox',
    'notifications', 'password_reset_tokens', 'permissions', 'policy_rule_conditions',
    'policy_rules', 'refresh_tokens', 'role_permissions', 'roles',
    'security_alerts', 'system_health_snapshots', 'user_attribute_assignments', 'user_roles',
    'users', 'watermark_configs', 'watermark_instances'
  ]
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS p_zero_trust_postgrest_deny ON public.%I', tbl);
    EXECUTE format(
      'CREATE POLICY p_zero_trust_postgrest_deny ON public.%I AS RESTRICTIVE FOR ALL TO PUBLIC USING (%s) WITH CHECK (%s)',
      tbl, deny_expr, deny_expr
    );
    EXECUTE format('DROP POLICY IF EXISTS p_zero_trust_backend_allow ON public.%I', tbl);
    EXECUTE format(
      'CREATE POLICY p_zero_trust_backend_allow ON public.%I AS PERMISSIVE FOR ALL TO PUBLIC USING (%s) WITH CHECK (%s)',
      tbl, allow_expr, allow_expr
    );
  END LOOP;
END $$;

DROP FUNCTION IF EXISTS public.safe_postgrest_jwt_role() CASCADE;
