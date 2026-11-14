-- Rollback for 20261113120000_performance_indexes_and_rls_role_flexibility
-- Thuật toán hoàn tác: Gỡ bỏ 6 chỉ mục tối ưu hiệu năng truy vấn và khôi phục biểu thức `p_zero_trust_backend_allow` về trạng thái migration #12.

DROP INDEX IF EXISTS public.idx_export_jobs_status_created;
DROP INDEX IF EXISTS public.idx_access_sessions_status_started;
DROP INDEX IF EXISTS public.idx_incident_actions_report;
DROP INDEX IF EXISTS public.idx_incident_reports_alert_status;
DROP INDEX IF EXISTS public.idx_system_health_captured_at;
DROP INDEX IF EXISTS public.idx_watermark_instances_session;

DO $$
DECLARE
  tbl TEXT;
  prev_allow_expr TEXT := '('
    || 'current_user IN (''postgres'', ''service_role'', ''supabase_admin'', ''sda'', ''sda_local'', ''sda_app'', ''prisma'') '
    || 'OR EXISTS (SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname = current_user AND (r.rolsuper OR r.rolbypassrls))'
    || ') '
    || 'AND coalesce(current_setting(''request.jwt.claim.role'', true), '''') NOT IN (''anon'', ''authenticated'') '
    || 'AND coalesce((nullif(current_setting(''request.jwt.claims'', true), '''')::jsonb ->> ''role''), '''') NOT IN (''anon'', ''authenticated'')';
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
    EXECUTE format('DROP POLICY IF EXISTS p_zero_trust_backend_allow ON public.%I', tbl);
    EXECUTE format(
      'CREATE POLICY p_zero_trust_backend_allow ON public.%I AS PERMISSIVE FOR ALL TO PUBLIC USING (%s) WITH CHECK (%s)',
      tbl,
      prev_allow_expr,
      prev_allow_expr
    );
  END LOOP;

  IF to_regclass('public._prisma_migrations') IS NOT NULL THEN
    EXECUTE format('DROP POLICY IF EXISTS p_zero_trust_backend_allow ON public._prisma_migrations');
    EXECUTE format(
      'CREATE POLICY p_zero_trust_backend_allow ON public._prisma_migrations AS PERMISSIVE FOR ALL TO PUBLIC USING (%s) WITH CHECK (%s)',
      prev_allow_expr,
      prev_allow_expr
    );
  END IF;
END $$;
