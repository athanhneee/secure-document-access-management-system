-- Migration: Restore Strict Positive Backend RLS Allowlist via Group Role `sda_backend_rls_member` & Safe PostgREST JSON Claims Parser
--
-- Thuật toán tổng quan migration (`BUG-017`):
-- 1. Khởi tạo lũy đẳng vai trò nhóm không đăng nhập `sda_backend_rls_member` (`NOLOGIN`) để DBA cấp quyền tường minh
--    (`GRANT sda_backend_rls_member TO <custom_backend_role>`) cho các tài khoản dịch vụ tùy chỉnh mà không mở cửa cho role bất kỳ.
-- 2. Khởi tạo hàm `public.safe_postgrest_jwt_role()` phân tích `request.jwt.claims` an toàn có bắt ngoại lệ (`EXCEPTION WHEN OTHERS`)
--    và fail-closed (`RETURN 'anon'`) khi JSON sai định dạng thay vì để `::jsonb` gây lỗi truy vấn.
-- 3. Khôi phục chính sách `p_zero_trust_postgrest_deny` và `p_zero_trust_backend_allow` trên cả 39 bảng nghiệp vụ và `public._prisma_migrations`:
--    - Xóa bỏ hoàn toàn nhánh `NOT IN ('anon','authenticated','authenticator')` phá vỡ allowlist của Migration #12.
--    - Xóa bỏ hoàn toàn GUC tự giả mạo `app.trusted_db_role` và điều kiện chết `coalesce(current_setting('app.current_user_id', true), '') IS NOT NULL`.
--    - Chỉ cho phép danh sách trắng vai trò máy chủ tin cậy, thành viên nhóm `pg_has_role(current_user, 'sda_backend_rls_member', 'MEMBER')`, hoặc `rolsuper`/`rolbypassrls`.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'sda_backend_rls_member') THEN
    CREATE ROLE sda_backend_rls_member NOLOGIN;
  END IF;
EXCEPTION WHEN insufficient_privilege THEN
  NULL;
END $$;

CREATE OR REPLACE FUNCTION public.safe_postgrest_jwt_role()
RETURNS text
LANGUAGE plpgsql
STABLE
SET search_path = public, extensions
AS $$
DECLARE
  raw_claims TEXT;
  parsed JSONB;
BEGIN
  raw_claims := nullif(btrim(coalesce(current_setting('request.jwt.claims', true), '')), '');
  IF raw_claims IS NULL THEN
    RETURN '';
  END IF;

  BEGIN
    parsed := raw_claims::jsonb;
  EXCEPTION WHEN OTHERS THEN
    RETURN 'anon';
  END;

  IF jsonb_typeof(parsed) <> 'object' THEN
    RETURN 'anon';
  END IF;

  RETURN coalesce(parsed ->> 'role', '');
END;
$$;

DO $$
DECLARE
  tbl TEXT;
  deny_expr TEXT := 'current_user NOT IN (''anon'', ''authenticated'', ''authenticator'') '
    || 'AND coalesce(current_setting(''request.jwt.claim.role'', true), '''') NOT IN (''anon'', ''authenticated'') '
    || 'AND public.safe_postgrest_jwt_role() NOT IN (''anon'', ''authenticated'')';
  allow_expr TEXT := '('
    || 'current_user IN (''postgres'', ''service_role'', ''supabase_admin'', ''sda'', ''sda_local'', ''sda_app'', ''prisma'') '
    || 'OR CASE WHEN EXISTS (SELECT 1 FROM pg_catalog.pg_roles gr WHERE gr.rolname = ''sda_backend_rls_member'') '
    || 'THEN pg_has_role(current_user, ''sda_backend_rls_member'', ''MEMBER'') ELSE FALSE END '
    || 'OR EXISTS (SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname = current_user AND (r.rolsuper OR r.rolbypassrls))'
    || ') '
    || 'AND coalesce(current_setting(''request.jwt.claim.role'', true), '''') NOT IN (''anon'', ''authenticated'') '
    || 'AND public.safe_postgrest_jwt_role() NOT IN (''anon'', ''authenticated'')';
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
    EXECUTE format('DROP POLICY IF EXISTS p_zero_trust_postgrest_deny ON public.%I', tbl);
    EXECUTE format(
      'CREATE POLICY p_zero_trust_postgrest_deny ON public.%I AS RESTRICTIVE FOR ALL TO PUBLIC USING (%s) WITH CHECK (%s)',
      tbl,
      deny_expr,
      deny_expr
    );

    EXECUTE format('DROP POLICY IF EXISTS p_zero_trust_backend_allow ON public.%I', tbl);
    EXECUTE format(
      'CREATE POLICY p_zero_trust_backend_allow ON public.%I AS PERMISSIVE FOR ALL TO PUBLIC USING (%s) WITH CHECK (%s)',
      tbl,
      allow_expr,
      allow_expr
    );
  END LOOP;

  IF to_regclass('public._prisma_migrations') IS NOT NULL THEN
    EXECUTE format('DROP POLICY IF EXISTS p_zero_trust_postgrest_deny ON public._prisma_migrations');
    EXECUTE format(
      'CREATE POLICY p_zero_trust_postgrest_deny ON public._prisma_migrations AS RESTRICTIVE FOR ALL TO PUBLIC USING (%s) WITH CHECK (%s)',
      deny_expr,
      deny_expr
    );

    EXECUTE format('DROP POLICY IF EXISTS p_zero_trust_backend_allow ON public._prisma_migrations');
    EXECUTE format(
      'CREATE POLICY p_zero_trust_backend_allow ON public._prisma_migrations AS PERMISSIVE FOR ALL TO PUBLIC USING (%s) WITH CHECK (%s)',
      allow_expr,
      allow_expr
    );
  END IF;
END $$;
