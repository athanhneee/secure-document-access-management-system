-- Migration: Harden Positive Backend RLS Allowlist, PostgREST JSON Claims Guard & Bell-LaPadula / SoD Role Grant Trigger
--
-- Thuật toán tổng quan migration (`HIGH-12`):
-- 1. Mở rộng hàm trigger `public.validate_user_clearance_for_grant()` để cưỡng chế đồng thời cho cả `principal_type = 'USER'` và `principal_type = 'ROLE'`:
--    - Chặn cấp quyền tài liệu cho các vai trò quản trị/an ninh/kiểm toán vi phạm Phân tách Nhiệm vụ (SoD), cả theo mã hệ thống lẫn theo tập quyền đặc quyền gán cho vai trò tùy chỉnh.
--    - Áp dụng phép giao bảo thủ (Lattice Meet) trên toàn bộ người giữ vai trò đang hoạt động/chờ kích hoạt để bảo đảm không thành viên nào vi phạm bất biến Bell-LaPadula `No Read Up` (`min_role_rank >= document_rank`, `holder_count > 0`).
-- 2. Chuyển chính sách `p_zero_trust_backend_allow` từ danh sách đen phủ định (`NOT IN ('anon', 'authenticated')`) sang danh sách trắng dương tính (Positive Backend Role Allowlist) cho kết nối máy chủ tin cậy, đồng thời kiểm tra cả biến cấu hình JSON `request.jwt.claims` mới của PostgREST trên 39 bảng nghiệp vụ và `public._prisma_migrations`.
-- CONFLICT-RESOLVED: Đóng lỗ hổng bỏ qua kiểm tra Bell-LaPadula/SoD cho `ROLE` grant tại tầng CSDL và chuyển `p_zero_trust_backend_allow` sang allowlist dương tính (HIGH-12).

CREATE OR REPLACE FUNCTION public.validate_user_clearance_for_grant()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, extensions
AS $$
DECLARE
  user_rank INTEGER;
  document_rank INTEGER;
  holder_count INTEGER;
  min_role_rank INTEGER;
BEGIN
  IF NEW.status = 'ACTIVE' THEN
    SELECT cl.rank INTO document_rank
    FROM public.document_classification_history dch
    JOIN public.classification_levels cl ON cl.id = dch.classification_level_id
    WHERE dch.document_id = NEW.document_id
      AND dch.effective_to IS NULL;

    IF document_rank IS NULL THEN
      RAISE EXCEPTION 'Clearance level is insufficient for this document';
    END IF;

    IF NEW.principal_type = 'USER' THEN
      SELECT ao.numeric_rank INTO user_rank
      FROM public.user_attribute_assignments uaa
      JOIN public.attribute_definitions ad ON ad.id = uaa.attribute_definition_id
      JOIN public.attribute_options ao ON ao.id = uaa.option_id
      WHERE uaa.user_id = NEW.principal_user_id
        AND ad.code = 'CLEARANCE_LEVEL'
        AND uaa.valid_from <= now()
        AND (uaa.valid_to IS NULL OR uaa.valid_to > now())
      ORDER BY ao.numeric_rank DESC
      LIMIT 1;

      IF user_rank IS NULL OR user_rank < document_rank THEN
        RAISE EXCEPTION 'Clearance level is insufficient for this document';
      END IF;
    ELSIF NEW.principal_type = 'ROLE' THEN
      IF EXISTS (
        SELECT 1
        FROM public.roles r
        WHERE r.id = NEW.principal_role_id
          AND (
            r.code IN ('SYSTEM_ADMIN', 'SECURITY_OFFICER', 'AUDITOR')
            OR EXISTS (
              SELECT 1
              FROM public.role_permissions rp
              JOIN public.permissions p ON p.id = rp.permission_id
              WHERE rp.role_id = r.id
                AND (p.resource_type || ':' || p.action) IN (
                  'USER:MANAGE',
                  'ROLE:MANAGE',
                  'POLICY_RULE:MANAGE',
                  'ATTRIBUTE_DEFINITION:MANAGE',
                  'AUDIT_LOG:READ',
                  'AUDIT_LOG:VERIFY',
                  'AUDIT_LOG:EXPORT',
                  'SECURITY_ALERT:READ',
                  'SECURITY_ALERT:MANAGE',
                  'INCIDENT_REPORT:CREATE',
                  'INCIDENT_REPORT:UPDATE',
                  'INCIDENT_REPORT:CLOSE',
                  'WATERMARK_CONFIG:MANAGE',
                  'WATERMARK_INSTANCE:TRACE',
                  'CLASSIFICATION_LEVEL:MANAGE',
                  'SYSTEM_HEALTH:READ'
                )
            )
          )
      ) THEN
        RAISE EXCEPTION 'Separation of duties violation: administrative, security, or audit roles cannot receive document grants';
      END IF;

      SELECT count(*)::int, min(coalesce(holder_clearance.max_rank, 0))
      INTO holder_count, min_role_rank
      FROM (
        SELECT DISTINCT ur.user_id
        FROM public.user_roles ur
        JOIN public.users u ON u.id = ur.user_id
        WHERE ur.role_id = NEW.principal_role_id
          AND (ur.valid_to IS NULL OR ur.valid_to > now())
          AND u.status <> 'DISABLED'
      ) active_holders
      LEFT JOIN LATERAL (
        SELECT max(ao.numeric_rank) AS max_rank
        FROM public.user_attribute_assignments uaa
        JOIN public.attribute_definitions ad ON ad.id = uaa.attribute_definition_id
        JOIN public.attribute_options ao ON ao.id = uaa.option_id
        WHERE uaa.user_id = active_holders.user_id
          AND ad.code = 'CLEARANCE_LEVEL'
          AND uaa.valid_from <= now()
          AND (uaa.valid_to IS NULL OR uaa.valid_to > now())
      ) holder_clearance ON TRUE;

      IF holder_count = 0 OR min_role_rank IS NULL OR min_role_rank < document_rank THEN
        RAISE EXCEPTION 'Clearance level is insufficient for this document';
      END IF;
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_validate_user_clearance_for_grant ON public.access_grants;
CREATE TRIGGER trg_validate_user_clearance_for_grant
  BEFORE INSERT OR UPDATE OF principal_type, principal_user_id, principal_role_id, document_id, status ON public.access_grants
  FOR EACH ROW EXECUTE FUNCTION public.validate_user_clearance_for_grant();

DO $$
DECLARE
  tbl TEXT;
  deny_expr TEXT := 'current_user NOT IN (''anon'', ''authenticated'') '
    || 'AND coalesce(current_setting(''request.jwt.claim.role'', true), '''') NOT IN (''anon'', ''authenticated'') '
    || 'AND coalesce((nullif(current_setting(''request.jwt.claims'', true), '''')::jsonb ->> ''role''), '''') NOT IN (''anon'', ''authenticated'')';
  allow_expr TEXT := '('
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
