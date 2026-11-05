-- Migration: Force Row Level Security Policies, Service-Role Least Privilege & Audit Log TRUNCATE Protection
--
-- Thuật toán tổng quan migration (`[HIGH-06]`):
-- 1. Mở rộng cơ chế bất biến Append-Only cho `audit_logs` và `audit_anchors` bằng 2 trigger mức câu lệnh (`BEFORE TRUNCATE FOR EACH STATEMENT`)
--    gọi hàm `public.prevent_audit_mutation()`, triệt tiêu hoàn toàn khả năng xóa trắng nhật ký kiểm toán qua lệnh `TRUNCATE`.
-- 2. Nâng cấp toàn bộ 39 bảng nghiệp vụ lên `FORCE ROW LEVEL SECURITY` kèm cặp chính sách tường minh:
--    - `p_zero_trust_postgrest_deny` (`AS RESTRICTIVE`): Chặn tuyệt đối các vai trò công khai PostgREST (`anon`, `authenticated`) cả qua `current_user` lẫn `request.jwt.claim.role`.
--    - `p_zero_trust_backend_allow` (`AS PERMISSIVE`): Cho phép kết nối máy chủ tin cậy (NestJS PEP / Worker) đi qua tầng RLS sau khi đã vượt qua lớp `RESTRICTIVE`.
-- 3. Áp dụng nguyên lý đặc quyền tối thiểu (Least Privilege) cho `service_role`: thu hồi `GRANT ALL` (loại bỏ quyền `TRUNCATE`, `TRIGGER`, `REFERENCES`),
--    chỉ cấp `SELECT, INSERT` trên `audit_logs` và `audit_anchors`, và `SELECT, INSERT, UPDATE, DELETE` trên 37 bảng nghiệp vụ còn lại.

-- 1. Block statement-level TRUNCATE on append-only cryptographic audit tables
DROP TRIGGER IF EXISTS trg_audit_no_truncate ON public.audit_logs;
CREATE TRIGGER trg_audit_no_truncate
  BEFORE TRUNCATE ON public.audit_logs
  FOR EACH STATEMENT EXECUTE FUNCTION public.prevent_audit_mutation();

DROP TRIGGER IF EXISTS trg_audit_anchor_no_truncate ON public.audit_anchors;
CREATE TRIGGER trg_audit_anchor_no_truncate
  BEFORE TRUNCATE ON public.audit_anchors
  FOR EACH STATEMENT EXECUTE FUNCTION public.prevent_audit_mutation();

-- 2. Enforce FORCE ROW LEVEL SECURITY, explicit Zero-Trust policies, and service_role least privilege across all 39 business tables
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
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', tbl);
    EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', tbl);

    EXECUTE format('DROP POLICY IF EXISTS p_zero_trust_postgrest_deny ON public.%I', tbl);
    EXECUTE format(
      'CREATE POLICY p_zero_trust_postgrest_deny ON public.%I AS RESTRICTIVE FOR ALL TO PUBLIC '
      || 'USING (current_user NOT IN (''anon'', ''authenticated'') AND coalesce(current_setting(''request.jwt.claim.role'', true), '''') NOT IN (''anon'', ''authenticated'')) '
      || 'WITH CHECK (current_user NOT IN (''anon'', ''authenticated'') AND coalesce(current_setting(''request.jwt.claim.role'', true), '''') NOT IN (''anon'', ''authenticated''))',
      tbl
    );

    EXECUTE format('DROP POLICY IF EXISTS p_zero_trust_backend_allow ON public.%I', tbl);
    EXECUTE format(
      'CREATE POLICY p_zero_trust_backend_allow ON public.%I AS PERMISSIVE FOR ALL TO PUBLIC '
      || 'USING (current_user NOT IN (''anon'', ''authenticated'') AND coalesce(current_setting(''request.jwt.claim.role'', true), '''') NOT IN (''anon'', ''authenticated'')) '
      || 'WITH CHECK (current_user NOT IN (''anon'', ''authenticated'') AND coalesce(current_setting(''request.jwt.claim.role'', true), '''') NOT IN (''anon'', ''authenticated''))',
      tbl
    );

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
      EXECUTE format('REVOKE ALL ON TABLE public.%I FROM anon', tbl);
    END IF;

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
      EXECUTE format('REVOKE ALL ON TABLE public.%I FROM authenticated', tbl);
    END IF;

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
      EXECUTE format('REVOKE ALL ON TABLE public.%I FROM service_role', tbl);
      IF tbl IN ('audit_logs', 'audit_anchors') THEN
        EXECUTE format('GRANT SELECT, INSERT ON TABLE public.%I TO service_role', tbl);
      ELSE
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.%I TO service_role', tbl);
      END IF;
    END IF;
  END LOOP;
END $$;
