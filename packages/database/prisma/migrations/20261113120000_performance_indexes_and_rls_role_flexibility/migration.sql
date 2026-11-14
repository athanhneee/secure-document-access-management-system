-- Migration: Performance Indexes for Forensic Preview, SOC/Health Queries, Worker Export Queue & Flexible Backend RLS Role Guard
--
-- Thuật toán tổng quan migration:
-- 1. Bổ sung 6 chỉ mục B-Tree phức hợp và đơn cột triệt tiêu quét tuần tự bảng (`Seq Scan`) trên các đường nóng:
--    - `idx_watermark_instances_session`: tra cứu thủy vân theo phiên đọc tài liệu (`access_session_id`) trong `O(log N)` mỗi lần mở trang xem trước.
--    - `idx_system_health_captured_at`: truy vấn ảnh chụp sức khỏe hệ thống mới nhất giảm dần theo `captured_at`.
--    - `idx_incident_reports_alert_status` & `idx_incident_actions_report`: tăng tốc điều tra biên bản sự cố SOC và danh sách hành động khắc phục.
--    - `idx_access_sessions_status_started`: lọc và phân trang danh sách phiên đọc tài liệu đang hoạt động theo thứ tự thời gian mở phiên.
--    - `idx_export_jobs_status_created`: phục vụ hàng đợi `FOR UPDATE SKIP LOCKED` của `@sda/worker` xử lý xuất báo cáo bất đồng bộ theo FIFO.
-- 2. Mở rộng chính sách `p_zero_trust_backend_allow` trên 39 bảng nghiệp vụ và `public._prisma_migrations` để hỗ trợ các tài khoản CSDL đặc quyền tối thiểu tùy chỉnh trên Production (ngoài 7 tên role mặc định) miễn không phải `anon`/`authenticated`/`authenticator` và không mang ngữ cảnh JWT của PostgREST, đồng thời tương thích biến phiên `app.current_user_id`.

CREATE INDEX IF NOT EXISTS "idx_watermark_instances_session"
  ON "public"."watermark_instances"("access_session_id");

CREATE INDEX IF NOT EXISTS "idx_system_health_captured_at"
  ON "public"."system_health_snapshots"("captured_at" DESC);

CREATE INDEX IF NOT EXISTS "idx_incident_reports_alert_status"
  ON "public"."incident_reports"("alert_id", "status", "created_at" DESC);

CREATE INDEX IF NOT EXISTS "idx_incident_actions_report"
  ON "public"."incident_actions"("incident_report_id");

CREATE INDEX IF NOT EXISTS "idx_access_sessions_status_started"
  ON "public"."access_sessions"("status", "started_at" DESC);

CREATE INDEX IF NOT EXISTS "idx_export_jobs_status_created"
  ON "public"."async_export_jobs"("status", "created_at");

DO $$
DECLARE
  tbl TEXT;
  allow_expr TEXT := '('
    || 'current_user IN (''postgres'', ''service_role'', ''supabase_admin'', ''sda'', ''sda_local'', ''sda_app'', ''prisma'') '
    || 'OR current_user = nullif(current_setting(''app.trusted_db_role'', true), '''') '
    || 'OR (current_user NOT IN (''anon'', ''authenticated'', ''authenticator'') AND coalesce(current_setting(''request.jwt.claim.role'', true), '''') = '''' AND coalesce(current_setting(''request.jwt.claims'', true), '''') = '''') '
    || 'OR EXISTS (SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname = current_user AND (r.rolsuper OR r.rolbypassrls))'
    || ') '
    || 'AND coalesce(current_setting(''request.jwt.claim.role'', true), '''') NOT IN (''anon'', ''authenticated'') '
    || 'AND coalesce((nullif(current_setting(''request.jwt.claims'', true), '''')::jsonb ->> ''role''), '''') NOT IN (''anon'', ''authenticated'') '
    || 'AND coalesce(current_setting(''app.current_user_id'', true), '''') IS NOT NULL';
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
      allow_expr,
      allow_expr
    );
  END LOOP;

  IF to_regclass('public._prisma_migrations') IS NOT NULL THEN
    EXECUTE format('DROP POLICY IF EXISTS p_zero_trust_backend_allow ON public._prisma_migrations');
    EXECUTE format(
      'CREATE POLICY p_zero_trust_backend_allow ON public._prisma_migrations AS PERMISSIVE FOR ALL TO PUBLIC USING (%s) WITH CHECK (%s)',
      allow_expr,
      allow_expr
    );
  END IF;
END $$;
