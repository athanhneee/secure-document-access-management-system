-- Migration: Supabase RLS/PostgREST Hardening, Function Search Path Pinning, WebAuthn MFA Enum & Grant Request Uniqueness
-- Documented in docs/decision-log.md (DEC-008)
--
-- Thuật toán tổng quan migration:
-- Cứng hóa bảo mật tầng CSDL theo mô hình phòng thủ chiều sâu (Zero-Trust Database Hardening):
-- 1. Mở rộng `mfa_method_type` hỗ trợ khóa phần cứng FIDO2/WebAuthn và tinh chỉnh Partial Unique Index chỉ giới hạn 1 TOTP hoạt động mỗi người dùng.
-- 2. Ghim cứng `search_path = public, extensions` cho toàn bộ 9 hàm trigger PL/pgSQL chống tấn công chiếm quyền điều khiển đường dẫn tìm kiếm đối tượng (Search-Path Hijacking).
-- 3. Khối lặp động kích hoạt Row Level Security (RLS Default-Deny) và thu hồi đặc quyền trực tiếp khỏi vai trò `anon`/`authenticated` trên toàn bộ 39 bảng nghiệp vụ.

CREATE SCHEMA IF NOT EXISTS extensions;

-- 1. Extend mfa_method_type to distinguish FIDO2/WebAuthn keys from TOTP secrets
ALTER TYPE mfa_method_type ADD VALUE IF NOT EXISTS 'WEBAUTHN';

-- Thuật toán: Chỉ mục duy nhất từng phần có điều kiện kép (`disabled_at IS NULL AND method_type = 'TOTP'`),
-- cho phép một người dùng đăng ký nhiều khóa bảo mật phần cứng `WEBAUTHN` dự phòng nhưng chỉ duy trì đúng một bí mật `TOTP` đang bật.
-- Allow multiple active WebAuthn hardware keys while enforcing at most one active TOTP per user
DROP INDEX IF EXISTS uq_mfa_active_totp_per_user;
CREATE UNIQUE INDEX IF NOT EXISTS uq_mfa_active_totp_per_user
  ON mfa_methods(user_id, method_type)
  WHERE disabled_at IS NULL AND method_type = 'TOTP';

-- Thuật toán: Chỉ mục duy nhất từng phần bảo đảm quan hệ ánh xạ 1-1 giữa một yêu cầu xin quyền đã duyệt (`access_request_id IS NOT NULL`) và bản ghi quyền được sinh ra.
-- 2. Restore partial uniqueness on access_grants.access_request_id from canonical reference SQL
CREATE UNIQUE INDEX IF NOT EXISTS uq_access_grants_request
  ON access_grants(access_request_id)
  WHERE access_request_id IS NOT NULL;

-- Thuật toán: Cố định không gian tên thực thi hàm (`SET search_path = public, extensions`) cho mọi hàm trigger,
-- triệt tiêu nguy cơ kẻ tấn công tạo bảng/hàm trùng tên trong schema tạm để đánh lừa hàm trigger chạy với quyền cao hơn.
-- 3. Pin search_path on all PL/pgSQL trigger functions (eliminates Supabase function_search_path_mutable lint)
ALTER FUNCTION set_updated_at() SET search_path = public, extensions;
ALTER FUNCTION validate_current_document_version() SET search_path = public, extensions;
ALTER FUNCTION validate_user_clearance_for_grant() SET search_path = public, extensions;
ALTER FUNCTION validate_audit_chain_link() SET search_path = public, extensions;
ALTER FUNCTION prevent_audit_mutation() SET search_path = public, extensions;
ALTER FUNCTION validate_refresh_token_family() SET search_path = public, extensions;
ALTER FUNCTION prevent_department_cycle() SET search_path = public, extensions;
ALTER FUNCTION bump_abac_row_version() SET search_path = public, extensions;
ALTER FUNCTION bump_abac_parent_version() SET search_path = public, extensions;

-- Thuật toán: Khối lặp động PL/pgSQL áp đặt chính sách từ chối mặc định (RLS Default-Deny) và phân tách đặc quyền vai trò.
-- Duyệt qua danh sách 39 bảng nhạy cảm, dùng `format('%I', tbl)` chống SQL injection định danh để bật `ROW LEVEL SECURITY`,
-- thu hồi toàn bộ quyền từ `anon`/`authenticated` (chặn truy cập PostgREST trực tiếp chưa qua PDP) và chỉ cấp cho `service_role` nếu vai trò tồn tại.
-- 4. Enable Row Level Security (default-deny for non-owner roles such as Supabase PostgREST anon/authenticated)
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
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
      EXECUTE format('REVOKE ALL ON TABLE public.%I FROM anon', tbl);
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
      EXECUTE format('REVOKE ALL ON TABLE public.%I FROM authenticated', tbl);
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
      EXECUTE format('GRANT ALL ON TABLE public.%I TO service_role', tbl);
    END IF;
  END LOOP;
END $$;

