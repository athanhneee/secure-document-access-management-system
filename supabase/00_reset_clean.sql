-- =============================================================================
-- SECURE DOCUMENT ACCESS SYSTEM — SUPABASE CLEAN RESET SCRIPT (DEV / STAGING)
-- =============================================================================
-- CẢNH BÁO: Kịch bản này XÓA TOÀN BỘ 39 bảng nghiệp vụ, bảng _prisma_migrations,
-- hàm trigger, sequence và 18 kiểu ENUM của dự án trong schema `public`.
-- KHÔNG chạm vào các schema nội bộ của Supabase (`auth`, `storage`, `realtime`, `vault`, `extensions`).
-- Chỉ chạy trên môi trường Development/Staging khi muốn cài đặt lại từ đầu!
-- =============================================================================

BEGIN;

SET search_path = public, extensions;

-- 1. Gỡ bỏ khóa ngoại vòng giữa documents <-> document_versions trước khi xóa bảng
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'fk_documents_current_version' AND contype = 'f'
  ) THEN
    ALTER TABLE public.documents DROP CONSTRAINT fk_documents_current_version;
  END IF;
END $$;

-- 2. Xóa toàn bộ 39 bảng nghiệp vụ + bảng _prisma_migrations theo thứ tự an toàn
DROP TABLE IF EXISTS public.alert_audit_links CASCADE;
DROP TABLE IF EXISTS public.incident_actions CASCADE;
DROP TABLE IF EXISTS public.incident_reports CASCADE;
DROP TABLE IF EXISTS public.security_alerts CASCADE;
DROP TABLE IF EXISTS public.detection_rule_configs CASCADE;
DROP TABLE IF EXISTS public.audit_anchors CASCADE;
DROP TABLE IF EXISTS public.audit_logs CASCADE;
DROP TABLE IF EXISTS public.watermark_instances CASCADE;
DROP TABLE IF EXISTS public.watermark_configs CASCADE;
DROP TABLE IF EXISTS public.access_sessions CASCADE;
DROP TABLE IF EXISTS public.access_grant_permissions CASCADE;
DROP TABLE IF EXISTS public.access_grants CASCADE;
DROP TABLE IF EXISTS public.access_request_decisions CASCADE;
DROP TABLE IF EXISTS public.access_request_permissions CASCADE;
DROP TABLE IF EXISTS public.access_requests CASCADE;
DROP TABLE IF EXISTS public.document_classification_history CASCADE;
DROP TABLE IF EXISTS public.document_versions CASCADE;
DROP TABLE IF EXISTS public.documents CASCADE;
DROP TABLE IF EXISTS public.business_categories CASCADE;
DROP TABLE IF EXISTS public.classification_levels CASCADE;
DROP TABLE IF EXISTS public.policy_rule_conditions CASCADE;
DROP TABLE IF EXISTS public.policy_rules CASCADE;
DROP TABLE IF EXISTS public.user_attribute_assignments CASCADE;
DROP TABLE IF EXISTS public.attribute_options CASCADE;
DROP TABLE IF EXISTS public.attribute_definitions CASCADE;
DROP TABLE IF EXISTS public.password_reset_tokens CASCADE;
DROP TABLE IF EXISTS public.mfa_methods CASCADE;
DROP TABLE IF EXISTS public.refresh_tokens CASCADE;
DROP TABLE IF EXISTS public.auth_sessions CASCADE;
DROP TABLE IF EXISTS public.role_permissions CASCADE;
DROP TABLE IF EXISTS public.user_roles CASCADE;
DROP TABLE IF EXISTS public.permissions CASCADE;
DROP TABLE IF EXISTS public.roles CASCADE;
DROP TABLE IF EXISTS public.notification_outbox CASCADE;
DROP TABLE IF EXISTS public.notifications CASCADE;
DROP TABLE IF EXISTS public.async_export_jobs CASCADE;
DROP TABLE IF EXISTS public.system_health_snapshots CASCADE;
DROP TABLE IF EXISTS public.users CASCADE;
DROP TABLE IF EXISTS public.departments CASCADE;
DROP TABLE IF EXISTS public._prisma_migrations CASCADE;

-- 3. Xóa 9 hàm PL/pgSQL trigger
DROP FUNCTION IF EXISTS public.bump_abac_parent_version() CASCADE;
DROP FUNCTION IF EXISTS public.bump_abac_row_version() CASCADE;
DROP FUNCTION IF EXISTS public.prevent_department_cycle() CASCADE;
DROP FUNCTION IF EXISTS public.validate_refresh_token_family() CASCADE;
DROP FUNCTION IF EXISTS public.prevent_audit_mutation() CASCADE;
DROP FUNCTION IF EXISTS public.validate_audit_chain_link() CASCADE;
DROP FUNCTION IF EXISTS public.validate_user_clearance_for_grant() CASCADE;
DROP FUNCTION IF EXISTS public.validate_current_document_version() CASCADE;
DROP FUNCTION IF EXISTS public.set_updated_at() CASCADE;

-- 4. Xóa sequence phiên bản chính sách ABAC
DROP SEQUENCE IF EXISTS public.abac_policy_version_seq CASCADE;

-- 5. Xóa toàn bộ 18 kiểu ENUM trong schema public
DROP TYPE IF EXISTS public.mfa_method_type CASCADE;
DROP TYPE IF EXISTS public.auth_session_status CASCADE;
DROP TYPE IF EXISTS public.notification_status CASCADE;
DROP TYPE IF EXISTS public.incident_status CASCADE;
DROP TYPE IF EXISTS public.severity_level CASCADE;
DROP TYPE IF EXISTS public.alert_status CASCADE;
DROP TYPE IF EXISTS public.session_status CASCADE;
DROP TYPE IF EXISTS public.grant_status CASCADE;
DROP TYPE IF EXISTS public.grant_source CASCADE;
DROP TYPE IF EXISTS public.principal_type CASCADE;
DROP TYPE IF EXISTS public.permission_code CASCADE;
DROP TYPE IF EXISTS public.request_status CASCADE;
DROP TYPE IF EXISTS public.scan_status CASCADE;
DROP TYPE IF EXISTS public.document_status CASCADE;
DROP TYPE IF EXISTS public.policy_effect CASCADE;
DROP TYPE IF EXISTS public.attribute_scope CASCADE;
DROP TYPE IF EXISTS public.data_type CASCADE;
DROP TYPE IF EXISTS public.user_status CASCADE;

COMMIT;

