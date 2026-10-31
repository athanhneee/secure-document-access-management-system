-- Migration: Supabase RLS/PostgREST Hardening, Function Search Path Pinning, WebAuthn MFA Enum & Grant Request Uniqueness
-- Documented in docs/decision-log.md (DEC-008)

CREATE SCHEMA IF NOT EXISTS extensions;

-- 1. Extend mfa_method_type to distinguish FIDO2/WebAuthn keys from TOTP secrets
ALTER TYPE mfa_method_type ADD VALUE IF NOT EXISTS 'WEBAUTHN';

-- Allow multiple active WebAuthn hardware keys while enforcing at most one active TOTP per user
DROP INDEX IF EXISTS uq_mfa_active_totp_per_user;
CREATE UNIQUE INDEX IF NOT EXISTS uq_mfa_active_totp_per_user
  ON mfa_methods(user_id, method_type)
  WHERE disabled_at IS NULL AND method_type = 'TOTP';

-- 2. Restore partial uniqueness on access_grants.access_request_id from canonical reference SQL
CREATE UNIQUE INDEX IF NOT EXISTS uq_access_grants_request
  ON access_grants(access_request_id)
  WHERE access_request_id IS NOT NULL;

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

