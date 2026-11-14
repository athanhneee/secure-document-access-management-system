-- Rollback for 20261105210000_harden_rls_allowlist_and_role_grant_trigger
-- Thuật toán hoàn tác: Khôi phục hàm trigger kiểm tra độ mật Bell-LaPadula cho `USER` grant và khôi phục cặp chính sách RLS chặn PostgREST ở trạng thái migration #11.
CREATE OR REPLACE FUNCTION public.validate_user_clearance_for_grant()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, extensions
AS $$
DECLARE
  user_rank INTEGER;
  document_rank INTEGER;
BEGIN
  IF NEW.principal_type = 'USER' AND NEW.status = 'ACTIVE' THEN
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

    SELECT cl.rank INTO document_rank
    FROM public.document_classification_history dch
    JOIN public.classification_levels cl ON cl.id = dch.classification_level_id
    WHERE dch.document_id = NEW.document_id
      AND dch.effective_to IS NULL;

    IF user_rank IS NULL OR document_rank IS NULL OR user_rank < document_rank THEN
      RAISE EXCEPTION 'Clearance level is insufficient for this document';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_validate_user_clearance_for_grant ON public.access_grants;
CREATE TRIGGER trg_validate_user_clearance_for_grant
  BEFORE INSERT OR UPDATE OF principal_user_id, document_id, status ON public.access_grants
  FOR EACH ROW EXECUTE FUNCTION public.validate_user_clearance_for_grant();

DO $$
DECLARE
  tbl TEXT;
  legacy_expr TEXT := 'current_user NOT IN (''anon'', ''authenticated'') '
    || 'AND coalesce(current_setting(''request.jwt.claim.role'', true), '''') NOT IN (''anon'', ''authenticated'')';
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
      legacy_expr,
      legacy_expr
    );

    EXECUTE format('DROP POLICY IF EXISTS p_zero_trust_backend_allow ON public.%I', tbl);
    EXECUTE format(
      'CREATE POLICY p_zero_trust_backend_allow ON public.%I AS PERMISSIVE FOR ALL TO PUBLIC USING (%s) WITH CHECK (%s)',
      tbl,
      legacy_expr,
      legacy_expr
    );
  END LOOP;

  IF to_regclass('public._prisma_migrations') IS NOT NULL THEN
    EXECUTE format('DROP POLICY IF EXISTS p_zero_trust_postgrest_deny ON public._prisma_migrations');
    EXECUTE format(
      'CREATE POLICY p_zero_trust_postgrest_deny ON public._prisma_migrations AS RESTRICTIVE FOR ALL TO PUBLIC USING (%s) WITH CHECK (%s)',
      legacy_expr,
      legacy_expr
    );

    EXECUTE format('DROP POLICY IF EXISTS p_zero_trust_backend_allow ON public._prisma_migrations');
    EXECUTE format(
      'CREATE POLICY p_zero_trust_backend_allow ON public._prisma_migrations AS PERMISSIVE FOR ALL TO PUBLIC USING (%s) WITH CHECK (%s)',
      legacy_expr,
      legacy_expr
    );
  END IF;
END $$;
