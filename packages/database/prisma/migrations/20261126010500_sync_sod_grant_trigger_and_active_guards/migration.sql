-- Migration: Synchronize SoD Permission Matrix & Enforce USER/ROLE Active Status and Attribute Guards in `validate_user_clearance_for_grant()`
--
-- Thuật toán tổng quan migration (`BUG-018`):
-- 1. Đồng bộ 100% danh sách cặp quyền đặc quyền `resource_type:action` của trigger với `permission-matrix.ts` & `seed-catalog.ts`
--    (gồm đủ 17 quyền quản trị/SOC/kiểm toán không thuộc trụ cột `BUSINESS_DOCUMENT`: `USER:MANAGE`, `DEPARTMENT:MANAGE`, `ROLE:MANAGE`,
--    `ATTRIBUTE:MANAGE`, `POLICY:MANAGE`, `POLICY:SIMULATE`, `WATERMARK_CONFIG:MANAGE`, `SYSTEM_HEALTH:VIEW`, `SYSTEM_HEALTH:MANAGE`,
--    `AUDIT_LOG:EXPORT`, `SECURITY_ALERT:VIEW`, `SECURITY_ALERT:MANAGE`, `WATERMARK_INSTANCE:TRACE`, `INCIDENT_REPORT:CREATE`,
--    `INCIDENT_REPORT:MANAGE`, `SYSTEM_REPORT:EXPORT`, `ACCESS_SESSION:TERMINATE`; giữ nguyên `AUDIT_LOG:VIEW` cho `DOCUMENT_OWNER`).
-- 2. Bổ sung kiểm tra `users.status = 'ACTIVE'` và kiểm tra Phân tách Nhiệm vụ (SoD) cho toàn bộ vai trò đang hiệu lực của nhánh `principal_type = 'USER'`.
-- 3. Bổ sung lọc `ad.is_active = TRUE`, `ao.is_active = TRUE` trên thuộc tính cấp độ mật và `r.is_active = TRUE` cho cả nhánh `USER` lẫn `ROLE`.

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
      IF NOT EXISTS (
        SELECT 1
        FROM public.users u
        WHERE u.id = NEW.principal_user_id
          AND u.status = 'ACTIVE'
      ) THEN
        RAISE EXCEPTION 'Target user is not active and cannot receive document grants';
      END IF;

      IF EXISTS (
        SELECT 1
        FROM public.user_roles ur
        JOIN public.roles r ON r.id = ur.role_id
        WHERE ur.user_id = NEW.principal_user_id
          AND ur.valid_from <= now()
          AND (ur.valid_to IS NULL OR ur.valid_to > now())
          AND r.is_active = TRUE
          AND (
            r.code IN ('SYSTEM_ADMIN', 'SECURITY_OFFICER', 'AUDITOR')
            OR EXISTS (
              SELECT 1
              FROM public.role_permissions rp
              JOIN public.permissions p ON p.id = rp.permission_id
              WHERE rp.role_id = r.id
                AND (
                  (p.resource_type || ':' || p.action) IN (
                    'USER:MANAGE',
                    'DEPARTMENT:MANAGE',
                    'ROLE:MANAGE',
                    'ATTRIBUTE:MANAGE',
                    'POLICY:MANAGE',
                    'POLICY:SIMULATE',
                    'WATERMARK_CONFIG:MANAGE',
                    'SYSTEM_HEALTH:VIEW',
                    'SYSTEM_HEALTH:MANAGE',
                    'AUDIT_LOG:EXPORT',
                    'SECURITY_ALERT:VIEW',
                    'SECURITY_ALERT:MANAGE',
                    'WATERMARK_INSTANCE:TRACE',
                    'INCIDENT_REPORT:CREATE',
                    'INCIDENT_REPORT:MANAGE',
                    'SYSTEM_REPORT:EXPORT',
                    'ACCESS_SESSION:TERMINATE'
                  )
                  OR p.resource_type IN (
                    'USER',
                    'DEPARTMENT',
                    'ROLE',
                    'ATTRIBUTE',
                    'WATERMARK_CONFIG',
                    'SYSTEM_HEALTH',
                    'INCIDENT_REPORT',
                    'ACCESS_SESSION',
                    'SYSTEM_REPORT',
                    'WATERMARK_INSTANCE',
                    'CLASSIFICATION_LEVEL'
                  )
                )
            )
          )
      ) THEN
        RAISE EXCEPTION 'Separation of duties violation: administrative, security, or audit users cannot receive document grants';
      END IF;

      SELECT ao.numeric_rank INTO user_rank
      FROM public.user_attribute_assignments uaa
      JOIN public.attribute_definitions ad ON ad.id = uaa.attribute_definition_id
      JOIN public.attribute_options ao ON ao.id = uaa.option_id
      WHERE uaa.user_id = NEW.principal_user_id
        AND ad.code = 'CLEARANCE_LEVEL'
        AND ad.is_active = TRUE
        AND ao.is_active = TRUE
        AND uaa.valid_from <= now()
        AND (uaa.valid_to IS NULL OR uaa.valid_to > now())
      ORDER BY ao.numeric_rank DESC
      LIMIT 1;

      IF user_rank IS NULL OR user_rank < document_rank THEN
        RAISE EXCEPTION 'Clearance level is insufficient for this document';
      END IF;
    ELSIF NEW.principal_type = 'ROLE' THEN
      IF NOT EXISTS (
        SELECT 1
        FROM public.roles r
        WHERE r.id = NEW.principal_role_id
          AND r.is_active = TRUE
      ) THEN
        RAISE EXCEPTION 'Target role is not active and cannot receive document grants';
      END IF;

      IF EXISTS (
        SELECT 1
        FROM public.roles r
        WHERE r.id = NEW.principal_role_id
          AND r.is_active = TRUE
          AND (
            r.code IN ('SYSTEM_ADMIN', 'SECURITY_OFFICER', 'AUDITOR')
            OR EXISTS (
              SELECT 1
              FROM public.role_permissions rp
              JOIN public.permissions p ON p.id = rp.permission_id
              WHERE rp.role_id = r.id
                AND (
                  (p.resource_type || ':' || p.action) IN (
                    'USER:MANAGE',
                    'DEPARTMENT:MANAGE',
                    'ROLE:MANAGE',
                    'ATTRIBUTE:MANAGE',
                    'POLICY:MANAGE',
                    'POLICY:SIMULATE',
                    'WATERMARK_CONFIG:MANAGE',
                    'SYSTEM_HEALTH:VIEW',
                    'SYSTEM_HEALTH:MANAGE',
                    'AUDIT_LOG:EXPORT',
                    'SECURITY_ALERT:VIEW',
                    'SECURITY_ALERT:MANAGE',
                    'WATERMARK_INSTANCE:TRACE',
                    'INCIDENT_REPORT:CREATE',
                    'INCIDENT_REPORT:MANAGE',
                    'SYSTEM_REPORT:EXPORT',
                    'ACCESS_SESSION:TERMINATE'
                  )
                  OR p.resource_type IN (
                    'USER',
                    'DEPARTMENT',
                    'ROLE',
                    'ATTRIBUTE',
                    'WATERMARK_CONFIG',
                    'SYSTEM_HEALTH',
                    'INCIDENT_REPORT',
                    'ACCESS_SESSION',
                    'SYSTEM_REPORT',
                    'WATERMARK_INSTANCE',
                    'CLASSIFICATION_LEVEL'
                  )
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
          AND ur.valid_from <= now()
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
          AND ad.is_active = TRUE
          AND ao.is_active = TRUE
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
