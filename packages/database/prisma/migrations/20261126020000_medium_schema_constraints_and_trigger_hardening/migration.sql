-- Migration: Medium-Severity Schema Constraints, Composite Attribute FK, Append-Only Audit FK Restrict & Unqualified Trigger Resolution
--
-- Thuật toán tổng quan migration (`BUG-113`):
-- 1. Chỉ mục duy nhất từng phần `uq_user_roles_global_valid_from` chặn nhân bản gán vai trò toàn cục (`scope_department_id IS NULL`) cùng thời điểm `valid_from`.
-- 2. Chỉ mục duy nhất `uq_audit_anchor_position` trên `audit_anchors(chain_partition, anchor_sequence)` chống đóng trùng điểm neo ở cùng một `sequence`.
-- 3. Ràng buộc `ck_detection_rule_configs_positive` (`threshold > 0`, `window_minutes > 0`, `cooldown_minutes > 0`) và trigger `trg_detection_rule_configs_updated` làm mới `updated_at` trên `detection_rule_configs`.
-- 4. Ràng buộc duy nhất `uq_attribute_options_definition_id (attribute_definition_id, id)` trên `attribute_options` và khóa ngoại tổ hợp `MATCH SIMPLE` `fk_user_attr_assignment_option_definition (attribute_definition_id, option_id)` trên `user_attribute_assignments` ngăn gán chéo tùy chọn khác định nghĩa thuộc tính nhưng vẫn cho phép `option_id IS NULL`.
-- 5. Chuyển 3 khóa ngoại của `audit_logs` (`actor_user_id`, `document_id`, `access_session_id`) từ `ON DELETE SET NULL` sang `ON DELETE RESTRICT` để đồng bộ với tính chất bất biến Append-Only của chuỗi băm kiểm toán.
-- 6. Bỏ tiền tố cứng `public.` bên trong thân hàm trigger `validate_user_clearance_for_grant()` để tương thích với môi trường bảng tạm / schema cô lập trên PGlite mà vẫn giữ ghim `SET search_path = public, extensions`.

-- 1. Partial unique index for global user_roles (scope_department_id IS NULL)
CREATE UNIQUE INDEX IF NOT EXISTS uq_user_roles_global_valid_from
  ON public.user_roles(user_id, role_id, valid_from)
  WHERE scope_department_id IS NULL;

-- 2. Unique anchor position per partition on audit_anchors
CREATE UNIQUE INDEX IF NOT EXISTS uq_audit_anchor_position
  ON public.audit_anchors(chain_partition, anchor_sequence);

-- 3. Positive bounds CHECK & updated_at trigger on detection_rule_configs
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint con
    JOIN pg_class rel ON rel.oid = con.conrelid
    JOIN pg_namespace nsp ON nsp.oid = rel.relnamespace
    WHERE nsp.nspname = 'public'
      AND rel.relname = 'detection_rule_configs'
      AND con.conname = 'ck_detection_rule_configs_positive'
  ) THEN
    ALTER TABLE public.detection_rule_configs
      ADD CONSTRAINT ck_detection_rule_configs_positive
      CHECK (threshold > 0 AND window_minutes > 0 AND cooldown_minutes > 0);
  END IF;
END $$;

DROP TRIGGER IF EXISTS trg_detection_rule_configs_updated ON public.detection_rule_configs;
CREATE TRIGGER trg_detection_rule_configs_updated
  BEFORE UPDATE ON public.detection_rule_configs
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

-- 4. Composite FK MATCH SIMPLE (attribute_definition_id, option_id) on user_attribute_assignments
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint con
    JOIN pg_class rel ON rel.oid = con.conrelid
    JOIN pg_namespace nsp ON nsp.oid = rel.relnamespace
    WHERE nsp.nspname = 'public'
      AND rel.relname = 'attribute_options'
      AND con.conname = 'uq_attribute_options_definition_id'
  ) THEN
    ALTER TABLE public.attribute_options
      ADD CONSTRAINT uq_attribute_options_definition_id
      UNIQUE (attribute_definition_id, id);
  END IF;
END $$;

ALTER TABLE public.user_attribute_assignments
  DROP CONSTRAINT IF EXISTS user_attribute_assignments_option_id_fkey;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint con
    JOIN pg_class rel ON rel.oid = con.conrelid
    JOIN pg_namespace nsp ON nsp.oid = rel.relnamespace
    WHERE nsp.nspname = 'public'
      AND rel.relname = 'user_attribute_assignments'
      AND con.conname = 'fk_user_attr_assignment_option_definition'
  ) THEN
    ALTER TABLE public.user_attribute_assignments
      ADD CONSTRAINT fk_user_attr_assignment_option_definition
      FOREIGN KEY (attribute_definition_id, option_id)
      REFERENCES public.attribute_options(attribute_definition_id, id)
      MATCH SIMPLE
      ON DELETE RESTRICT
      ON UPDATE NO ACTION;
  END IF;
END $$;

-- 5. Enforce ON DELETE RESTRICT on audit_logs foreign keys (append-only table cannot SET NULL)
ALTER TABLE public.audit_logs
  DROP CONSTRAINT IF EXISTS audit_logs_actor_user_id_fkey,
  ADD CONSTRAINT audit_logs_actor_user_id_fkey
    FOREIGN KEY (actor_user_id) REFERENCES public.users(id) ON DELETE RESTRICT,
  DROP CONSTRAINT IF EXISTS audit_logs_document_id_fkey,
  ADD CONSTRAINT audit_logs_document_id_fkey
    FOREIGN KEY (document_id) REFERENCES public.documents(id) ON DELETE RESTRICT,
  DROP CONSTRAINT IF EXISTS audit_logs_access_session_id_fkey,
  ADD CONSTRAINT audit_logs_access_session_id_fkey
    FOREIGN KEY (access_session_id) REFERENCES public.access_sessions(id) ON DELETE RESTRICT;

-- 6. Remove hardcoded `public.` inside `validate_user_clearance_for_grant()` body for PGlite compatibility
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
    FROM document_classification_history dch
    JOIN classification_levels cl ON cl.id = dch.classification_level_id
    WHERE dch.document_id = NEW.document_id
      AND dch.effective_to IS NULL;

    IF document_rank IS NULL THEN
      RAISE EXCEPTION 'Clearance level is insufficient for this document';
    END IF;

    IF NEW.principal_type = 'USER' THEN
      IF NOT EXISTS (
        SELECT 1
        FROM users u
        WHERE u.id = NEW.principal_user_id
          AND u.status = 'ACTIVE'
      ) THEN
        RAISE EXCEPTION 'Target user is not active and cannot receive document grants';
      END IF;

      IF EXISTS (
        SELECT 1
        FROM user_roles ur
        JOIN roles r ON r.id = ur.role_id
        WHERE ur.user_id = NEW.principal_user_id
          AND ur.valid_from <= now()
          AND (ur.valid_to IS NULL OR ur.valid_to > now())
          AND r.is_active = TRUE
          AND (
            r.code IN ('SYSTEM_ADMIN', 'SECURITY_OFFICER', 'AUDITOR')
            OR EXISTS (
              SELECT 1
              FROM role_permissions rp
              JOIN permissions p ON p.id = rp.permission_id
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
      FROM user_attribute_assignments uaa
      JOIN attribute_definitions ad ON ad.id = uaa.attribute_definition_id
      JOIN attribute_options ao ON ao.id = uaa.option_id
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
        FROM roles r
        WHERE r.id = NEW.principal_role_id
          AND r.is_active = TRUE
      ) THEN
        RAISE EXCEPTION 'Target role is not active and cannot receive document grants';
      END IF;

      IF EXISTS (
        SELECT 1
        FROM roles r
        WHERE r.id = NEW.principal_role_id
          AND r.is_active = TRUE
          AND (
            r.code IN ('SYSTEM_ADMIN', 'SECURITY_OFFICER', 'AUDITOR')
            OR EXISTS (
              SELECT 1
              FROM role_permissions rp
              JOIN permissions p ON p.id = rp.permission_id
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
        FROM user_roles ur
        JOIN users u ON u.id = ur.user_id
        WHERE ur.role_id = NEW.principal_role_id
          AND ur.valid_from <= now()
          AND (ur.valid_to IS NULL OR ur.valid_to > now())
          AND u.status <> 'DISABLED'
      ) active_holders
      LEFT JOIN LATERAL (
        SELECT max(ao.numeric_rank) AS max_rank
        FROM user_attribute_assignments uaa
        JOIN attribute_definitions ad ON ad.id = uaa.attribute_definition_id
        JOIN attribute_options ao ON ao.id = uaa.option_id
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
