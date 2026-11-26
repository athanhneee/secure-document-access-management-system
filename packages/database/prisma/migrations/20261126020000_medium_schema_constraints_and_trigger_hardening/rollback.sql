-- Rollback: Revert Medium Schema Constraints, Composite Attribute FK & Audit FK Restrict (20261126020000)

DROP TRIGGER IF EXISTS trg_detection_rule_configs_updated ON public.detection_rule_configs;

ALTER TABLE public.detection_rule_configs
  DROP CONSTRAINT IF EXISTS ck_detection_rule_configs_positive;

DROP INDEX IF EXISTS public.uq_audit_anchor_position;
DROP INDEX IF EXISTS public.uq_user_roles_global_valid_from;

ALTER TABLE public.user_attribute_assignments
  DROP CONSTRAINT IF EXISTS fk_user_attr_assignment_option_definition;

ALTER TABLE public.attribute_options
  DROP CONSTRAINT IF EXISTS uq_attribute_options_definition_id;

ALTER TABLE public.user_attribute_assignments
  ADD CONSTRAINT user_attribute_assignments_option_id_fkey
  FOREIGN KEY (option_id) REFERENCES public.attribute_options(id) ON DELETE RESTRICT;

ALTER TABLE public.audit_logs
  DROP CONSTRAINT IF EXISTS audit_logs_actor_user_id_fkey,
  ADD CONSTRAINT audit_logs_actor_user_id_fkey
    FOREIGN KEY (actor_user_id) REFERENCES public.users(id) ON DELETE SET NULL,
  DROP CONSTRAINT IF EXISTS audit_logs_document_id_fkey,
  ADD CONSTRAINT audit_logs_document_id_fkey
    FOREIGN KEY (document_id) REFERENCES public.documents(id) ON DELETE SET NULL,
  DROP CONSTRAINT IF EXISTS audit_logs_access_session_id_fkey,
  ADD CONSTRAINT audit_logs_access_session_id_fkey
    FOREIGN KEY (access_session_id) REFERENCES public.access_sessions(id) ON DELETE SET NULL;
