-- Rollback for 20261105210000_harden_rls_allowlist_and_role_grant_trigger
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

