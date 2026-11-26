-- Rollback: Revert SoD Matrix & Active Guards in `validate_user_clearance_for_grant()` (20261126010500)
-- Restores the prior Migration #12 trigger definition.

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

      IF user_rank IS NULL OR user_rank < document_rank THEN
        RAISE EXCEPTION 'Clearance level is insufficient for this document';
      END IF;
    ELSIF NEW.principal_type = 'ROLE' THEN
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
