-- Rollback for 20261105160000_prisma_migrations_rls_hardening

DO $$
BEGIN
  IF to_regclass('public._prisma_migrations') IS NOT NULL THEN
    DROP POLICY IF EXISTS p_zero_trust_postgrest_deny ON public._prisma_migrations;
    DROP POLICY IF EXISTS p_zero_trust_backend_allow ON public._prisma_migrations;
    ALTER TABLE public._prisma_migrations NO FORCE ROW LEVEL SECURITY;
    ALTER TABLE public._prisma_migrations DISABLE ROW LEVEL SECURITY;
  END IF;
END $$;
