-- Migration: Force Row Level Security & Least-Privilege Policy Parity on public._prisma_migrations
--
-- Thuật toán (`[MED-08]`):
-- Kiểm tra sự tồn tại của bảng siêu dữ liệu `public._prisma_migrations` qua `to_regclass('public._prisma_migrations') IS NOT NULL`
-- (an toàn tuyệt đối khi phát lại trên môi trường `PGlite` không có bảng lịch sử Prisma CLI), sau đó cưỡng chế
-- `ENABLE/FORCE ROW LEVEL SECURITY`, gắn cặp chính sách `p_zero_trust_postgrest_deny` (`AS RESTRICTIVE`) và
-- `p_zero_trust_backend_allow` (`AS PERMISSIVE`), đồng thời thu hồi quyền khỏi `anon`/`authenticated` và cấp quyền tối thiểu cho `service_role`.
-- CONFLICT-RESOLVED: Đồng bộ hóa cấu hình FORCE RLS và chính sách chặn PostgREST trên bảng _prisma_migrations giữa chuỗi Prisma migrations, kịch bản Supabase SQL và tệp DDL chuẩn.

DO $$
BEGIN
  IF to_regclass('public._prisma_migrations') IS NOT NULL THEN
    ALTER TABLE public._prisma_migrations ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public._prisma_migrations FORCE ROW LEVEL SECURITY;

    DROP POLICY IF EXISTS p_zero_trust_postgrest_deny ON public._prisma_migrations;
    CREATE POLICY p_zero_trust_postgrest_deny ON public._prisma_migrations
      AS RESTRICTIVE
      FOR ALL
      TO PUBLIC
      USING (
        current_user NOT IN ('anon', 'authenticated')
        AND coalesce(current_setting('request.jwt.claim.role', true), '') NOT IN ('anon', 'authenticated')
      )
      WITH CHECK (
        current_user NOT IN ('anon', 'authenticated')
        AND coalesce(current_setting('request.jwt.claim.role', true), '') NOT IN ('anon', 'authenticated')
      );

    DROP POLICY IF EXISTS p_zero_trust_backend_allow ON public._prisma_migrations;
    CREATE POLICY p_zero_trust_backend_allow ON public._prisma_migrations
      AS PERMISSIVE
      FOR ALL
      TO PUBLIC
      USING (
        current_user NOT IN ('anon', 'authenticated')
        AND coalesce(current_setting('request.jwt.claim.role', true), '') NOT IN ('anon', 'authenticated')
      )
      WITH CHECK (
        current_user NOT IN ('anon', 'authenticated')
        AND coalesce(current_setting('request.jwt.claim.role', true), '') NOT IN ('anon', 'authenticated')
      );

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
      REVOKE ALL ON TABLE public._prisma_migrations FROM anon;
    END IF;

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
      REVOKE ALL ON TABLE public._prisma_migrations FROM authenticated;
    END IF;

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
      REVOKE ALL ON TABLE public._prisma_migrations FROM service_role;
      GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public._prisma_migrations TO service_role;
    END IF;
  END IF;
END $$;
