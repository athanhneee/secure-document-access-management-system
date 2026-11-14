-- Rollback for 20260923170000_access_grant_indexes
-- Thuật toán hoàn tác: Gỡ bỏ các chỉ mục từng phần kiểm tra chồng lấp quyền truy cập và quét hết hạn phiên.
DROP INDEX IF EXISTS public.idx_access_sessions_grant_active;
DROP INDEX IF EXISTS public.idx_access_grants_expiry;
DROP INDEX IF EXISTS public.uq_access_grant_active_role;
DROP INDEX IF EXISTS public.uq_access_grant_active_user;
