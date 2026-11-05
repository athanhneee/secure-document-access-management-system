-- Migration: Add indexes for Access Grant overlap detection and expiry worker
-- Prompt 12: Time-bound grants, immediate revocation, session termination
--
-- Thuật toán tổng quan migration:
-- Cưỡng chế chống cấp trùng quyền đang hoạt động ở mức CSDL bằng Partial Unique Index (tách biệt chủ thể USER và ROLE),
-- đồng thời tối ưu hóa đường truy cập O(log N) cho tiến trình nền quét hết hạn quyền và thu hồi tức thời các phiên đang mở.

-- Thuật toán: Chỉ mục duy nhất từng phần (`uq_access_grant_active_user`) bảo đảm mỗi cặp `(document_id, principal_user_id)`
-- chỉ tồn tại tối đa 1 bản ghi quyền `ACTIVE` tại một thời điểm (hỗ trợ gia hạn tại chỗ thay vì chèn trùng).
-- Partial unique index prevents duplicate active grants per user-document pair.
-- When extending an existing grant, the service updates the row rather than inserting.
CREATE UNIQUE INDEX IF NOT EXISTS uq_access_grant_active_user
  ON access_grants(document_id, principal_user_id)
  WHERE status = 'ACTIVE' AND principal_type = 'USER';

-- Thuật toán: Chỉ mục duy nhất từng phần (`uq_access_grant_active_role`) bảo đảm mỗi cặp `(document_id, principal_role_id)`
-- chỉ tồn tại tối đa 1 bản ghi quyền theo vai trò đang `ACTIVE`.
-- Partial unique index prevents duplicate active grants per role-document pair.
CREATE UNIQUE INDEX IF NOT EXISTS uq_access_grant_active_role
  ON access_grants(document_id, principal_role_id)
  WHERE status = 'ACTIVE' AND principal_type = 'ROLE';

-- Thuật toán: Chỉ mục B-Tree từng phần theo thứ tự thời gian hết hạn `valid_until` chỉ dành cho hàng `ACTIVE`,
-- phục vụ trực tiếp truy vấn lô `FOR UPDATE SKIP LOCKED` của tiến trình nền `grant-expiry-job`.
-- Index for worker batch expiry queries: find ACTIVE grants past valid_until.
CREATE INDEX IF NOT EXISTS idx_access_grants_expiry
  ON access_grants(status, valid_until)
  WHERE status = 'ACTIVE';

-- Thuật toán: Chỉ mục B-Tree từng phần giúp định vị tức thì các phiên truy cập đang mở (`status = 'ACTIVE'`)
-- thuộc quyền vừa bị thu hồi hoặc hết hạn để chấm dứt dây chuyền (Cascade Session Termination).
-- Index for finding active sessions by grant (used during revocation/expiry).
CREATE INDEX IF NOT EXISTS idx_access_sessions_grant_active
  ON access_sessions(access_grant_id, status)
  WHERE status = 'ACTIVE';
