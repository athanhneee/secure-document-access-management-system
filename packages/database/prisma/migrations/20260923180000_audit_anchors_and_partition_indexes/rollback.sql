-- Rollback for 20260923180000_audit_anchors_and_partition_indexes
-- Thuật toán hoàn tác: Gỡ bỏ các chỉ mục phân vùng thời gian trên `audit_logs`, gỡ trigger bất biến và xóa bảng điểm neo `audit_anchors`.
DROP INDEX IF EXISTS public.idx_audit_occurred_at;
DROP INDEX IF EXISTS public.idx_audit_partition_time;
DROP INDEX IF EXISTS public.idx_audit_outcome_time;
DROP TRIGGER IF EXISTS trg_audit_anchor_no_update ON public.audit_anchors;
DROP INDEX IF EXISTS public.idx_audit_anchor_partition;
DROP TABLE IF EXISTS public.audit_anchors;
