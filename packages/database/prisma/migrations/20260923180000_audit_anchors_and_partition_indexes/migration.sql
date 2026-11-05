-- Migration: Audit anchors and partition indexes for tamper-evident audit trail
-- Prompt 14: Hardened audit trail & accountability without data leakage
--
-- Thuật toán tổng quan migration:
-- Bổ sung bảng điểm neo chữ ký kiểm toán định kỳ (`audit_anchors`) chống tấn công cắt cụt đuôi hoặc tái tạo lại toàn bộ chuỗi băm,
-- bảo vệ bất biến chỉ ghi nối tiếp (Append-Only WORM) trên bảng điểm neo và bổ sung các chỉ mục phân vùng thời gian cho truy vấn điều tra.

-- Create audit_anchors table for periodic signed checkpoints
CREATE TABLE IF NOT EXISTS "audit_anchors" (
    "id" BIGSERIAL NOT NULL,
    "chain_partition" VARCHAR(80) NOT NULL,
    "anchor_sequence" BIGINT NOT NULL,
    "entry_hash" CHAR(64) NOT NULL,
    "anchored_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "signature" VARCHAR(512) NOT NULL,
    "signer_key_id" VARCHAR(80) NOT NULL,
    "status" VARCHAR(20) NOT NULL DEFAULT 'VALID',

    CONSTRAINT "audit_anchors_pkey" PRIMARY KEY ("id")
);

-- Thuật toán: Chỉ mục phức hợp giảm dần theo `anchor_sequence` giúp tra cứu điểm neo mới nhất của mỗi phân vùng trong thời gian O(log N).
-- Index for finding the latest anchor per partition
CREATE INDEX IF NOT EXISTS "idx_audit_anchor_partition"
  ON "audit_anchors"("chain_partition", "anchor_sequence" DESC);

-- Thuật toán: Khối PL/pgSQL lũy đẳng kiểm tra danh mục hệ thống `pg_trigger` và gắn hàm chặn biến đổi `prevent_audit_mutation()`
-- lên bảng `audit_anchors`, đảm bảo các điểm neo chữ ký cũng bất biến tuyệt đối như bảng `audit_logs`.
-- Audit anchors are append-only: prevent UPDATE or DELETE
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = 'trg_audit_anchor_no_update'
  ) THEN
    CREATE TRIGGER trg_audit_anchor_no_update
    BEFORE UPDATE OR DELETE ON audit_anchors
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_mutation();
  END IF;
END $$;

-- Indexes on audit_logs for query allowlist filters and monthly scans
CREATE INDEX IF NOT EXISTS "idx_audit_outcome_time"
  ON "audit_logs"("outcome", "occurred_at" DESC);

CREATE INDEX IF NOT EXISTS "idx_audit_partition_time"
  ON "audit_logs"("chain_partition", "occurred_at" DESC);

CREATE INDEX IF NOT EXISTS "idx_audit_occurred_at"
  ON "audit_logs"("occurred_at" DESC);
