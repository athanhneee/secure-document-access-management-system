-- Migration: Audit anchors and partition indexes for tamper-evident audit trail
-- Prompt 14: Hardened audit trail & accountability without data leakage

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

-- Index for finding the latest anchor per partition
CREATE INDEX IF NOT EXISTS "idx_audit_anchor_partition"
  ON "audit_anchors"("chain_partition", "anchor_sequence" DESC);

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
