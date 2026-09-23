-- Migration: Security Operations, Incident Management, Notification Outbox, and Async Export Jobs
-- Prompt 15: Security Officer, Auditor & Administrator Operations

-- 1. Create notification_outbox table for transactional outbox pattern with deduplication and retry backoff
CREATE TABLE IF NOT EXISTS "notification_outbox" (
    "id" UUID NOT NULL,
    "recipient_id" BIGINT NOT NULL,
    "channel" VARCHAR(20) NOT NULL,
    "notification_type" VARCHAR(80) NOT NULL,
    "title" VARCHAR(255) NOT NULL,
    "body" TEXT NOT NULL,
    "payload" JSONB NOT NULL DEFAULT '{}'::jsonb,
    "deduplication_key" VARCHAR(255) NOT NULL,
    "status" VARCHAR(20) NOT NULL DEFAULT 'PENDING',
    "attempt_count" INTEGER NOT NULL DEFAULT 0,
    "max_attempts" INTEGER NOT NULL DEFAULT 5,
    "next_retry_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_error" TEXT,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "processed_at" TIMESTAMPTZ(6),

    CONSTRAINT "notification_outbox_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "notification_outbox_recipient_id_fkey" FOREIGN KEY ("recipient_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE NO ACTION
);

CREATE UNIQUE INDEX IF NOT EXISTS "idx_outbox_dedup" ON "notification_outbox"("deduplication_key");
CREATE INDEX IF NOT EXISTS "idx_outbox_pending" ON "notification_outbox"("status", "next_retry_at");

-- 2. Create async_export_jobs table for large reports (CSV/JSON/PDF/Excel) with TTL and authorization
CREATE TABLE IF NOT EXISTS "async_export_jobs" (
    "id" UUID NOT NULL,
    "requester_user_id" BIGINT NOT NULL,
    "export_type" VARCHAR(80) NOT NULL,
    "format" VARCHAR(20) NOT NULL,
    "status" VARCHAR(20) NOT NULL DEFAULT 'PENDING',
    "filter_params" JSONB NOT NULL DEFAULT '{}'::jsonb,
    "file_path" VARCHAR(500),
    "file_size_bytes" BIGINT,
    "sha256_hash" CHAR(64),
    "mime_type" VARCHAR(150),
    "row_count" INTEGER NOT NULL DEFAULT 0,
    "error_message" TEXT,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "completed_at" TIMESTAMPTZ(6),
    "expires_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "async_export_jobs_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "async_export_jobs_requester_user_id_fkey" FOREIGN KEY ("requester_user_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE NO ACTION
);

CREATE INDEX IF NOT EXISTS "idx_export_jobs_user_status" ON "async_export_jobs"("requester_user_id", "status");
CREATE INDEX IF NOT EXISTS "idx_export_jobs_expires" ON "async_export_jobs"("expires_at");

-- 3. Create detection_rule_configs table for configurable rule-based anomaly detection
CREATE TABLE IF NOT EXISTS "detection_rule_configs" (
    "id" BIGSERIAL NOT NULL,
    "rule_code" VARCHAR(80) NOT NULL,
    "name" VARCHAR(180) NOT NULL,
    "description" TEXT,
    "is_enabled" BOOLEAN NOT NULL DEFAULT TRUE,
    "severity" severity_level NOT NULL DEFAULT 'HIGH',
    "threshold" INTEGER NOT NULL DEFAULT 5,
    "window_minutes" INTEGER NOT NULL DEFAULT 10,
    "cooldown_minutes" INTEGER NOT NULL DEFAULT 30,
    "parameters" JSONB NOT NULL DEFAULT '{}'::jsonb,
    "updated_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_by" BIGINT,

    CONSTRAINT "detection_rule_configs_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "detection_rule_configs_updated_by_fkey" FOREIGN KEY ("updated_by") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE NO ACTION
);

CREATE UNIQUE INDEX IF NOT EXISTS "detection_rule_configs_rule_code_key" ON "detection_rule_configs"("rule_code");

-- 4. Seed initial default detection rules
INSERT INTO "detection_rule_configs" ("rule_code", "name", "description", "is_enabled", "severity", "threshold", "window_minutes", "cooldown_minutes", "parameters")
VALUES
    ('MASS_DOWNLOAD', 'Phát hiện tải hàng loạt', 'Cảnh báo khi người dùng tải nhiều tài liệu trong khoảng thời gian ngắn', TRUE, 'HIGH', 5, 10, 30, '{"action": "DOCUMENT_DOWNLOADED"}'::jsonb),
    ('REPEATED_DENIED', 'Phát hiện từ chối truy cập liên tiếp', 'Cảnh báo khi có nhiều yêu cầu bị từ chối truy cập từ cùng một đối tượng', TRUE, 'MEDIUM', 5, 10, 15, '{"outcome": "DENIED"}'::jsonb),
    ('OFF_HOURS_ACCESS', 'Phát hiện truy cập ngoài giờ', 'Cảnh báo khi có hoạt động truy cập tài liệu nhạy cảm ngoài giờ làm việc hoặc cuối tuần', TRUE, 'MEDIUM', 1, 5, 60, '{"startHourUtc": 0, "endHourUtc": 11}'::jsonb),
    ('UNTRUSTED_CONTEXT', 'Phát hiện IP hoặc thiết bị chưa tin cậy', 'Cảnh báo khi truy cập từ thiết bị hoặc địa chỉ IP nằm ngoài danh sách tin cậy', TRUE, 'HIGH', 1, 5, 30, '{}'::jsonb),
    ('REFRESH_TOKEN_REUSE', 'Phát hiện tái sử dụng Refresh Token', 'Cảnh báo khi một refresh token đã xoay vòng hoặc thu hồi được sử dụng lại', TRUE, 'HIGH', 1, 5, 15, '{}'::jsonb),
    ('AUDIT_INTEGRITY_COMPROMISED', 'Phát hiện vi phạm toàn vẹn Audit', 'Cảnh báo nghiêm trọng khi phát hiện đứt gãy chuỗi HMAC hoặc sai lệch sequence', TRUE, 'CRITICAL', 1, 5, 15, '{}'::jsonb)
ON CONFLICT ("rule_code") DO NOTHING;
