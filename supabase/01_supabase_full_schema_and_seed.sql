-- =============================================================================
-- HỆ THỐNG QUẢN LÝ TRUY CẬP TÀI LIỆU MẬT (SECURE DOCUMENT ACCESS SYSTEM)
-- BỘ MÃ SQL TOÀN DIỆN CHO SUPABASE POSTGRESQL (SCHEMA + TRIGGERS + RLS + SEED)
-- =============================================================================
-- Phiên bản tương thích: Supabase PostgreSQL 15 / 17 & PostgreSQL 18, Prisma 7.x
-- Nguồn đồng bộ chuẩn: packages/database/prisma/schema/ & packages/database/prisma/migrations/
--
-- HƯỚNG DẪN CHẠY TRÊN SUPABASE:
--   1. Mở Supabase Dashboard -> SQL Editor -> New Query.
--   2. (Tùy chọn) Nếu muốn xóa sạch dữ liệu cũ trên môi trường Dev/Staging, chạy
--      tệp `supabase/00_reset_clean.sql` trước.
--   3. Dán toàn bộ nội dung tệp `supabase/01_supabase_full_schema_and_seed.sql`
--      này vào SQL Editor và nhấn "Run".
--   4. Kịch bản được thiết kế IDEMPOTENT (chạy lại nhiều lần không lỗi, không
--      nhân bản dữ liệu danh mục, không làm gãy chuỗi băm audit_logs).
--
-- Thuật toán tổng quan kịch bản:
-- Hợp nhất toàn trình lược đồ bảo mật 39 bảng nghiệp vụ, 18 miền liệt kê ENUM, chỉ mục chuyên biệt (GIN JSONB, GIN Trigram, GIN Full-Text, Partial Unique Index),
-- 9 hàm trigger PL/pgSQL ghim cứng `search_path` (Bell-LaPadula MAC, chuỗi băm bất biến HMAC-SHA256, phát hiện chu trình cây bằng `WITH RECURSIVE`, khóa lạc quan OCC),
-- vòng lặp khóa chặt Zero-Trust Row Level Security (RLS), đồng bộ bảng `_prisma_migrations` và gieo dữ liệu hạt giống tất định lũy đẳng (Idempotent Deterministic Seed).
-- =============================================================================

-- =============================================================================
-- PHẦN 1: SCHEMA EXTENSIONS & CẤU HÌNH SEARCH PATH CHO SUPABASE
-- =============================================================================

CREATE SCHEMA IF NOT EXISTS extensions;

-- Thuật toán: Cài đặt an toàn tiện ích mở rộng `pgcrypto` và `pg_trgm` vào không gian tên biệt lập `extensions`
-- kèm cơ chế bắt ngoại lệ để tương thích cả PostgreSQL nhân thuần lẫn hạ tầng quản trị của Supabase.
DO $$
BEGIN
  CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA extensions;
EXCEPTION
  WHEN OTHERS THEN
    NULL; -- PostgreSQL 15+ đã tích hợp sẵn gen_random_uuid() trong nhân core
END $$;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_trgm') THEN
    NULL;
  ELSE
    CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA extensions;
  END IF;
END $$;

SET search_path = public, extensions;

-- =============================================================================
-- PHẦN 2: KHỞI TẠO 18 KIỂU DỮ LIỆU LIỆT KÊ (ENUM TYPES)
-- (Đặt ngoài khối BEGIN..COMMIT để ALTER TYPE ADD VALUE tương thích mọi phiên bản PG)
-- =============================================================================

-- Thuật toán: Khởi tạo lũy đẳng 18 kiểu dữ liệu ENUM ngoài giao dịch bằng truy vấn kiểm tra danh mục `pg_type` + `pg_namespace`
-- kết hợp `ALTER TYPE ... ADD VALUE IF NOT EXISTS` để nâng cấp không gián đoạn trên mọi phiên bản PostgreSQL.
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace WHERE n.nspname = 'public' AND t.typname = 'user_status') THEN
    CREATE TYPE public.user_status AS ENUM ('PENDING', 'ACTIVE', 'LOCKED', 'DISABLED');
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace WHERE n.nspname = 'public' AND t.typname = 'data_type') THEN
    CREATE TYPE public.data_type AS ENUM ('STRING', 'NUMBER', 'BOOLEAN', 'DATE', 'ENUM');
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace WHERE n.nspname = 'public' AND t.typname = 'attribute_scope') THEN
    CREATE TYPE public.attribute_scope AS ENUM ('USER', 'RESOURCE', 'ENVIRONMENT');
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace WHERE n.nspname = 'public' AND t.typname = 'policy_effect') THEN
    CREATE TYPE public.policy_effect AS ENUM ('PERMIT', 'DENY');
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace WHERE n.nspname = 'public' AND t.typname = 'document_status') THEN
    CREATE TYPE public.document_status AS ENUM ('DRAFT', 'ACTIVE', 'ARCHIVED', 'DELETED');
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace WHERE n.nspname = 'public' AND t.typname = 'scan_status') THEN
    CREATE TYPE public.scan_status AS ENUM ('PENDING', 'CLEAN', 'INFECTED', 'FAILED');
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace WHERE n.nspname = 'public' AND t.typname = 'request_status') THEN
    CREATE TYPE public.request_status AS ENUM ('PENDING', 'APPROVED', 'REJECTED', 'CANCELLED', 'EXPIRED');
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace WHERE n.nspname = 'public' AND t.typname = 'permission_code') THEN
    CREATE TYPE public.permission_code AS ENUM ('DISCOVER', 'VIEW', 'DOWNLOAD', 'SHARE', 'MANAGE');
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace WHERE n.nspname = 'public' AND t.typname = 'principal_type') THEN
    CREATE TYPE public.principal_type AS ENUM ('USER', 'ROLE');
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace WHERE n.nspname = 'public' AND t.typname = 'grant_source') THEN
    CREATE TYPE public.grant_source AS ENUM ('DIRECT', 'ACCESS_REQUEST', 'SYSTEM');
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace WHERE n.nspname = 'public' AND t.typname = 'grant_status') THEN
    CREATE TYPE public.grant_status AS ENUM ('ACTIVE', 'REVOKED', 'EXPIRED', 'SUSPENDED');
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace WHERE n.nspname = 'public' AND t.typname = 'session_status') THEN
    CREATE TYPE public.session_status AS ENUM ('ACTIVE', 'ENDED', 'TERMINATED');
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace WHERE n.nspname = 'public' AND t.typname = 'alert_status') THEN
    CREATE TYPE public.alert_status AS ENUM ('OPEN', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE');
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace WHERE n.nspname = 'public' AND t.typname = 'severity_level') THEN
    CREATE TYPE public.severity_level AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL');
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace WHERE n.nspname = 'public' AND t.typname = 'incident_status') THEN
    CREATE TYPE public.incident_status AS ENUM ('DRAFT', 'SUBMITTED', 'IN_REVIEW', 'CLOSED');
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace WHERE n.nspname = 'public' AND t.typname = 'notification_status') THEN
    CREATE TYPE public.notification_status AS ENUM ('UNREAD', 'READ', 'ARCHIVED');
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace WHERE n.nspname = 'public' AND t.typname = 'auth_session_status') THEN
    CREATE TYPE public.auth_session_status AS ENUM ('ACTIVE', 'REVOKED', 'EXPIRED');
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace WHERE n.nspname = 'public' AND t.typname = 'mfa_method_type') THEN
    CREATE TYPE public.mfa_method_type AS ENUM ('TOTP', 'WEBAUTHN');
  END IF;
END $$;

ALTER TYPE public.mfa_method_type ADD VALUE IF NOT EXISTS 'WEBAUTHN';

BEGIN;

SET LOCAL search_path = public, extensions;

-- =============================================================================
-- PHẦN 3: SEQUENCE ĐÁNH SỐ PHIÊN BẢN CHÍNH SÁCH ABAC ĐƠN ĐIỆU
-- =============================================================================

-- Thuật toán: Bộ sinh số hiệu phiên bản đơn điệu toàn cục (`NO CYCLE`) phục vụ kiểm soát đồng thời lạc quan (OCC)
-- và phát tín hiệu làm mới tức thì bộ nhớ đệm chính sách ABAC tại tầng ứng dụng.
CREATE SEQUENCE IF NOT EXISTS public.abac_policy_version_seq
  AS BIGINT
  START WITH 1
  INCREMENT BY 1
  NO CYCLE;

-- =============================================================================
-- PHẦN 4: KHỞI TẠO 39 BẢNG NGHIỆP VỤ + BẢNG _prisma_migrations
-- =============================================================================

-- 4.1. Tổ chức, Người dùng & RBAC có phạm vi (6 bảng)
-- CONFLICT-RESOLVED: Đồng bộ cột version trên departments/users/roles khớp chính xác với migration 20260919180000_scoped_rbac_administration
CREATE TABLE IF NOT EXISTS public.departments (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    code                VARCHAR(30) NOT NULL UNIQUE,
    name                VARCHAR(150) NOT NULL,
    parent_id           BIGINT REFERENCES public.departments(id) ON DELETE SET NULL,
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    version             INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS public.users (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username            VARCHAR(80) NOT NULL UNIQUE,
    email               VARCHAR(255) NOT NULL UNIQUE,
    password_hash       VARCHAR(255) NOT NULL,
    full_name           VARCHAR(150) NOT NULL,
    employee_code       VARCHAR(50) UNIQUE,
    department_id       BIGINT REFERENCES public.departments(id) ON DELETE SET NULL,
    status              public.user_status NOT NULL DEFAULT 'PENDING',
    failed_login_count  INTEGER NOT NULL DEFAULT 0 CHECK (failed_login_count >= 0),
    locked_until        TIMESTAMPTZ,
    last_login_at       TIMESTAMPTZ,
    created_by          BIGINT REFERENCES public.users(id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    disabled_at         TIMESTAMPTZ,
    version             INTEGER NOT NULL DEFAULT 0,
    CHECK ((status = 'DISABLED') = (disabled_at IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS public.roles (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    code                VARCHAR(50) NOT NULL UNIQUE,
    name                VARCHAR(120) NOT NULL,
    description         TEXT,
    is_system_role      BOOLEAN NOT NULL DEFAULT FALSE,
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    created_by          BIGINT REFERENCES public.users(id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    version             INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS public.permissions (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    code                VARCHAR(80) NOT NULL UNIQUE,
    name                VARCHAR(150) NOT NULL,
    resource_type       VARCHAR(80) NOT NULL,
    action              VARCHAR(80) NOT NULL,
    description         TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (resource_type, action)
);

CREATE TABLE IF NOT EXISTS public.user_roles (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id             BIGINT NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    role_id             BIGINT NOT NULL REFERENCES public.roles(id) ON DELETE CASCADE,
    scope_department_id BIGINT REFERENCES public.departments(id) ON DELETE CASCADE,
    valid_from          TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_to            TIMESTAMPTZ,
    assigned_by         BIGINT NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (valid_to IS NULL OR valid_to > valid_from),
    UNIQUE (user_id, role_id, scope_department_id, valid_from)
);

CREATE TABLE IF NOT EXISTS public.role_permissions (
    role_id             BIGINT NOT NULL REFERENCES public.roles(id) ON DELETE CASCADE,
    permission_id       BIGINT NOT NULL REFERENCES public.permissions(id) ON DELETE CASCADE,
    granted_by          BIGINT NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (role_id, permission_id)
);

-- 4.2. Xác thực Cứng hóa, Refresh Token Rotation & MFA TOTP/WebAuthn (4 bảng)
-- CONFLICT-RESOLVED: Loại bỏ DEFAULT gen_random_uuid() trên các khóa UUID để đồng nhất 100% với Prisma schema & chuỗi migrations (ứng dụng sinh UUID tường minh)
CREATE TABLE IF NOT EXISTS public.auth_sessions (
    id                  UUID PRIMARY KEY,
    user_id             BIGINT NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    token_family_id     UUID NOT NULL UNIQUE,
    status              public.auth_session_status NOT NULL DEFAULT 'ACTIVE',
    ip_address          INET,
    user_agent          TEXT,
    mfa_verified_at     TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at          TIMESTAMPTZ NOT NULL,
    revoked_at          TIMESTAMPTZ,
    revocation_reason   VARCHAR(80),
    CHECK (expires_at > created_at),
    CHECK (
      (status = 'ACTIVE' AND revoked_at IS NULL)
      OR (status <> 'ACTIVE' AND revoked_at IS NOT NULL)
    ),
    CHECK (revoked_at IS NULL OR revocation_reason IS NOT NULL)
);

CREATE TABLE IF NOT EXISTS public.refresh_tokens (
    id                  UUID PRIMARY KEY,
    auth_session_id     UUID NOT NULL REFERENCES public.auth_sessions(id) ON DELETE CASCADE,
    token_family_id     UUID NOT NULL,
    token_hash          CHAR(64) NOT NULL UNIQUE,
    parent_token_id     UUID REFERENCES public.refresh_tokens(id) ON DELETE RESTRICT,
    issued_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at          TIMESTAMPTZ NOT NULL,
    used_at             TIMESTAMPTZ,
    revoked_at          TIMESTAMPTZ,
    revocation_reason   VARCHAR(80),
    CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    CHECK (expires_at > issued_at),
    CHECK (revoked_at IS NULL OR revocation_reason IS NOT NULL),
    UNIQUE (id, token_family_id)
);

CREATE TABLE IF NOT EXISTS public.mfa_methods (
    id                   UUID PRIMARY KEY,
    user_id              BIGINT NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    method_type          public.mfa_method_type NOT NULL DEFAULT 'TOTP',
    label                VARCHAR(80),
    secret_encrypted     TEXT NOT NULL,
    recovery_code_hashes JSONB NOT NULL DEFAULT '[]'::jsonb,
    verified_at          TIMESTAMPTZ,
    enabled_at           TIMESTAMPTZ,
    disabled_at          TIMESTAMPTZ,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (enabled_at IS NULL OR verified_at IS NOT NULL),
    CHECK (disabled_at IS NULL OR enabled_at IS NOT NULL)
);

CREATE TABLE IF NOT EXISTS public.password_reset_tokens (
    id                  UUID PRIMARY KEY,
    user_id             BIGINT NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    token_hash          CHAR(64) NOT NULL UNIQUE,
    requested_ip        INET,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at          TIMESTAMPTZ NOT NULL,
    used_at             TIMESTAMPTZ,
    CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    CHECK (expires_at > created_at)
);

-- 4.3. Thuộc tính Động & Bộ đánh giá Chính sách ABAC Tất định (5 bảng)
CREATE TABLE IF NOT EXISTS public.attribute_definitions (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    code                VARCHAR(80) NOT NULL UNIQUE,
    name                VARCHAR(150) NOT NULL,
    scope               public.attribute_scope NOT NULL,
    value_type          public.data_type NOT NULL,
    description         TEXT,
    is_required         BOOLEAN NOT NULL DEFAULT FALSE,
    is_multi_value      BOOLEAN NOT NULL DEFAULT FALSE,
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    created_by          BIGINT REFERENCES public.users(id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    version             BIGINT NOT NULL DEFAULT nextval('public.abac_policy_version_seq'::regclass)
);

CREATE TABLE IF NOT EXISTS public.attribute_options (
    id                      BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    attribute_definition_id BIGINT NOT NULL REFERENCES public.attribute_definitions(id) ON DELETE CASCADE,
    value_code              VARCHAR(120) NOT NULL,
    display_name            VARCHAR(150) NOT NULL,
    numeric_rank            INTEGER,
    is_active               BOOLEAN NOT NULL DEFAULT TRUE,
    sort_order              INTEGER NOT NULL DEFAULT 0,
    UNIQUE (attribute_definition_id, value_code)
);

CREATE TABLE IF NOT EXISTS public.user_attribute_assignments (
    id                      BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id                 BIGINT NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    attribute_definition_id BIGINT NOT NULL REFERENCES public.attribute_definitions(id) ON DELETE RESTRICT,
    option_id               BIGINT REFERENCES public.attribute_options(id) ON DELETE RESTRICT,
    value_text              TEXT,
    value_number            NUMERIC(18,4),
    value_boolean           BOOLEAN,
    value_date              DATE,
    valid_from              TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_to                TIMESTAMPTZ,
    assigned_by             BIGINT NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (valid_to IS NULL OR valid_to > valid_from),
    CHECK (num_nonnulls(option_id, value_text, value_number, value_boolean, value_date) = 1)
);

CREATE TABLE IF NOT EXISTS public.policy_rules (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    code                VARCHAR(80) NOT NULL UNIQUE,
    name                VARCHAR(180) NOT NULL,
    description         TEXT,
    effect              public.policy_effect NOT NULL,
    priority            INTEGER NOT NULL DEFAULT 100 CHECK (priority >= 0),
    target_resource     VARCHAR(80) NOT NULL DEFAULT 'DOCUMENT',
    target_action       public.permission_code,
    combining_algorithm VARCHAR(40) NOT NULL DEFAULT 'DENY_OVERRIDES',
    obligations         JSONB NOT NULL DEFAULT '[]'::jsonb,
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    valid_from          TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_to            TIMESTAMPTZ,
    created_by          BIGINT NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    version             BIGINT NOT NULL DEFAULT nextval('public.abac_policy_version_seq'::regclass),
    CHECK (valid_to IS NULL OR valid_to > valid_from),
    CHECK (combining_algorithm IN ('DENY_OVERRIDES', 'PERMIT_OVERRIDES', 'FIRST_APPLICABLE')),
    CONSTRAINT ck_policy_rule_obligations_array CHECK (jsonb_typeof(obligations) = 'array')
);

CREATE TABLE IF NOT EXISTS public.policy_rule_conditions (
    id                      BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    policy_rule_id          BIGINT NOT NULL REFERENCES public.policy_rules(id) ON DELETE CASCADE,
    attribute_definition_id BIGINT REFERENCES public.attribute_definitions(id) ON DELETE RESTRICT,
    context_key             VARCHAR(100),
    operator                VARCHAR(30) NOT NULL,
    expected_value          JSONB NOT NULL,
    condition_group         INTEGER NOT NULL DEFAULT 1,
    sequence_no             INTEGER NOT NULL DEFAULT 1,
    CHECK ((attribute_definition_id IS NOT NULL) <> (context_key IS NOT NULL)),
    CHECK (operator IN ('EQ','NEQ','IN','NOT_IN','GTE','LTE','BETWEEN','CIDR_MATCH','TIME_BETWEEN','EXISTS')),
    UNIQUE (policy_rule_id, condition_group, sequence_no)
);

-- 4.4. Phân loại Độ mật, Tài liệu, Phiên bản & Lịch sử SCD Type 2 (5 bảng)
CREATE TABLE IF NOT EXISTS public.classification_levels (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    code                VARCHAR(40) NOT NULL UNIQUE,
    name                VARCHAR(100) NOT NULL,
    rank                INTEGER NOT NULL UNIQUE CHECK (rank >= 0),
    description         TEXT,
    default_view_days   INTEGER CHECK (default_view_days > 0),
    allow_download      BOOLEAN NOT NULL DEFAULT FALSE,
    require_watermark   BOOLEAN NOT NULL DEFAULT TRUE,
    is_active           BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS public.business_categories (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    code                VARCHAR(50) NOT NULL UNIQUE,
    name                VARCHAR(150) NOT NULL,
    department_id       BIGINT REFERENCES public.departments(id) ON DELETE SET NULL,
    description         TEXT,
    is_active           BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS public.documents (
    id                  UUID PRIMARY KEY,
    document_code       VARCHAR(60) NOT NULL UNIQUE,
    title               VARCHAR(255) NOT NULL,
    description         TEXT,
    owner_id            BIGINT NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
    department_id       BIGINT NOT NULL REFERENCES public.departments(id) ON DELETE RESTRICT,
    current_version_id  BIGINT,
    status              public.document_status NOT NULL DEFAULT 'DRAFT',
    discoverable        BOOLEAN NOT NULL DEFAULT TRUE,
    retention_until     DATE,
    archived_at         TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    version             INTEGER NOT NULL DEFAULT 0 CHECK (version >= 0),
    CHECK ((status = 'ARCHIVED') = (archived_at IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS public.document_versions (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    document_id         UUID NOT NULL,
    version_no          INTEGER NOT NULL CHECK (version_no > 0),
    original_filename   VARCHAR(255) NOT NULL,
    storage_key         VARCHAR(500) NOT NULL UNIQUE,
    mime_type           VARCHAR(150) NOT NULL,
    file_size_bytes     BIGINT NOT NULL CHECK (file_size_bytes > 0),
    sha256_hash         CHAR(64) NOT NULL,
    encryption_key_ref  VARCHAR(255) NOT NULL,
    scan_status         public.scan_status NOT NULL DEFAULT 'PENDING',
    change_note         TEXT,
    uploaded_by         BIGINT NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT document_versions_document_id_fkey
      FOREIGN KEY (document_id) REFERENCES public.documents(id) ON DELETE RESTRICT,
    UNIQUE (document_id, version_no),
    UNIQUE (document_id, sha256_hash)
);

-- Thuật toán: Tạo trễ có điều kiện khóa ngoại tham chiếu vòng `fk_documents_current_version` (`documents.current_version_id` -> `document_versions.id`)
-- qua tra cứu `pg_constraint`, giải quyết phụ thuộc hai chiều giữa bảng tài liệu và bảng phiên bản một cách lũy đẳng.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'fk_documents_current_version' AND contype = 'f'
  ) THEN
    ALTER TABLE public.documents
      ADD CONSTRAINT fk_documents_current_version
      FOREIGN KEY (current_version_id) REFERENCES public.document_versions(id) ON DELETE RESTRICT;
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS public.document_classification_history (
    id                      BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    document_id             UUID NOT NULL REFERENCES public.documents(id) ON DELETE RESTRICT,
    classification_level_id BIGINT NOT NULL REFERENCES public.classification_levels(id) ON DELETE RESTRICT,
    business_category_id    BIGINT NOT NULL REFERENCES public.business_categories(id) ON DELETE RESTRICT,
    reason                  TEXT,
    classified_by           BIGINT NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
    effective_from          TIMESTAMPTZ NOT NULL DEFAULT now(),
    effective_to            TIMESTAMPTZ,
    CHECK (effective_to IS NULL OR effective_to > effective_from)
);

-- 4.5. Yêu cầu Truy cập, Cấp quyền Có thời hạn & Phiên xem Tài liệu (6 bảng)
CREATE TABLE IF NOT EXISTS public.access_requests (
    id                  UUID PRIMARY KEY,
    document_id         UUID NOT NULL REFERENCES public.documents(id) ON DELETE RESTRICT,
    requester_id        BIGINT NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
    reason              TEXT NOT NULL CHECK (length(trim(reason)) >= 10),
    requested_from      TIMESTAMPTZ NOT NULL,
    requested_until     TIMESTAMPTZ NOT NULL,
    status              public.request_status NOT NULL DEFAULT 'PENDING',
    submitted_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    cancelled_at        TIMESTAMPTZ,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    version             INTEGER NOT NULL DEFAULT 0 CHECK (version >= 0),
    CHECK (requested_until > requested_from),
    CHECK ((status = 'CANCELLED') = (cancelled_at IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS public.access_request_permissions (
    access_request_id   UUID NOT NULL REFERENCES public.access_requests(id) ON DELETE CASCADE,
    permission          public.permission_code NOT NULL,
    PRIMARY KEY (access_request_id, permission),
    CHECK (permission IN ('VIEW', 'DOWNLOAD'))
);

CREATE TABLE IF NOT EXISTS public.access_request_decisions (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    access_request_id   UUID NOT NULL UNIQUE REFERENCES public.access_requests(id) ON DELETE RESTRICT,
    decision            public.request_status NOT NULL,
    decided_by          BIGINT NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
    decision_note       TEXT,
    approved_from       TIMESTAMPTZ,
    approved_until      TIMESTAMPTZ,
    decided_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (decision IN ('APPROVED', 'REJECTED')),
    CHECK (
      (decision = 'APPROVED' AND approved_from IS NOT NULL AND approved_until > approved_from)
      OR (decision = 'REJECTED' AND approved_from IS NULL AND approved_until IS NULL)
    )
);

CREATE TABLE IF NOT EXISTS public.access_grants (
    id                  UUID PRIMARY KEY,
    document_id         UUID NOT NULL REFERENCES public.documents(id) ON DELETE RESTRICT,
    principal_type      public.principal_type NOT NULL,
    principal_user_id   BIGINT REFERENCES public.users(id) ON DELETE CASCADE,
    principal_role_id   BIGINT REFERENCES public.roles(id) ON DELETE CASCADE,
    source              public.grant_source NOT NULL,
    access_request_id   UUID REFERENCES public.access_requests(id) ON DELETE RESTRICT,
    valid_from          TIMESTAMPTZ NOT NULL,
    valid_until         TIMESTAMPTZ NOT NULL,
    status              public.grant_status NOT NULL DEFAULT 'ACTIVE',
    granted_by          BIGINT NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
    granted_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_by          BIGINT REFERENCES public.users(id) ON DELETE RESTRICT,
    revoked_at          TIMESTAMPTZ,
    revoke_reason       TEXT,
    version             INTEGER NOT NULL DEFAULT 0 CHECK (version >= 0),
    CHECK (valid_until > valid_from),
    CHECK (
      (principal_type = 'USER' AND principal_user_id IS NOT NULL AND principal_role_id IS NULL)
      OR (principal_type = 'ROLE' AND principal_role_id IS NOT NULL AND principal_user_id IS NULL)
    ),
    CHECK ((source = 'ACCESS_REQUEST') = (access_request_id IS NOT NULL)),
    CHECK (
      (status = 'REVOKED' AND revoked_by IS NOT NULL AND revoked_at IS NOT NULL AND revoke_reason IS NOT NULL)
      OR (status <> 'REVOKED' AND revoked_by IS NULL AND revoked_at IS NULL)
    )
);

CREATE TABLE IF NOT EXISTS public.access_grant_permissions (
    access_grant_id     UUID NOT NULL REFERENCES public.access_grants(id) ON DELETE CASCADE,
    permission          public.permission_code NOT NULL,
    PRIMARY KEY (access_grant_id, permission),
    CHECK (permission IN ('VIEW', 'DOWNLOAD'))
);

CREATE TABLE IF NOT EXISTS public.access_sessions (
    id                  UUID PRIMARY KEY,
    access_grant_id     UUID NOT NULL REFERENCES public.access_grants(id) ON DELETE RESTRICT,
    document_version_id BIGINT NOT NULL REFERENCES public.document_versions(id) ON DELETE RESTRICT,
    user_id             BIGINT NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
    ip_address          INET NOT NULL,
    user_agent          TEXT,
    device_fingerprint  VARCHAR(255),
    status              public.session_status NOT NULL DEFAULT 'ACTIVE',
    started_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_activity_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at            TIMESTAMPTZ,
    terminated_reason   TEXT,
    CHECK ((status = 'ACTIVE' AND ended_at IS NULL) OR (status <> 'ACTIVE' AND ended_at IS NOT NULL))
);

-- 4.6. Đóng dấu Pháp y Động (Dynamic Forensic Watermarking) (2 bảng)
CREATE TABLE IF NOT EXISTS public.watermark_configs (
    id                      BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name                    VARCHAR(120) NOT NULL,
    classification_level_id BIGINT REFERENCES public.classification_levels(id) ON DELETE CASCADE,
    is_default              BOOLEAN NOT NULL DEFAULT FALSE,
    is_visible              BOOLEAN NOT NULL DEFAULT TRUE,
    template_text           VARCHAR(500) NOT NULL,
    opacity_percent         SMALLINT NOT NULL DEFAULT 25 CHECK (opacity_percent BETWEEN 1 AND 100),
    rotation_degrees        SMALLINT NOT NULL DEFAULT -30 CHECK (rotation_degrees BETWEEN -90 AND 90),
    font_size               SMALLINT NOT NULL DEFAULT 12 CHECK (font_size BETWEEN 6 AND 72),
    color_hex               CHAR(7) NOT NULL DEFAULT '#808080',
    include_qr_code         BOOLEAN NOT NULL DEFAULT TRUE,
    is_active               BOOLEAN NOT NULL DEFAULT TRUE,
    created_by              BIGINT NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (color_hex ~ '^#[0-9A-Fa-f]{6}$')
);

CREATE TABLE IF NOT EXISTS public.watermark_instances (
    id                  UUID PRIMARY KEY,
    watermark_config_id BIGINT NOT NULL REFERENCES public.watermark_configs(id) ON DELETE RESTRICT,
    access_session_id   UUID NOT NULL REFERENCES public.access_sessions(id) ON DELETE RESTRICT,
    document_version_id BIGINT NOT NULL REFERENCES public.document_versions(id) ON DELETE RESTRICT,
    user_id             BIGINT NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
    watermark_token     VARCHAR(128) NOT NULL UNIQUE,
    rendered_text       VARCHAR(1000) NOT NULL,
    output_sha256_hash  CHAR(64),
    generated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 4.7. Nhật ký Kiểm toán Bất biến Chuỗi HMAC-SHA-256 & Checkpoint Chữ ký (2 bảng)
CREATE TABLE IF NOT EXISTS public.audit_logs (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_user_id       BIGINT REFERENCES public.users(id) ON DELETE SET NULL,
    actor_username      VARCHAR(80),
    action              VARCHAR(100) NOT NULL,
    object_type         VARCHAR(80) NOT NULL,
    object_id           VARCHAR(100),
    document_id         UUID REFERENCES public.documents(id) ON DELETE SET NULL,
    access_session_id   UUID REFERENCES public.access_sessions(id) ON DELETE SET NULL,
    outcome             VARCHAR(20) NOT NULL CHECK (outcome IN ('SUCCESS', 'DENIED', 'FAILED')),
    reason_code         VARCHAR(80),
    ip_address          INET,
    user_agent          TEXT,
    correlation_id      UUID NOT NULL,
    details             JSONB NOT NULL DEFAULT '{}'::jsonb,
    previous_hash       CHAR(64),
    entry_hash          CHAR(64) NOT NULL,
    chain_partition     VARCHAR(80) NOT NULL DEFAULT 'GLOBAL',
    chain_sequence      BIGINT NOT NULL,
    hmac_key_version    INTEGER NOT NULL DEFAULT 1,
    chain_algorithm     VARCHAR(20) NOT NULL DEFAULT 'HMAC-SHA-256',
    CHECK (actor_user_id IS NOT NULL OR actor_username IS NOT NULL),
    CHECK (previous_hash IS NULL OR previous_hash ~ '^[0-9A-Fa-f]{64}$'),
    CHECK (entry_hash ~ '^[0-9A-Fa-f]{64}$'),
    CHECK (chain_sequence > 0),
    CHECK (hmac_key_version > 0),
    CHECK (chain_algorithm = 'HMAC-SHA-256'),
    CHECK ((chain_sequence = 1 AND previous_hash IS NULL) OR (chain_sequence > 1 AND previous_hash IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS public.audit_anchors (
    id                  BIGSERIAL PRIMARY KEY,
    chain_partition     VARCHAR(80) NOT NULL,
    anchor_sequence     BIGINT NOT NULL,
    entry_hash          CHAR(64) NOT NULL,
    anchored_at         TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    signature           VARCHAR(512) NOT NULL,
    signer_key_id       VARCHAR(80) NOT NULL,
    status              VARCHAR(20) NOT NULL DEFAULT 'VALID'
);

-- 4.8. Cảnh báo An ninh, Quy tắc Phát hiện Bất thường & Quản lý Sự cố SOC (5 bảng)
CREATE TABLE IF NOT EXISTS public.security_alerts (
    id                  UUID PRIMARY KEY,
    alert_type          VARCHAR(80) NOT NULL,
    severity            public.severity_level NOT NULL,
    status              public.alert_status NOT NULL DEFAULT 'OPEN',
    title               VARCHAR(255) NOT NULL,
    description         TEXT NOT NULL,
    detected_user_id    BIGINT REFERENCES public.users(id) ON DELETE SET NULL,
    document_id         UUID REFERENCES public.documents(id) ON DELETE SET NULL,
    detected_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    assigned_to         BIGINT REFERENCES public.users(id) ON DELETE SET NULL,
    resolved_at         TIMESTAMPTZ,
    resolution_note     TEXT,
    CHECK ((status IN ('RESOLVED','FALSE_POSITIVE')) = (resolved_at IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS public.alert_audit_links (
    alert_id            UUID NOT NULL REFERENCES public.security_alerts(id) ON DELETE CASCADE,
    audit_log_id        BIGINT NOT NULL REFERENCES public.audit_logs(id) ON DELETE RESTRICT,
    PRIMARY KEY (alert_id, audit_log_id)
);

CREATE TABLE IF NOT EXISTS public.detection_rule_configs (
    id                  BIGSERIAL PRIMARY KEY,
    rule_code           VARCHAR(80) NOT NULL,
    name                VARCHAR(180) NOT NULL,
    description         TEXT,
    is_enabled          BOOLEAN NOT NULL DEFAULT TRUE,
    severity            public.severity_level NOT NULL DEFAULT 'HIGH',
    threshold           INTEGER NOT NULL DEFAULT 5,
    window_minutes      INTEGER NOT NULL DEFAULT 10,
    cooldown_minutes    INTEGER NOT NULL DEFAULT 30,
    parameters          JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at          TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_by          BIGINT REFERENCES public.users(id) ON DELETE SET NULL ON UPDATE NO ACTION
);

CREATE TABLE IF NOT EXISTS public.incident_reports (
    id                  UUID PRIMARY KEY,
    incident_code       VARCHAR(50) NOT NULL UNIQUE,
    alert_id            UUID REFERENCES public.security_alerts(id) ON DELETE SET NULL,
    title               VARCHAR(255) NOT NULL,
    summary             TEXT NOT NULL,
    findings            TEXT,
    impact_assessment   TEXT,
    status              public.incident_status NOT NULL DEFAULT 'DRAFT',
    prepared_by         BIGINT NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
    submitted_to_owner  BIGINT REFERENCES public.users(id) ON DELETE SET NULL,
    submitted_to_admin  BIGINT REFERENCES public.users(id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    submitted_at        TIMESTAMPTZ,
    closed_at           TIMESTAMPTZ,
    CHECK ((status = 'DRAFT') OR submitted_at IS NOT NULL),
    CHECK ((status = 'CLOSED') = (closed_at IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS public.incident_actions (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    incident_report_id  UUID NOT NULL REFERENCES public.incident_reports(id) ON DELETE CASCADE,
    action_type         VARCHAR(80) NOT NULL,
    recommendation      TEXT NOT NULL,
    assigned_to         BIGINT REFERENCES public.users(id) ON DELETE SET NULL,
    due_at              TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ,
    completion_note     TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (completed_at IS NULL OR completion_note IS NOT NULL)
);

-- 4.9. Thông báo, Hàng đợi Outbox, Xuất Báo cáo Bất đồng bộ & Sức khỏe Hệ thống (4 bảng)
CREATE TABLE IF NOT EXISTS public.notifications (
    id                  UUID PRIMARY KEY,
    recipient_id        BIGINT NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    notification_type   VARCHAR(80) NOT NULL,
    title               VARCHAR(255) NOT NULL,
    body                TEXT NOT NULL,
    related_object_type VARCHAR(80),
    related_object_id   VARCHAR(100),
    status              public.notification_status NOT NULL DEFAULT 'UNREAD',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    read_at             TIMESTAMPTZ,
    CHECK ((status = 'UNREAD' AND read_at IS NULL) OR (status <> 'UNREAD' AND read_at IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS public.notification_outbox (
    id                  UUID PRIMARY KEY,
    recipient_id        BIGINT NOT NULL REFERENCES public.users(id) ON DELETE CASCADE ON UPDATE NO ACTION,
    channel             VARCHAR(20) NOT NULL,
    notification_type   VARCHAR(80) NOT NULL,
    title               VARCHAR(255) NOT NULL,
    body                TEXT NOT NULL,
    payload             JSONB NOT NULL DEFAULT '{}'::jsonb,
    deduplication_key   VARCHAR(255) NOT NULL,
    status              VARCHAR(20) NOT NULL DEFAULT 'PENDING',
    attempt_count       INTEGER NOT NULL DEFAULT 0,
    max_attempts        INTEGER NOT NULL DEFAULT 5,
    next_retry_at       TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_error          TEXT,
    created_at          TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    processed_at        TIMESTAMPTZ(6)
);

CREATE TABLE IF NOT EXISTS public.async_export_jobs (
    id                  UUID PRIMARY KEY,
    requester_user_id   BIGINT NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT ON UPDATE NO ACTION,
    export_type         VARCHAR(80) NOT NULL,
    format              VARCHAR(20) NOT NULL,
    status              VARCHAR(20) NOT NULL DEFAULT 'PENDING',
    filter_params       JSONB NOT NULL DEFAULT '{}'::jsonb,
    file_path           VARCHAR(500),
    file_size_bytes     BIGINT,
    sha256_hash         CHAR(64),
    mime_type           VARCHAR(150),
    row_count           INTEGER NOT NULL DEFAULT 0,
    error_message       TEXT,
    created_at          TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at        TIMESTAMPTZ(6),
    expires_at          TIMESTAMPTZ(6) NOT NULL
);

CREATE TABLE IF NOT EXISTS public.system_health_snapshots (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    captured_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    service_name        VARCHAR(100) NOT NULL,
    status              VARCHAR(20) NOT NULL CHECK (status IN ('HEALTHY','DEGRADED','DOWN')),
    response_time_ms    INTEGER CHECK (response_time_ms >= 0),
    storage_used_bytes  BIGINT CHECK (storage_used_bytes >= 0),
    storage_total_bytes BIGINT CHECK (storage_total_bytes > 0),
    error_count         INTEGER NOT NULL DEFAULT 0 CHECK (error_count >= 0),
    details             JSONB NOT NULL DEFAULT '{}'::jsonb
);

-- 4.10. Bảng theo dõi lịch sử Migration của Prisma CLI
CREATE TABLE IF NOT EXISTS public._prisma_migrations (
    id                      VARCHAR(36) PRIMARY KEY,
    checksum                VARCHAR(64) NOT NULL,
    finished_at             TIMESTAMPTZ,
    migration_name          VARCHAR(255) NOT NULL,
    logs                    TEXT,
    rolled_back_at          TIMESTAMPTZ,
    started_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    applied_steps_count     INTEGER NOT NULL DEFAULT 0
);

-- =============================================================================
-- PHẦN 5: HỆ THỐNG CHỈ MỤC TỐI ƯU HÓA & RÀNG BUỘC DUY NHẤT CỤC BỘ (INDEXES)
-- =============================================================================

-- Người dùng, Vai trò & Thuộc tính ABAC
CREATE INDEX IF NOT EXISTS idx_users_department_status
  ON public.users(department_id, status);
CREATE INDEX IF NOT EXISTS idx_user_roles_active
  ON public.user_roles(user_id, role_id, valid_from, valid_to);
CREATE INDEX IF NOT EXISTS idx_user_attrs_active
  ON public.user_attribute_assignments(user_id, attribute_definition_id, valid_from, valid_to);

-- Phiên xác thực, Refresh Token & MFA
CREATE INDEX IF NOT EXISTS idx_auth_sessions_user_status
  ON public.auth_sessions(user_id, status, expires_at);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_session_expiry
  ON public.refresh_tokens(auth_session_id, expires_at);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family
  ON public.refresh_tokens(token_family_id, revoked_at);
CREATE INDEX IF NOT EXISTS idx_mfa_methods_user_active
  ON public.mfa_methods(user_id, enabled_at, disabled_at);
-- Thuật toán: Chỉ mục duy nhất từng phần (`uq_mfa_active_totp_per_user`) bảo đảm mỗi người dùng chỉ có tối đa 1 phương thức `TOTP` đang hoạt động,
-- đồng thời cho phép đăng ký song song nhiều khóa bảo mật phần cứng FIDO2/`WEBAUTHN`.
DROP INDEX IF EXISTS public.uq_mfa_active_totp_per_user;
CREATE UNIQUE INDEX IF NOT EXISTS uq_mfa_active_totp_per_user
  ON public.mfa_methods(user_id, method_type)
  WHERE disabled_at IS NULL AND method_type = 'TOTP';
CREATE INDEX IF NOT EXISTS idx_password_reset_user_expiry
  ON public.password_reset_tokens(user_id, expires_at);

-- Tài liệu, Phiên bản, Phân loại SCD Type 2 & Tìm kiếm Toàn văn / Trigram
CREATE INDEX IF NOT EXISTS idx_documents_owner_status
  ON public.documents(owner_id, status);
CREATE INDEX IF NOT EXISTS idx_documents_department_status
  ON public.documents(department_id, status);
CREATE INDEX IF NOT EXISTS idx_document_versions_document
  ON public.document_versions(document_id, version_no DESC);
-- Thuật toán: Chỉ mục duy nhất từng phần SCD Type 2 (`uq_document_current_classification`) cưỡng chế mỗi tài liệu
-- chỉ có duy nhất một bản ghi phân loại độ mật đang hiệu lực (`effective_to IS NULL`) tại mọi thời điểm.
CREATE UNIQUE INDEX IF NOT EXISTS uq_document_current_classification
  ON public.document_classification_history(document_id)
  WHERE effective_to IS NULL;
-- Thuật toán: Cặp chỉ mục đảo GIN Trigram (`gin_trgm_ops`) tách chuỗi thành tập bộ 3 ký tự để tăng tốc truy vấn khớp mờ (`ILIKE`, `%`).
CREATE INDEX IF NOT EXISTS idx_documents_title_trgm
  ON public.documents USING gin (title gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_documents_code_trgm
  ON public.documents USING gin (document_code gin_trgm_ops);
-- Thuật toán: Chỉ mục đảo GIN Full-Text Search trên biểu thức `to_tsvector('simple', ...)` ghép tiêu đề, mô tả và mã hiệu tài liệu,
-- sử dụng cấu hình `'simple'` không cắt gốc từ để hỗ trợ tìm kiếm tiếng Việt chính xác.
CREATE INDEX IF NOT EXISTS idx_documents_fts
  ON public.documents USING gin (
    to_tsvector('simple', coalesce(title, '') || ' ' || coalesce(description, '') || ' ' || coalesce(document_code, ''))
  );
-- Thuật toán: Chỉ mục từng phần loại bỏ sẵn các tài liệu đã xóa mềm (`status NOT IN ('DELETED')`) khi lọc tìm kiếm có kiểm soát quyền.
CREATE INDEX IF NOT EXISTS idx_documents_discoverable_status
  ON public.documents(discoverable, status)
  WHERE status NOT IN ('DELETED');

-- Yêu cầu Truy cập, Cấp quyền & Phiên xem Tài liệu
CREATE INDEX IF NOT EXISTS idx_access_requests_owner_queue
  ON public.access_requests(document_id, status, submitted_at);
CREATE INDEX IF NOT EXISTS idx_access_requests_requester
  ON public.access_requests(requester_id, status, submitted_at DESC);
CREATE INDEX IF NOT EXISTS idx_access_grants_user_active
  ON public.access_grants(principal_user_id, document_id, status, valid_until);
CREATE INDEX IF NOT EXISTS idx_access_grants_role_active
  ON public.access_grants(principal_role_id, document_id, status, valid_until);
-- Thuật toán: Hệ thống chỉ mục từng phần (Partial & Partial Unique Indexes) bảo vệ bất biến cấp quyền và tăng tốc tiến trình nền:
-- - `uq_access_grants_request`: ánh xạ 1-1 giữa phiếu yêu cầu đã duyệt và quyền được cấp.
-- - `uq_access_grant_active_user` / `uq_access_grant_active_role`: triệt tiêu tình trạng cấp trùng quyền `ACTIVE` trên cùng tài liệu.
-- - `idx_access_grants_expiry` & `idx_access_sessions_grant_active`: tối ưu hóa quét lô hết hạn `FOR UPDATE SKIP LOCKED` và thu hồi phiên tức thì.
CREATE INDEX IF NOT EXISTS idx_access_grants_doc_user_active
  ON public.access_grants(document_id, principal_user_id, status, valid_from, valid_until)
  WHERE status = 'ACTIVE';
CREATE UNIQUE INDEX IF NOT EXISTS uq_access_grants_request
  ON public.access_grants(access_request_id)
  WHERE access_request_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_access_grant_active_user
  ON public.access_grants(document_id, principal_user_id)
  WHERE status = 'ACTIVE' AND principal_type = 'USER';
CREATE UNIQUE INDEX IF NOT EXISTS uq_access_grant_active_role
  ON public.access_grants(document_id, principal_role_id)
  WHERE status = 'ACTIVE' AND principal_type = 'ROLE';
CREATE INDEX IF NOT EXISTS idx_access_grants_expiry
  ON public.access_grants(status, valid_until)
  WHERE status = 'ACTIVE';
CREATE INDEX IF NOT EXISTS idx_sessions_user_active
  ON public.access_sessions(user_id, status, last_activity_at DESC);
CREATE INDEX IF NOT EXISTS idx_access_sessions_grant_active
  ON public.access_sessions(access_grant_id, status)
  WHERE status = 'ACTIVE';

-- Nhật ký Kiểm toán Bất biến & Điểm neo Chữ ký
CREATE INDEX IF NOT EXISTS idx_audit_actor_time
  ON public.audit_logs(actor_user_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_document_time
  ON public.audit_logs(document_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action_time
  ON public.audit_logs(action, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_outcome_time
  ON public.audit_logs(outcome, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_partition_time
  ON public.audit_logs(chain_partition, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_occurred_at
  ON public.audit_logs(occurred_at DESC);
-- Thuật toán: Chỉ mục đảo GIN trên trường JSONB `details` và cặp chỉ mục duy nhất (`uq_audit_chain_position`, `uq_audit_chain_entry_hash`)
-- bảo đảm tính tuyến tính không phân nhánh của chuỗi băm kiểm toán trên từng `chain_partition`.
CREATE INDEX IF NOT EXISTS idx_audit_details_gin
  ON public.audit_logs USING GIN (details);
CREATE UNIQUE INDEX IF NOT EXISTS uq_audit_chain_position
  ON public.audit_logs(chain_partition, chain_sequence);
CREATE UNIQUE INDEX IF NOT EXISTS uq_audit_chain_entry_hash
  ON public.audit_logs(chain_partition, entry_hash);
CREATE INDEX IF NOT EXISTS idx_audit_anchor_partition
  ON public.audit_anchors(chain_partition, anchor_sequence DESC);

-- Cảnh báo SOC, Quy tắc Phát hiện, Thông báo, Outbox & Xuất Báo cáo
CREATE INDEX IF NOT EXISTS idx_alert_status_severity
  ON public.security_alerts(status, severity, detected_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS detection_rule_configs_rule_code_key
  ON public.detection_rule_configs(rule_code);
CREATE INDEX IF NOT EXISTS idx_notifications_recipient
  ON public.notifications(recipient_id, status, created_at DESC);
-- Thuật toán: Chỉ mục duy nhất chống trùng lặp hàng đợi Transactional Outbox (`idx_outbox_dedup`), chỉ mục quét lịch thử lại lùi mũ (`idx_outbox_pending`)
-- và chỉ mục thu dọn tệp báo cáo bất đồng bộ hết hạn TTL (`idx_export_jobs_expires`).
CREATE UNIQUE INDEX IF NOT EXISTS idx_outbox_dedup
  ON public.notification_outbox(deduplication_key);
CREATE INDEX IF NOT EXISTS idx_outbox_pending
  ON public.notification_outbox(status, next_retry_at);
CREATE INDEX IF NOT EXISTS idx_export_jobs_user_status
  ON public.async_export_jobs(requester_user_id, status);
CREATE INDEX IF NOT EXISTS idx_export_jobs_expires
  ON public.async_export_jobs(expires_at);

-- =============================================================================
-- PHẦN 6: 9 HÀM PL/pgSQL (PINNED SEARCH_PATH) & 19 TRIGGER TOÀN VẸN DỮ LIỆU
-- =============================================================================

-- 6.1. Thuật toán tự động làm mới dấu thời gian sửa đổi (`set_updated_at`, 8 triggers):
-- Ghi đè trực tiếp `NEW.updated_at := now()` ở pha `BEFORE UPDATE` cấp dòng để triệt tiêu mọi giá trị thời gian cũ hoặc giả mạo từ tầng ứng dụng.
CREATE OR REPLACE FUNCTION public.set_updated_at()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, extensions
AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_departments_updated ON public.departments;
CREATE TRIGGER trg_departments_updated
  BEFORE UPDATE ON public.departments
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

DROP TRIGGER IF EXISTS trg_users_updated ON public.users;
CREATE TRIGGER trg_users_updated
  BEFORE UPDATE ON public.users
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

DROP TRIGGER IF EXISTS trg_roles_updated ON public.roles;
CREATE TRIGGER trg_roles_updated
  BEFORE UPDATE ON public.roles
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

DROP TRIGGER IF EXISTS trg_attribute_definitions_updated ON public.attribute_definitions;
CREATE TRIGGER trg_attribute_definitions_updated
  BEFORE UPDATE ON public.attribute_definitions
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

DROP TRIGGER IF EXISTS trg_policy_rules_updated ON public.policy_rules;
CREATE TRIGGER trg_policy_rules_updated
  BEFORE UPDATE ON public.policy_rules
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

DROP TRIGGER IF EXISTS trg_documents_updated ON public.documents;
CREATE TRIGGER trg_documents_updated
  BEFORE UPDATE ON public.documents
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

DROP TRIGGER IF EXISTS trg_access_requests_updated ON public.access_requests;
CREATE TRIGGER trg_access_requests_updated
  BEFORE UPDATE ON public.access_requests
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

DROP TRIGGER IF EXISTS trg_watermark_configs_updated ON public.watermark_configs;
CREATE TRIGGER trg_watermark_configs_updated
  BEFORE UPDATE ON public.watermark_configs
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

-- 6.2. Thuật toán kiểm chứng toàn vẹn tham chiếu vòng phiên bản tài liệu (`validate_current_document_version`, 1 trigger):
-- Khi `NEW.current_version_id IS NOT NULL`, đối chiếu bảng `document_versions` bảo đảm bản ghi phiên bản tồn tại và thuộc chính xác `NEW.id` trước khi cho phép ghi.
CREATE OR REPLACE FUNCTION public.validate_current_document_version()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, extensions
AS $$
BEGIN
  IF NEW.current_version_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM public.document_versions v
    WHERE v.id = NEW.current_version_id AND v.document_id = NEW.id
  ) THEN
    RAISE EXCEPTION 'current_version_id does not belong to document';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_validate_current_document_version ON public.documents;
CREATE TRIGGER trg_validate_current_document_version
  BEFORE INSERT OR UPDATE OF current_version_id ON public.documents
  FOR EACH ROW EXECUTE FUNCTION public.validate_current_document_version();

-- 6.3. Thuật toán kiểm soát truy cập đa mức Bell-LaPadula Simple Security Property & Phân tách Nhiệm vụ SoD (`validate_user_clearance_for_grant`, 1 trigger):
-- Cưỡng chế đồng thời cho cả `USER` và `ROLE` grant (phép giao bảo thủ Lattice Meet trên tập người giữ vai trò đang hoạt động + chặn vai trò quản trị/an ninh/kiểm toán SoD).
-- CONFLICT-RESOLVED: Mở rộng trigger Bell-LaPadula/SoD cho `ROLE` grant để đồng bộ 100% với migration 20261105210000 (HIGH-12).
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
      IF EXISTS (
        SELECT 1
        FROM public.roles r
        WHERE r.id = NEW.principal_role_id
          AND (
            r.code IN ('SYSTEM_ADMIN', 'SECURITY_OFFICER', 'AUDITOR')
            OR EXISTS (
              SELECT 1
              FROM public.role_permissions rp
              JOIN public.permissions p ON p.id = rp.permission_id
              WHERE rp.role_id = r.id
                AND (p.resource_type || ':' || p.action) IN (
                  'USER:MANAGE',
                  'ROLE:MANAGE',
                  'POLICY_RULE:MANAGE',
                  'ATTRIBUTE_DEFINITION:MANAGE',
                  'AUDIT_LOG:READ',
                  'AUDIT_LOG:VERIFY',
                  'AUDIT_LOG:EXPORT',
                  'SECURITY_ALERT:READ',
                  'SECURITY_ALERT:MANAGE',
                  'INCIDENT_REPORT:CREATE',
                  'INCIDENT_REPORT:UPDATE',
                  'INCIDENT_REPORT:CLOSE',
                  'WATERMARK_CONFIG:MANAGE',
                  'WATERMARK_INSTANCE:TRACE',
                  'CLASSIFICATION_LEVEL:MANAGE',
                  'SYSTEM_HEALTH:READ'
                )
            )
          )
      ) THEN
        RAISE EXCEPTION 'Separation of duties violation: administrative, security, or audit roles cannot receive document grants';
      END IF;

      SELECT count(*)::int, min(coalesce(holder_clearance.max_rank, 0))
      INTO holder_count, min_role_rank
      FROM (
        SELECT DISTINCT ur.user_id
        FROM public.user_roles ur
        JOIN public.users u ON u.id = ur.user_id
        WHERE ur.role_id = NEW.principal_role_id
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

DROP TRIGGER IF EXISTS trg_validate_user_clearance_for_grant ON public.access_grants;
CREATE TRIGGER trg_validate_user_clearance_for_grant
  BEFORE INSERT OR UPDATE OF principal_type, principal_user_id, principal_role_id, document_id, status ON public.access_grants
  FOR EACH ROW EXECUTE FUNCTION public.validate_user_clearance_for_grant();

-- 6.4. Thuật toán kiểm chứng tính liên tục chuỗi băm mật mã HMAC-SHA-256 (`validate_audit_chain_link`, 1 trigger):
-- Khóa tuần tự hóa phân vùng chuỗi bằng `pg_advisory_xact_lock(hashtextextended(NEW.chain_partition, 0))`, bảo đảm bản ghi đầu tiên (`chain_sequence = 1`) là duy nhất và mọi bản ghi kế tiếp có `NEW.previous_hash` khớp tuyệt đối với `entry_hash` của `chain_sequence - 1`.
CREATE OR REPLACE FUNCTION public.validate_audit_chain_link()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, extensions
AS $$
DECLARE
  expected_previous_hash CHAR(64);
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended(NEW.chain_partition, 0));

  IF NEW.chain_sequence = 1 THEN
    IF EXISTS (SELECT 1 FROM public.audit_logs WHERE chain_partition = NEW.chain_partition) THEN
      RAISE EXCEPTION 'audit chain already initialized for partition';
    END IF;
    RETURN NEW;
  END IF;

  SELECT entry_hash INTO expected_previous_hash
  FROM public.audit_logs
  WHERE chain_partition = NEW.chain_partition
    AND chain_sequence = NEW.chain_sequence - 1;

  IF expected_previous_hash IS NULL OR NEW.previous_hash IS DISTINCT FROM expected_previous_hash THEN
    RAISE EXCEPTION 'audit chain previous_hash mismatch';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_validate_audit_chain_link ON public.audit_logs;
CREATE TRIGGER trg_validate_audit_chain_link
  BEFORE INSERT ON public.audit_logs
  FOR EACH ROW EXECUTE FUNCTION public.validate_audit_chain_link();

-- 6.5. Thuật toán cưỡng chế tính bất biến chỉ ghi nối thêm Append-Only (`prevent_audit_mutation`, 4 triggers):
-- Chặn vô điều kiện mọi lệnh `UPDATE`, `DELETE` (mức dòng) và `TRUNCATE` (mức câu lệnh) trên `audit_logs` và `audit_anchors` bằng ngoại lệ cấp engine ở pha `BEFORE`.
CREATE OR REPLACE FUNCTION public.prevent_audit_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, extensions
AS $$
BEGIN
  RAISE EXCEPTION 'audit_logs is append-only';
END;
$$;

DROP TRIGGER IF EXISTS trg_audit_no_update ON public.audit_logs;
CREATE TRIGGER trg_audit_no_update
  BEFORE UPDATE OR DELETE ON public.audit_logs
  FOR EACH ROW EXECUTE FUNCTION public.prevent_audit_mutation();

DROP TRIGGER IF EXISTS trg_audit_no_truncate ON public.audit_logs;
CREATE TRIGGER trg_audit_no_truncate
  BEFORE TRUNCATE ON public.audit_logs
  FOR EACH STATEMENT EXECUTE FUNCTION public.prevent_audit_mutation();

DROP TRIGGER IF EXISTS trg_audit_anchor_no_update ON public.audit_anchors;
CREATE TRIGGER trg_audit_anchor_no_update
  BEFORE UPDATE OR DELETE ON public.audit_anchors
  FOR EACH ROW EXECUTE FUNCTION public.prevent_audit_mutation();

DROP TRIGGER IF EXISTS trg_audit_anchor_no_truncate ON public.audit_anchors;
CREATE TRIGGER trg_audit_anchor_no_truncate
  BEFORE TRUNCATE ON public.audit_anchors
  FOR EACH STATEMENT EXECUTE FUNCTION public.prevent_audit_mutation();

-- 6.6. Thuật toán bảo toàn họ khóa xoay vòng Refresh Token (`validate_refresh_token_family`, 1 trigger):
-- Xác minh cặp `(NEW.auth_session_id, NEW.token_family_id)` khớp với phiên gốc trong `auth_sessions` nhằm ngăn gắn nhầm hoặc giả mạo chuỗi xoay vòng token.
CREATE OR REPLACE FUNCTION public.validate_refresh_token_family()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, extensions
AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public.auth_sessions s
    WHERE s.id = NEW.auth_session_id AND s.token_family_id = NEW.token_family_id
  ) THEN
    RAISE EXCEPTION 'refresh token family does not match auth session';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_validate_refresh_token_family ON public.refresh_tokens;
CREATE TRIGGER trg_validate_refresh_token_family
  BEFORE INSERT OR UPDATE OF auth_session_id, token_family_id ON public.refresh_tokens
  FOR EACH ROW EXECUTE FUNCTION public.validate_refresh_token_family();

-- 6.7. Thuật toán phát hiện chu trình đồ thị cây có hướng bằng đệ quy CTE (`prevent_department_cycle`, 1 trigger):
-- Chặn tự tham chiếu (`NEW.parent_id = NEW.id`) và dùng `WITH RECURSIVE descendants` duyệt bao đóng bắc cầu các nút con cháu của `NEW.id`; ném lỗi `23514` nếu `NEW.parent_id` nằm trong tập con cháu.
CREATE OR REPLACE FUNCTION public.prevent_department_cycle()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, extensions
AS $$
BEGIN
  IF NEW.parent_id IS NULL THEN
    RETURN NEW;
  END IF;
  IF NEW.id IS NOT NULL AND NEW.parent_id = NEW.id THEN
    RAISE EXCEPTION 'department cannot be its own parent' USING ERRCODE = '23514';
  END IF;
  -- Thuật toán: Duyệt cây đệ quy (`WITH RECURSIVE`) thu thập bao đóng bắc cầu các phòng ban con cháu của `NEW.id` để phát hiện chu trình
  IF NEW.id IS NOT NULL AND EXISTS (
    WITH RECURSIVE descendants AS (
      SELECT id FROM public.departments WHERE parent_id = NEW.id
      UNION ALL
      SELECT d.id FROM public.departments d JOIN descendants x ON d.parent_id = x.id
    )
    SELECT 1 FROM descendants WHERE id = NEW.parent_id
  ) THEN
    RAISE EXCEPTION 'department hierarchy cycle detected' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_prevent_department_cycle ON public.departments;
CREATE TRIGGER trg_prevent_department_cycle
  BEFORE INSERT OR UPDATE OF parent_id ON public.departments
  FOR EACH ROW EXECUTE FUNCTION public.prevent_department_cycle();

-- 6.8. Thuật toán vô hiệu hóa bộ đệm ABAC bằng bộ đếm phiên bản đơn điệu toàn cục (`bump_abac_row_version` & `bump_abac_parent_version`, 4 triggers):
-- Cấp số thứ tự tăng nghiêm ngặt từ sequence `abac_policy_version_seq` mỗi khi định nghĩa thuộc tính, tùy chọn ENUM, quy tắc chính sách hoặc điều kiện con thay đổi thực chất (loại trừ `updated_at`), chống ghi lùi phiên bản.
CREATE OR REPLACE FUNCTION public.bump_abac_row_version()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, extensions
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    PERFORM nextval('public.abac_policy_version_seq');
    RETURN OLD;
  END IF;
  IF NEW.version IS DISTINCT FROM OLD.version
    OR (to_jsonb(NEW) - 'updated_at' - 'version')
      IS DISTINCT FROM (to_jsonb(OLD) - 'updated_at' - 'version') THEN
    NEW.version := nextval('public.abac_policy_version_seq');
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_attribute_definitions_version ON public.attribute_definitions;
CREATE TRIGGER trg_attribute_definitions_version
  BEFORE UPDATE OR DELETE ON public.attribute_definitions
  FOR EACH ROW EXECUTE FUNCTION public.bump_abac_row_version();

DROP TRIGGER IF EXISTS trg_policy_rules_version ON public.policy_rules;
CREATE TRIGGER trg_policy_rules_version
  BEFORE UPDATE OR DELETE ON public.policy_rules
  FOR EACH ROW EXECUTE FUNCTION public.bump_abac_row_version();

-- Thuật toán: Lan truyền tăng phiên bản từ thực thể con lên thực thể cha tổng hợp (`public.bump_abac_parent_version` - Aggregate Root Version Propagation).
-- Khi thêm/sửa/xóa `attribute_options` hoặc `policy_rule_conditions`, tự động nhảy `version` trên bảng cha (`attribute_definitions` hoặc `policy_rules`,
-- bao gồm cả cha cũ và cha mới nếu chuyển khóa ngoại) để buộc PDP tải lại cấu hình chính sách mới nhất.
CREATE OR REPLACE FUNCTION public.bump_abac_parent_version()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, extensions
AS $$
DECLARE
  parent_id BIGINT;
BEGIN
  IF TG_OP = 'UPDATE' AND to_jsonb(NEW) IS NOT DISTINCT FROM to_jsonb(OLD) THEN
    RETURN NEW;
  END IF;
  IF TG_TABLE_NAME = 'attribute_options' THEN
    IF TG_OP = 'UPDATE' AND OLD.attribute_definition_id <> NEW.attribute_definition_id THEN
      UPDATE public.attribute_definitions
      SET version = nextval('public.abac_policy_version_seq')
      WHERE id = OLD.attribute_definition_id;
    END IF;
    parent_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.attribute_definition_id ELSE NEW.attribute_definition_id END;
    UPDATE public.attribute_definitions
    SET version = nextval('public.abac_policy_version_seq')
    WHERE id = parent_id;
  ELSE
    IF TG_OP = 'UPDATE' AND OLD.policy_rule_id <> NEW.policy_rule_id THEN
      UPDATE public.policy_rules
      SET version = nextval('public.abac_policy_version_seq')
      WHERE id = OLD.policy_rule_id;
    END IF;
    parent_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.policy_rule_id ELSE NEW.policy_rule_id END;
    UPDATE public.policy_rules
    SET version = nextval('public.abac_policy_version_seq')
    WHERE id = parent_id;
  END IF;
  IF TG_OP = 'DELETE' THEN
    RETURN OLD;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_attribute_options_version ON public.attribute_options;
CREATE TRIGGER trg_attribute_options_version
  AFTER INSERT OR UPDATE OR DELETE ON public.attribute_options
  FOR EACH ROW EXECUTE FUNCTION public.bump_abac_parent_version();

DROP TRIGGER IF EXISTS trg_policy_rule_conditions_version ON public.policy_rule_conditions;
CREATE TRIGGER trg_policy_rule_conditions_version
  AFTER INSERT OR UPDATE OR DELETE ON public.policy_rule_conditions
  FOR EACH ROW EXECUTE FUNCTION public.bump_abac_parent_version();

-- =============================================================================
-- PHẦN 7: KHÓA CHẶT SUPABASE ROW LEVEL SECURITY (RLS) & POSTGREST DATA API
-- (Zero-Trust: Chặn hoàn toàn truy cập trực tiếp từ anon/authenticated qua PostgREST;
--  mọi luồng dữ liệu bắt buộc đi qua NestJS PEP / Worker sử dụng kết nối Backend)
-- =============================================================================

-- Thuật toán: Khối lặp động PL/pgSQL cưỡng chế mô hình Zero-Trust Row Level Security (RLS Default-Deny) trên toàn bộ 40 bảng trong schema `public`:
-- kích hoạt RLS, thu hồi toàn bộ quyền truy cập bảng và sequence khỏi vai trò công khai `anon`/`authenticated` (chặn truy cập PostgREST trực tiếp),
-- và chỉ cấp đặc quyền cho `service_role` phục vụ kết nối máy chủ tin cậy.
DO $$
DECLARE
  tbl TEXT;
BEGIN
  FOREACH tbl IN ARRAY ARRAY[
    '_prisma_migrations',
    'access_grant_permissions',
    'access_grants',
    'access_request_decisions',
    'access_request_permissions',
    'access_requests',
    'access_sessions',
    'alert_audit_links',
    'async_export_jobs',
    'attribute_definitions',
    'attribute_options',
    'audit_anchors',
    'audit_logs',
    'auth_sessions',
    'business_categories',
    'classification_levels',
    'departments',
    'detection_rule_configs',
    'document_classification_history',
    'document_versions',
    'documents',
    'incident_actions',
    'incident_reports',
    'mfa_methods',
    'notification_outbox',
    'notifications',
    'password_reset_tokens',
    'permissions',
    'policy_rule_conditions',
    'policy_rules',
    'refresh_tokens',
    'role_permissions',
    'roles',
    'security_alerts',
    'system_health_snapshots',
    'user_attribute_assignments',
    'user_roles',
    'users',
    'watermark_configs',
    'watermark_instances'
  ]
  LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', tbl);
    EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', tbl);

    EXECUTE format('DROP POLICY IF EXISTS p_zero_trust_postgrest_deny ON public.%I', tbl);
    EXECUTE format(
      'CREATE POLICY p_zero_trust_postgrest_deny ON public.%I AS RESTRICTIVE FOR ALL TO PUBLIC '
      || 'USING (current_user NOT IN (''anon'', ''authenticated'') AND coalesce(current_setting(''request.jwt.claim.role'', true), '''') NOT IN (''anon'', ''authenticated'') AND coalesce((nullif(current_setting(''request.jwt.claims'', true), '''')::jsonb ->> ''role''), '''') NOT IN (''anon'', ''authenticated'')) '
      || 'WITH CHECK (current_user NOT IN (''anon'', ''authenticated'') AND coalesce(current_setting(''request.jwt.claim.role'', true), '''') NOT IN (''anon'', ''authenticated'') AND coalesce((nullif(current_setting(''request.jwt.claims'', true), '''')::jsonb ->> ''role''), '''') NOT IN (''anon'', ''authenticated''))',
      tbl
    );

    EXECUTE format('DROP POLICY IF EXISTS p_zero_trust_backend_allow ON public.%I', tbl);
    EXECUTE format(
      'CREATE POLICY p_zero_trust_backend_allow ON public.%I AS PERMISSIVE FOR ALL TO PUBLIC '
      || 'USING ((current_user IN (''postgres'', ''service_role'', ''supabase_admin'', ''sda'', ''sda_local'', ''sda_app'', ''prisma'') OR EXISTS (SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname = current_user AND (r.rolsuper OR r.rolbypassrls))) AND coalesce(current_setting(''request.jwt.claim.role'', true), '''') NOT IN (''anon'', ''authenticated'') AND coalesce((nullif(current_setting(''request.jwt.claims'', true), '''')::jsonb ->> ''role''), '''') NOT IN (''anon'', ''authenticated'')) '
      || 'WITH CHECK ((current_user IN (''postgres'', ''service_role'', ''supabase_admin'', ''sda'', ''sda_local'', ''sda_app'', ''prisma'') OR EXISTS (SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname = current_user AND (r.rolsuper OR r.rolbypassrls))) AND coalesce(current_setting(''request.jwt.claim.role'', true), '''') NOT IN (''anon'', ''authenticated'') AND coalesce((nullif(current_setting(''request.jwt.claims'', true), '''')::jsonb ->> ''role''), '''') NOT IN (''anon'', ''authenticated''))',
      tbl
    );

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
      EXECUTE format('REVOKE ALL ON TABLE public.%I FROM anon', tbl);
    END IF;

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
      EXECUTE format('REVOKE ALL ON TABLE public.%I FROM authenticated', tbl);
    END IF;

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
      EXECUTE format('REVOKE ALL ON TABLE public.%I FROM service_role', tbl);
      IF tbl IN ('audit_logs', 'audit_anchors') THEN
        EXECUTE format('GRANT SELECT, INSERT ON TABLE public.%I TO service_role', tbl);
      ELSE
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.%I TO service_role', tbl);
      END IF;
    END IF;
  END LOOP;

  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM anon;
  END IF;

  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM authenticated;
  END IF;

  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
    GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO service_role;
  END IF;
END $$;

-- =============================================================================
-- PHẦN 8: ĐỒNG BỘ BẢNG _prisma_migrations (KHỚP 100% SHA-256 CHECKSUM VỚI PRISMA CLI)
-- =============================================================================

-- Thuật toán: Đồng bộ lũy đẳng lịch sử áp dụng migration (`WHERE NOT EXISTS`) bằng cách đối chiếu tên migration và mã băm toàn vẹn SHA-256 chuẩn của Prisma CLI.
INSERT INTO public._prisma_migrations (id, checksum, finished_at, migration_name, started_at, applied_steps_count)
SELECT v.id, v.checksum, now(), v.migration_name, now(), 1
FROM (
  VALUES
    -- CONFLICT-RESOLVED: Synchronized SHA-256 checksums across all 12 Prisma migration files
    ('00000000-0000-4000-8000-000000000001', '888f80f07b278005583e833af6a81983bd14ced9314ca04d0ca37749abe4fa07', '20260917160000_initial_secure_schema'),
    ('00000000-0000-4000-8000-000000000002', '62afc2f3ebe6bbc85c8b92b676091ff4ae62255906b9b6fb71845b143e9a9629', '20260919120000_hardened_authentication'),
    ('00000000-0000-4000-8000-000000000003', '704e601658fb17e709e81f31abfae3e938faf4b869ee29c17b608a7adc7181ec', '20260919180000_scoped_rbac_administration'),
    ('00000000-0000-4000-8000-000000000004', '76ce761a52506e37be9a3338df3c248b8d763ec481596df10a070f004790ec73', '20260922120000_deterministic_abac'),
    ('00000000-0000-4000-8000-000000000005', 'b5e2276887ce76292220f3b0a3aaca273a704f616038f1f9eb0a5e792fa57f2d', '20260923120000_document_search_indexes'),
    ('00000000-0000-4000-8000-000000000006', '7965ab37b62a6bcef361180562f5749cf302bbf80ff2804b5b76c404db04f24a', '20260923170000_access_grant_indexes'),
    ('00000000-0000-4000-8000-000000000007', 'a91fe5f6f541f59aa913226569d471c305ed93036ee33f03e0990e57d9bde025', '20260923180000_audit_anchors_and_partition_indexes'),
    ('00000000-0000-4000-8000-000000000008', '57847f304f12740360ee357170f6fe0335edec964ee258945b4f24f5dc51f581', '20260923200000_security_ops_and_incident_management'),
    ('00000000-0000-4000-8000-000000000009', '442f6b5eb9efb20b8b132d934f3dbc2ecafde4843dc7bf0721077b9e8a152e6d', '20261031120000_supabase_rls_and_mfa_webauthn'),
    ('00000000-0000-4000-8000-000000000010', '6a366ad5437851cb216414080c6b56789741bf408ce190f6ebd2c89249cdf43c', '20261105133000_rls_policies_and_audit_truncate_guard'),
    ('00000000-0000-4000-8000-000000000011', '52f89c902eb0daf6955ae415e43491e9a663a4a3c0a98aacad78125a2015523d', '20261105160000_prisma_migrations_rls_hardening'),
    ('00000000-0000-4000-8000-000000000012', 'e304141e09963409f64aad5c5196b4011db31ceb9dd8fc2ebc3d03f64e59f34f', '20261105210000_harden_rls_allowlist_and_role_grant_trigger')
) AS v(id, checksum, migration_name)
WHERE NOT EXISTS (
  SELECT 1 FROM public._prisma_migrations pm WHERE pm.migration_name = v.migration_name
);

-- =============================================================================
-- PHẦN 9: DỮ LIỆU KHỞI TẠO NỀN TẢNG (IDEMPOTENT BASELINE SEED)
-- (Tuân thủ nghiêm ngặt chính sách không lưu mật khẩu tĩnh trong mã nguồn)
--
-- Thuật toán tổng quan khối Seed tất định (Idempotent Deterministic Upsert Seed):
-- Sử dụng khóa tự nhiên (`username`, `code`, `(role_id, permission_id)`, `(attribute_definition_id, value_code)`, `(policy_rule_id, condition_group, sequence_no)`)
-- kết hợp mệnh đề `ON CONFLICT ... DO UPDATE / DO NOTHING` và kiểm tra `WHERE NOT EXISTS` để tái lập trạng thái chuẩn hội tụ 100% sau số lần thực thi bất kỳ.
-- =============================================================================

-- 9.1. Tài khoản hệ thống phục vụ tham chiếu khóa ngoại khi khởi tạo (không thể đăng nhập)
-- Thuật toán: Khởi tạo tác nhân gốc `system.seed` ở trạng thái khóa vô hiệu hóa (`DISABLED`) với giá trị sentinel không thể khớp hàm băm xác thực.
INSERT INTO public.users (username, email, password_hash, full_name, status, disabled_at)
VALUES (
  'system.seed',
  'system.seed@local.invalid',
  '!AUTHENTICATION_NOT_CONFIGURED_DEMO_ACCOUNT!',
  'System Seed Actor',
  'DISABLED',
  '2026-01-01T00:00:00Z'::timestamptz
)
ON CONFLICT (username) DO UPDATE
SET full_name = EXCLUDED.full_name;

-- 9.2. Cây Phòng ban mẫu
INSERT INTO public.departments (code, name, parent_id, is_active)
VALUES ('HEAD_OFFICE', 'Khối văn phòng', NULL, TRUE)
ON CONFLICT (code) DO UPDATE
SET name = EXCLUDED.name, is_active = TRUE;

INSERT INTO public.departments (code, name, parent_id, is_active)
VALUES
  ('INFORMATION_SECURITY', 'Phòng An toàn thông tin', (SELECT id FROM public.departments WHERE code = 'HEAD_OFFICE'), TRUE),
  ('LEGAL_COMPLIANCE', 'Ban Pháp chế & Tuân thủ', (SELECT id FROM public.departments WHERE code = 'HEAD_OFFICE'), TRUE),
  ('FINANCE_TREASURY', 'Phòng Tài chính - Kế toán', (SELECT id FROM public.departments WHERE code = 'HEAD_OFFICE'), TRUE),
  ('RND_ENGINEERING', 'Khối Công nghệ & Kỹ thuật', (SELECT id FROM public.departments WHERE code = 'HEAD_OFFICE'), TRUE)
ON CONFLICT (code) DO UPDATE
SET name = EXCLUDED.name, parent_id = EXCLUDED.parent_id, is_active = TRUE;

-- 9.3. Danh mục Nghiệp vụ Tài liệu
INSERT INTO public.business_categories (code, name, department_id, description, is_active)
VALUES
  ('GENERAL_OPERATIONS', 'Nghiệp vụ chung', (SELECT id FROM public.departments WHERE code = 'HEAD_OFFICE'), 'Văn bản điều hành và quy trình nội bộ chung', TRUE),
  ('SECURITY_OPERATIONS', 'An toàn thông tin', (SELECT id FROM public.departments WHERE code = 'INFORMATION_SECURITY'), 'Chính sách bảo mật, báo cáo SOC và biên bản điều tra sự cố', TRUE),
  ('LEGAL_CONTRACTS', 'Hồ sơ Pháp lý & Hợp đồng', (SELECT id FROM public.departments WHERE code = 'LEGAL_COMPLIANCE'), 'Hợp đồng chiến lược, biên bản thỏa thuận bảo mật NDA', TRUE),
  ('FINANCIAL_REPORTS', 'Báo cáo Tài chính & Ngân sách', (SELECT id FROM public.departments WHERE code = 'FINANCE_TREASURY'), 'Báo cáo kiểm toán tài chính, dự toán ngân sách trọng yếu', TRUE)
ON CONFLICT (code) DO UPDATE
SET name = EXCLUDED.name, department_id = EXCLUDED.department_id, description = EXCLUDED.description, is_active = TRUE;

-- 9.4. 4 Cấp độ Phân loại Độ mật Chuẩn (Bell-LaPadula Rank 1..4)
-- // CONFLICT-RESOLVED: Giữ chuẩn rank CSDL INTERNAL: 1 .. TOP_SECRET: 4 (mức 0 dành cho UNCLASSIFIED) và đồng bộ thống nhất với packages/contracts/src/classifications.ts cùng seed.ts.
INSERT INTO public.classification_levels (code, name, rank, description, default_view_days, allow_download, require_watermark, is_active)
VALUES
  ('INTERNAL', 'Nội bộ', 1, 'Tài liệu lưu hành nội bộ trong tổ chức', 30, TRUE, TRUE, TRUE),
  ('CONFIDENTIAL', 'Mật', 2, 'Tài liệu nhạy cảm cấp phòng ban/dự án, yêu cầu thẩm tra cấp 2+', 14, TRUE, TRUE, TRUE),
  ('SECRET', 'Tối mật', 3, 'Tài liệu trọng yếu, cấm tải về mặc định, bắt buộc mạng tin cậy', 7, FALSE, TRUE, TRUE),
  ('TOP_SECRET', 'Tuyệt mật', 4, 'Tài liệu tối trọng yếu, chỉ xem trực tuyến có đóng dấu pháp y và MFA', 1, FALSE, TRUE, TRUE)
ON CONFLICT (code) DO UPDATE
SET
  name = EXCLUDED.name,
  rank = EXCLUDED.rank,
  description = EXCLUDED.description,
  default_view_days = EXCLUDED.default_view_days,
  allow_download = EXCLUDED.allow_download,
  require_watermark = EXCLUDED.require_watermark,
  is_active = TRUE;

-- 9.5. 5 Vai trò Hệ thống (Phân tách nhiệm vụ SoD nghiêm ngặt)
INSERT INTO public.roles (code, name, description, is_system_role, is_active, created_by)
VALUES
  ('SYSTEM_ADMIN', 'Quản trị viên hệ thống', 'Quản trị người dùng, phòng ban, vai trò, thuộc tính và chính sách; không có quyền xem nội dung tài liệu mật', TRUE, TRUE, (SELECT id FROM public.users WHERE username = 'system.seed')),
  ('SECURITY_OFFICER', 'Nhân viên bảo mật', 'Giám sát cảnh báo SOC, truy vết thủy vân pháp y, quản lý sự cố và ngắt phiên khẩn cấp', TRUE, TRUE, (SELECT id FROM public.users WHERE username = 'system.seed')),
  ('AUDITOR', 'Kiểm toán viên', 'Tra cứu nhật ký kiểm toán bất biến, xác minh chuỗi HMAC và xuất báo cáo độc lập (chỉ đọc)', TRUE, TRUE, (SELECT id FROM public.users WHERE username = 'system.seed')),
  ('DOCUMENT_OWNER', 'Chủ sở hữu tài liệu', 'Tải lên, phân loại độ mật, phát hành phiên bản và phê duyệt/thu hồi quyền truy cập tài liệu sở hữu', TRUE, TRUE, (SELECT id FROM public.users WHERE username = 'system.seed')),
  ('DOCUMENT_READER', 'Người đọc tài liệu', 'Tìm kiếm tài liệu được phép khám phá, gửi yêu cầu cấp quyền và xem/tải tài liệu trong thời hạn hiệu lực', TRUE, TRUE, (SELECT id FROM public.users WHERE username = 'system.seed'))
ON CONFLICT (code) DO UPDATE
SET
  name = EXCLUDED.name,
  description = EXCLUDED.description,
  is_system_role = TRUE,
  is_active = TRUE;

-- 9.6. 34 Quyền Hạt nhân (Permissions)
-- CONFLICT-RESOLVED: Bổ sung quyền SYSTEM_HEALTH_MANAGE và DOCUMENT_MANAGE đồng bộ với Prisma seed-catalog và bộ quyền RBAC tầng API.
INSERT INTO public.permissions (code, name, resource_type, action)
VALUES
  ('USER_MANAGE', 'USER_MANAGE', 'USER', 'MANAGE'),
  ('DEPARTMENT_MANAGE', 'DEPARTMENT_MANAGE', 'DEPARTMENT', 'MANAGE'),
  ('ROLE_MANAGE', 'ROLE_MANAGE', 'ROLE', 'MANAGE'),
  ('ATTRIBUTE_MANAGE', 'ATTRIBUTE_MANAGE', 'ATTRIBUTE', 'MANAGE'),
  ('POLICY_MANAGE', 'POLICY_MANAGE', 'POLICY', 'MANAGE'),
  ('POLICY_SIMULATE', 'POLICY_SIMULATE', 'POLICY', 'SIMULATE'),
  ('WATERMARK_CONFIG_MANAGE', 'WATERMARK_CONFIG_MANAGE', 'WATERMARK_CONFIG', 'MANAGE'),
  ('SYSTEM_HEALTH_VIEW', 'SYSTEM_HEALTH_VIEW', 'SYSTEM_HEALTH', 'VIEW'),
  ('SYSTEM_HEALTH_MANAGE', 'SYSTEM_HEALTH_MANAGE', 'SYSTEM_HEALTH', 'MANAGE'),
  ('DOCUMENT_UPLOAD', 'DOCUMENT_UPLOAD', 'DOCUMENT', 'UPLOAD'),
  ('DOCUMENT_CLASSIFY', 'DOCUMENT_CLASSIFY', 'DOCUMENT', 'CLASSIFY'),
  ('DOCUMENT_VERSION_CREATE', 'DOCUMENT_VERSION_CREATE', 'DOCUMENT_VERSION', 'CREATE'),
  ('DOCUMENT_ARCHIVE', 'DOCUMENT_ARCHIVE', 'DOCUMENT', 'ARCHIVE'),
  ('DOCUMENT_MANAGE', 'DOCUMENT_MANAGE', 'DOCUMENT', 'MANAGE'),
  ('DOCUMENT_DISCOVER', 'DOCUMENT_DISCOVER', 'DOCUMENT', 'DISCOVER'),
  ('DOCUMENT_VIEW', 'DOCUMENT_VIEW', 'DOCUMENT', 'VIEW'),
  ('DOCUMENT_DOWNLOAD', 'DOCUMENT_DOWNLOAD', 'DOCUMENT', 'DOWNLOAD'),
  ('ACCESS_REQUEST_CREATE', 'ACCESS_REQUEST_CREATE', 'ACCESS_REQUEST', 'CREATE'),
  ('ACCESS_REQUEST_VIEW_OWN', 'ACCESS_REQUEST_VIEW_OWN', 'ACCESS_REQUEST', 'VIEW_OWN'),
  ('ACCESS_REQUEST_CANCEL', 'ACCESS_REQUEST_CANCEL', 'ACCESS_REQUEST', 'CANCEL'),
  ('ACCESS_REQUEST_DECIDE', 'ACCESS_REQUEST_DECIDE', 'ACCESS_REQUEST', 'DECIDE'),
  ('ACCESS_GRANT_CREATE', 'ACCESS_GRANT_CREATE', 'ACCESS_GRANT', 'CREATE'),
  ('ACCESS_GRANT_REVOKE', 'ACCESS_GRANT_REVOKE', 'ACCESS_GRANT', 'REVOKE'),
  ('ACCESS_GRANT_VIEW', 'ACCESS_GRANT_VIEW', 'ACCESS_GRANT', 'VIEW'),
  ('AUDIT_VIEW', 'AUDIT_VIEW', 'AUDIT_LOG', 'VIEW'),
  ('AUDIT_EXPORT', 'AUDIT_EXPORT', 'AUDIT_LOG', 'EXPORT'),
  ('ALERT_VIEW', 'ALERT_VIEW', 'SECURITY_ALERT', 'VIEW'),
  ('ALERT_MANAGE', 'ALERT_MANAGE', 'SECURITY_ALERT', 'MANAGE'),
  ('WATERMARK_TRACE', 'WATERMARK_TRACE', 'WATERMARK_INSTANCE', 'TRACE'),
  ('INCIDENT_CREATE', 'INCIDENT_CREATE', 'INCIDENT_REPORT', 'CREATE'),
  ('INCIDENT_MANAGE', 'INCIDENT_MANAGE', 'INCIDENT_REPORT', 'MANAGE'),
  ('NOTIFICATION_VIEW', 'NOTIFICATION_VIEW', 'NOTIFICATION', 'VIEW'),
  ('SYSTEM_REPORT_EXPORT', 'SYSTEM_REPORT_EXPORT', 'SYSTEM_REPORT', 'EXPORT'),
  ('ACCESS_SESSION_TERMINATE', 'ACCESS_SESSION_TERMINATE', 'ACCESS_SESSION', 'TERMINATE')
ON CONFLICT (code) DO UPDATE
SET name = EXCLUDED.name, resource_type = EXCLUDED.resource_type, action = EXCLUDED.action;

-- 9.7. Ma trận Gán quyền theo Vai trò (Role-Permission Matrix tuân thủ SoD)
-- Thuật toán: Kết nối quan hệ tập hằng `VALUES(role_code, perm_code)` với bảng `roles` và `permissions` để ánh xạ ma trận phân tách nhiệm vụ (Separation of Duties - SoD),
-- đảm bảo `SYSTEM_ADMIN` không bao giờ nhận quyền đọc/tải nội dung tài liệu mật và `AUDITOR` chỉ nhận quyền đọc kiểm toán độc lập.
INSERT INTO public.role_permissions (role_id, permission_id, granted_by)
SELECT r.id, p.id, (SELECT id FROM public.users WHERE username = 'system.seed')
FROM (
  VALUES
    -- SYSTEM_ADMIN (9 quyền quản trị cấu hình, tuyệt đối không có DOCUMENT_VIEW/DOWNLOAD)
    ('SYSTEM_ADMIN', 'USER_MANAGE'),
    ('SYSTEM_ADMIN', 'DEPARTMENT_MANAGE'),
    ('SYSTEM_ADMIN', 'ROLE_MANAGE'),
    ('SYSTEM_ADMIN', 'ATTRIBUTE_MANAGE'),
    ('SYSTEM_ADMIN', 'POLICY_MANAGE'),
    ('SYSTEM_ADMIN', 'POLICY_SIMULATE'),
    ('SYSTEM_ADMIN', 'WATERMARK_CONFIG_MANAGE'),
    ('SYSTEM_ADMIN', 'SYSTEM_HEALTH_VIEW'),
    ('SYSTEM_ADMIN', 'SYSTEM_HEALTH_MANAGE'),
    -- SECURITY_OFFICER (8 quyền giám sát SOC & phản ứng sự cố)
    ('SECURITY_OFFICER', 'AUDIT_VIEW'),
    ('SECURITY_OFFICER', 'ALERT_VIEW'),
    ('SECURITY_OFFICER', 'ALERT_MANAGE'),
    ('SECURITY_OFFICER', 'WATERMARK_TRACE'),
    ('SECURITY_OFFICER', 'INCIDENT_CREATE'),
    ('SECURITY_OFFICER', 'INCIDENT_MANAGE'),
    ('SECURITY_OFFICER', 'ACCESS_SESSION_TERMINATE'),
    ('SECURITY_OFFICER', 'POLICY_SIMULATE'),
    -- AUDITOR (5 quyền kiểm toán độc lập chỉ đọc & xuất báo cáo)
    ('AUDITOR', 'AUDIT_VIEW'),
    ('AUDITOR', 'AUDIT_EXPORT'),
    ('AUDITOR', 'ALERT_VIEW'),
    ('AUDITOR', 'WATERMARK_TRACE'),
    ('AUDITOR', 'SYSTEM_REPORT_EXPORT'),
    -- DOCUMENT_OWNER (15 quyền quản lý vòng đời tài liệu sở hữu & cấp phát quyền)
    ('DOCUMENT_OWNER', 'DOCUMENT_UPLOAD'),
    ('DOCUMENT_OWNER', 'DOCUMENT_CLASSIFY'),
    ('DOCUMENT_OWNER', 'DOCUMENT_VERSION_CREATE'),
    ('DOCUMENT_OWNER', 'DOCUMENT_ARCHIVE'),
    ('DOCUMENT_OWNER', 'DOCUMENT_MANAGE'),
    ('DOCUMENT_OWNER', 'DOCUMENT_DISCOVER'),
    ('DOCUMENT_OWNER', 'DOCUMENT_VIEW'),
    ('DOCUMENT_OWNER', 'DOCUMENT_DOWNLOAD'),
    ('DOCUMENT_OWNER', 'ACCESS_REQUEST_DECIDE'),
    ('DOCUMENT_OWNER', 'ACCESS_REQUEST_VIEW_OWN'),
    ('DOCUMENT_OWNER', 'ACCESS_GRANT_CREATE'),
    ('DOCUMENT_OWNER', 'ACCESS_GRANT_REVOKE'),
    ('DOCUMENT_OWNER', 'ACCESS_GRANT_VIEW'),
    ('DOCUMENT_OWNER', 'NOTIFICATION_VIEW'),
    ('DOCUMENT_OWNER', 'AUDIT_VIEW'),
    -- DOCUMENT_READER (7 quyền tra cứu, xin cấp quyền & truy cập tài liệu được duyệt)
    ('DOCUMENT_READER', 'DOCUMENT_DISCOVER'),
    ('DOCUMENT_READER', 'DOCUMENT_VIEW'),
    ('DOCUMENT_READER', 'DOCUMENT_DOWNLOAD'),
    ('DOCUMENT_READER', 'ACCESS_REQUEST_CREATE'),
    ('DOCUMENT_READER', 'ACCESS_REQUEST_VIEW_OWN'),
    ('DOCUMENT_READER', 'ACCESS_REQUEST_CANCEL'),
    ('DOCUMENT_READER', 'NOTIFICATION_VIEW')
) AS m(role_code, perm_code)
JOIN public.roles r ON r.code = m.role_code
JOIN public.permissions p ON p.code = m.perm_code
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- 9.8. 15 Định nghĩa Thuộc tính ABAC (USER / RESOURCE / ENVIRONMENT) & Tùy chọn ENUM
INSERT INTO public.attribute_definitions (code, name, scope, value_type, is_required, is_multi_value, is_active, created_by)
VALUES
  ('CLEARANCE_LEVEL', 'Cấp độ thẩm tra', 'USER', 'ENUM', TRUE, FALSE, TRUE, (SELECT id FROM public.users WHERE username = 'system.seed')),
  ('SUBJECT_DEPARTMENT', 'Phòng ban chủ thể', 'USER', 'STRING', TRUE, FALSE, TRUE, (SELECT id FROM public.users WHERE username = 'system.seed')),
  ('EMPLOYMENT_STATUS', 'Trạng thái làm việc', 'USER', 'ENUM', TRUE, FALSE, TRUE, (SELECT id FROM public.users WHERE username = 'system.seed')),
  ('PROJECT', 'Dự án', 'USER', 'STRING', FALSE, TRUE, TRUE, (SELECT id FROM public.users WHERE username = 'system.seed')),
  ('CLASSIFICATION_RANK', 'Hạng phân loại tài liệu', 'RESOURCE', 'NUMBER', TRUE, FALSE, TRUE, (SELECT id FROM public.users WHERE username = 'system.seed')),
  ('RESOURCE_OWNER', 'Chủ sở hữu tài liệu', 'RESOURCE', 'STRING', TRUE, FALSE, TRUE, (SELECT id FROM public.users WHERE username = 'system.seed')),
  ('RESOURCE_DEPARTMENT', 'Phòng ban tài liệu', 'RESOURCE', 'STRING', TRUE, FALSE, TRUE, (SELECT id FROM public.users WHERE username = 'system.seed')),
  ('RESOURCE_CATEGORY', 'Danh mục tài liệu', 'RESOURCE', 'STRING', TRUE, FALSE, TRUE, (SELECT id FROM public.users WHERE username = 'system.seed')),
  ('RESOURCE_STATUS', 'Trạng thái tài liệu', 'RESOURCE', 'ENUM', TRUE, FALSE, TRUE, (SELECT id FROM public.users WHERE username = 'system.seed')),
  ('CURRENT_TIME', 'Thời điểm truy cập', 'ENVIRONMENT', 'DATE', TRUE, FALSE, TRUE, (SELECT id FROM public.users WHERE username = 'system.seed')),
  ('SOURCE_IP', 'Địa chỉ IP nguồn', 'ENVIRONMENT', 'STRING', TRUE, FALSE, TRUE, (SELECT id FROM public.users WHERE username = 'system.seed')),
  ('TRUSTED_NETWORK', 'Mạng tin cậy', 'ENVIRONMENT', 'BOOLEAN', TRUE, FALSE, TRUE, (SELECT id FROM public.users WHERE username = 'system.seed')),
  ('DEVICE_TRUST', 'Thiết bị tin cậy', 'ENVIRONMENT', 'BOOLEAN', TRUE, FALSE, TRUE, (SELECT id FROM public.users WHERE username = 'system.seed')),
  ('MFA', 'Xác thực đa yếu tố', 'ENVIRONMENT', 'BOOLEAN', TRUE, FALSE, TRUE, (SELECT id FROM public.users WHERE username = 'system.seed')),
  ('RISK_SCORE', 'Điểm rủi ro', 'ENVIRONMENT', 'NUMBER', TRUE, FALSE, TRUE, (SELECT id FROM public.users WHERE username = 'system.seed'))
ON CONFLICT (code) DO UPDATE
SET
  name = EXCLUDED.name,
  scope = EXCLUDED.scope,
  value_type = EXCLUDED.value_type,
  is_required = EXCLUDED.is_required,
  is_multi_value = EXCLUDED.is_multi_value,
  is_active = TRUE;

INSERT INTO public.attribute_options (attribute_definition_id, value_code, display_name, numeric_rank, is_active, sort_order)
SELECT
  (SELECT id FROM public.attribute_definitions WHERE code = 'CLEARANCE_LEVEL'),
  cl.code,
  cl.name,
  cl.rank,
  TRUE,
  cl.rank
FROM public.classification_levels cl
ON CONFLICT (attribute_definition_id, value_code) DO UPDATE
SET
  display_name = EXCLUDED.display_name,
  numeric_rank = EXCLUDED.numeric_rank,
  sort_order = EXCLUDED.sort_order,
  is_active = TRUE;

INSERT INTO public.attribute_options (attribute_definition_id, value_code, display_name, numeric_rank, is_active, sort_order)
SELECT
  (SELECT id FROM public.attribute_definitions WHERE code = 'EMPLOYMENT_STATUS'),
  v.value_code,
  v.display_name,
  v.numeric_rank,
  TRUE,
  v.sort_order
FROM (
  VALUES
    ('ACTIVE_STAFF', 'Nhân sự chính thức', 2, 1),
    ('CONTRACTOR', 'Cộng tác viên / Nhà thầu', 1, 2),
    ('SUSPENDED', 'Tạm đình chỉ công tác', 0, 3)
) AS v(value_code, display_name, numeric_rank, sort_order)
ON CONFLICT (attribute_definition_id, value_code) DO UPDATE
SET display_name = EXCLUDED.display_name, numeric_rank = EXCLUDED.numeric_rank, sort_order = EXCLUDED.sort_order, is_active = TRUE;

-- 9.9. Chính sách ABAC Mặc định (Zero-Trust Baseline Rules)
-- Thuật toán: Gieo cặp luật từ chối ưu tiên cao (`DENY_OVERRIDES`) chặn phiên có điểm rủi ro >= 80 và chặn xem tài liệu `TOP_SECRET` (hạng 4) khi thiếu xác thực đa nhân tố MFA,
-- kèm danh sách nghĩa vụ JSONB (`obligations`) và tổ hợp điều kiện thuộc tính ngữ cảnh tương ứng.
INSERT INTO public.policy_rules (code, name, description, effect, priority, target_resource, target_action, combining_algorithm, obligations, is_active, created_by)
VALUES
  (
    'POL-DENY-HIGH-RISK-SESSION',
    'Từ chối truy cập khi điểm rủi ro phiên vượt ngưỡng an toàn',
    'Chặn mọi hành động trên tài liệu nếu điểm rủi ro môi trường >= 80',
    'DENY',
    10,
    'DOCUMENT',
    NULL,
    'DENY_OVERRIDES',
    '["AUDIT_ELEVATED"]'::jsonb,
    TRUE,
    (SELECT id FROM public.users WHERE username = 'system.seed')
  ),
  (
    'POL-DENY-TOP-SECRET-WITHOUT-MFA',
    'Bắt buộc xác thực đa yếu tố (MFA) đối với tài liệu Tuyệt mật',
    'Chặn xem/tải tài liệu hạng 4 (TOP_SECRET) khi phiên chưa hoàn tất xác thực MFA',
    'DENY',
    20,
    'DOCUMENT',
    'VIEW',
    'DENY_OVERRIDES',
    '["REQUIRE_MFA"]'::jsonb,
    TRUE,
    (SELECT id FROM public.users WHERE username = 'system.seed')
  )
ON CONFLICT (code) DO UPDATE
SET
  name = EXCLUDED.name,
  description = EXCLUDED.description,
  effect = EXCLUDED.effect,
  priority = EXCLUDED.priority,
  obligations = EXCLUDED.obligations;

INSERT INTO public.policy_rule_conditions (policy_rule_id, attribute_definition_id, context_key, operator, expected_value, condition_group, sequence_no)
VALUES
  (
    (SELECT id FROM public.policy_rules WHERE code = 'POL-DENY-HIGH-RISK-SESSION'),
    NULL,
    'environment.riskScore',
    'GTE',
    '80'::jsonb,
    1,
    1
  ),
  (
    (SELECT id FROM public.policy_rules WHERE code = 'POL-DENY-TOP-SECRET-WITHOUT-MFA'),
    NULL,
    'resource.classificationRank',
    'GTE',
    '4'::jsonb,
    1,
    1
  ),
  (
    (SELECT id FROM public.policy_rules WHERE code = 'POL-DENY-TOP-SECRET-WITHOUT-MFA'),
    NULL,
    'environment.mfa',
    'EQ',
    'false'::jsonb,
    1,
    2
  )
ON CONFLICT (policy_rule_id, condition_group, sequence_no) DO UPDATE
SET
  context_key = EXCLUDED.context_key,
  operator = EXCLUDED.operator,
  expected_value = EXCLUDED.expected_value;

-- 9.10. Cấu hình Đóng dấu Thủy vân Pháp y Mặc định & Theo Cấp độ Mật (Ngăn lỗi FK 23503)
INSERT INTO public.watermark_configs (
  name, classification_level_id, is_default, is_visible, template_text,
  opacity_percent, rotation_degrees, font_size, color_hex, include_qr_code, is_active, created_by
)
SELECT
  'Cấu hình đóng dấu mặc định toàn hệ thống',
  NULL,
  TRUE,
  TRUE,
  'CONFIDENTIAL | {username} ({employeeCode}) | {documentCode} | {timestamp} | {shortToken}',
  25,
  -30,
  12,
  '#808080',
  TRUE,
  TRUE,
  (SELECT id FROM public.users WHERE username = 'system.seed')
WHERE NOT EXISTS (
  SELECT 1 FROM public.watermark_configs WHERE is_default = TRUE AND classification_level_id IS NULL
);

INSERT INTO public.watermark_configs (
  name, classification_level_id, is_default, is_visible, template_text,
  opacity_percent, rotation_degrees, font_size, color_hex, include_qr_code, is_active, created_by
)
SELECT
  v.name,
  cl.id,
  FALSE,
  TRUE,
  v.template_text,
  v.opacity_percent,
  -35,
  v.font_size,
  v.color_hex,
  TRUE,
  TRUE,
  (SELECT id FROM public.users WHERE username = 'system.seed')
FROM (
  VALUES
    ('SECRET', 'Đóng dấu Tối mật (SECRET)', 'SECRET - DO NOT DISTRIBUTE | {username} ({employeeCode}) | {documentCode} | {timestamp} | {shortToken}', 32, 13, '#991B1B'),
    ('TOP_SECRET', 'Đóng dấu Tuyệt mật (TOP SECRET)', 'TOP SECRET - FORENSIC TRACKED | {username} ({employeeCode}) | {documentCode} | {timestamp} | {shortToken}', 38, 14, '#7F1D1D')
) AS v(level_code, name, template_text, opacity_percent, font_size, color_hex)
JOIN public.classification_levels cl ON cl.code = v.level_code
WHERE NOT EXISTS (
  SELECT 1 FROM public.watermark_configs wc WHERE wc.classification_level_id = cl.id
);

-- 9.11. 6 Quy tắc Phát hiện Bất thường An ninh SOC Mặc định
INSERT INTO public.detection_rule_configs (
  rule_code, name, description, is_enabled, severity, threshold, window_minutes, cooldown_minutes, parameters
)
VALUES
  ('MASS_DOWNLOAD', 'Phát hiện tải hàng loạt', 'Cảnh báo khi người dùng tải nhiều tài liệu trong khoảng thời gian ngắn', TRUE, 'HIGH', 5, 10, 30, '{"action": "DOCUMENT_DOWNLOADED"}'::jsonb),
  ('REPEATED_DENIED', 'Phát hiện từ chối truy cập liên tiếp', 'Cảnh báo khi có nhiều yêu cầu bị từ chối truy cập từ cùng một đối tượng', TRUE, 'MEDIUM', 5, 10, 15, '{"outcome": "DENIED"}'::jsonb),
  ('OFF_HOURS_ACCESS', 'Phát hiện truy cập ngoài giờ', 'Cảnh báo khi có hoạt động truy cập tài liệu nhạy cảm ngoài giờ làm việc hoặc cuối tuần', TRUE, 'MEDIUM', 1, 5, 60, '{"startHourUtc": 0, "endHourUtc": 11}'::jsonb),
  ('UNTRUSTED_CONTEXT', 'Phát hiện IP hoặc thiết bị chưa tin cậy', 'Cảnh báo khi truy cập từ thiết bị hoặc địa chỉ IP nằm ngoài danh sách tin cậy', TRUE, 'HIGH', 1, 5, 30, '{}'::jsonb),
  ('REFRESH_TOKEN_REUSE', 'Phát hiện tái sử dụng Refresh Token', 'Cảnh báo khi một refresh token đã xoay vòng hoặc thu hồi được sử dụng lại', TRUE, 'HIGH', 1, 5, 15, '{}'::jsonb),
  ('AUDIT_INTEGRITY_COMPROMISED', 'Phát hiện vi phạm toàn vẹn Audit', 'Cảnh báo nghiêm trọng khi phát hiện đứt gãy chuỗi HMAC hoặc sai lệch sequence', TRUE, 'CRITICAL', 1, 5, 15, '{}'::jsonb)
ON CONFLICT (rule_code) DO UPDATE
SET
  name = EXCLUDED.name,
  description = EXCLUDED.description,
  severity = EXCLUDED.severity;

-- 9.12. 5 Tài khoản Khung theo Vai trò (Khởi tạo ở trạng thái DISABLED không mật khẩu tĩnh)
-- Xem hướng dẫn kích hoạt bằng Argon2id trong `supabase/README.md`.
-- Thuật toán: Vòng lặp thủ tục PL/pgSQL cấp phát lũy đẳng 5 tài khoản khung đại diện cho 5 vai trò SoD ở trạng thái `DISABLED`,
-- tự động ánh xạ phòng ban, gán vai trò hiệu lực mở (`user_roles`) và gán cấp độ thẩm tra an ninh Bell-LaPadula (`CLEARANCE_LEVEL`) không tạo bản ghi trùng.
DO $$
DECLARE
  v_seed_id BIGINT;
  v_hq_id BIGINT;
  v_sec_id BIGINT;
  v_clearance_def_id BIGINT;
  rec RECORD;
  v_user_id BIGINT;
  v_role_id BIGINT;
  v_option_id BIGINT;
BEGIN
  SELECT id INTO v_seed_id FROM public.users WHERE username = 'system.seed';
  SELECT id INTO v_hq_id FROM public.departments WHERE code = 'HEAD_OFFICE';
  SELECT id INTO v_sec_id FROM public.departments WHERE code = 'INFORMATION_SECURITY';
  SELECT id INTO v_clearance_def_id FROM public.attribute_definitions WHERE code = 'CLEARANCE_LEVEL';

  FOR rec IN
    SELECT * FROM (
      VALUES
        ('admin.demo', 'admin.demo@local.invalid', 'Quản trị viên demo', 'EMP-001', 'SYSTEM_ADMIN', 'INTERNAL', FALSE),
        ('security.demo', 'security.demo@local.invalid', 'Nhân viên bảo mật demo', 'EMP-002', 'SECURITY_OFFICER', 'TOP_SECRET', TRUE),
        ('auditor.demo', 'auditor.demo@local.invalid', 'Kiểm toán viên demo', 'EMP-003', 'AUDITOR', 'SECRET', TRUE),
        ('owner.demo', 'owner.demo@local.invalid', 'Chủ sở hữu tài liệu demo', 'EMP-004', 'DOCUMENT_OWNER', 'SECRET', FALSE),
        ('reader.demo', 'reader.demo@local.invalid', 'Người đọc tài liệu demo', 'EMP-005', 'DOCUMENT_READER', 'INTERNAL', FALSE)
    ) AS t(username, email, full_name, employee_code, role_code, clearance_code, is_sec_dept)
  LOOP
    INSERT INTO public.users (
      username, email, password_hash, full_name, employee_code, department_id, status, disabled_at, created_by
    )
    VALUES (
      rec.username,
      rec.email,
      '!AUTHENTICATION_NOT_CONFIGURED_DEMO_ACCOUNT!',
      rec.full_name,
      rec.employee_code,
      CASE WHEN rec.is_sec_dept THEN v_sec_id ELSE v_hq_id END,
      'DISABLED',
      '2026-01-01T00:00:00Z'::timestamptz,
      v_seed_id
    )
    ON CONFLICT (username) DO UPDATE
    SET
      full_name = EXCLUDED.full_name,
      department_id = EXCLUDED.department_id
    RETURNING id INTO v_user_id;

    SELECT id INTO v_role_id FROM public.roles WHERE code = rec.role_code;
    SELECT id INTO v_option_id
    FROM public.attribute_options
    WHERE attribute_definition_id = v_clearance_def_id AND value_code = rec.clearance_code;

    IF NOT EXISTS (
      SELECT 1 FROM public.user_roles
      WHERE user_id = v_user_id AND role_id = v_role_id AND valid_to IS NULL
    ) THEN
      INSERT INTO public.user_roles (user_id, role_id, valid_from, assigned_by)
      VALUES (v_user_id, v_role_id, '2026-01-01T00:00:00Z'::timestamptz, v_seed_id);
    END IF;

    IF NOT EXISTS (
      SELECT 1 FROM public.user_attribute_assignments
      WHERE user_id = v_user_id AND attribute_definition_id = v_clearance_def_id AND valid_to IS NULL
    ) THEN
      INSERT INTO public.user_attribute_assignments (
        user_id, attribute_definition_id, option_id, valid_from, assigned_by
      )
      VALUES (
        v_user_id, v_clearance_def_id, v_option_id, '2026-01-01T00:00:00Z'::timestamptz, v_seed_id
      );
    END IF;
  END LOOP;
END $$;

COMMIT;

-- =============================================================================
-- PHẦN 10: TRUY VẤN TỰ KIỂM CHỨNG SAU KHI CHẠY (VERIFICATION SUMMARY)
-- Kết quả kỳ vọng trên Supabase SQL Editor:
--   business_tables = 39 | rls_locked_tables = 40 | rls_policies = 80 | enum_types = 18 | triggers = 21
--   roles = 5 | permissions = 34 | classifications = 4 | watermark_configs = 3 | detection_rules = 6 | synced_migrations = 12
-- =============================================================================

-- Thuật toán: Truy vấn tổng hợp đối soát danh mục hệ thống PostgreSQL (`pg_tables`, `pg_policies`, `pg_type`, `pg_trigger`) và số lượng bản ghi nền tảng
-- nhằm tự động kiểm chứng toàn vẹn lược đồ, trạng thái bật FORCE RLS + chính sách tường minh và dữ liệu hạt giống ngay sau khi thực thi kịch bản.
SELECT
  (SELECT count(*)::int FROM pg_tables WHERE schemaname = 'public' AND tablename <> '_prisma_migrations') AS business_tables,
  (SELECT count(*)::int FROM pg_tables WHERE schemaname = 'public' AND rowsecurity = TRUE) AS rls_locked_tables,
  (SELECT count(*)::int FROM pg_policies WHERE schemaname = 'public') AS rls_policies,
  (SELECT count(*)::int FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace WHERE n.nspname = 'public' AND t.typtype = 'e') AS enum_types,
  (SELECT count(*)::int FROM pg_trigger tg JOIN pg_class c ON c.oid = tg.tgrelid JOIN pg_namespace n ON n.oid = c.relnamespace WHERE NOT tg.tgisinternal AND n.nspname = 'public') AS triggers,
  (SELECT count(*)::int FROM public.roles WHERE is_system_role = TRUE) AS system_roles,
  (SELECT count(*)::int FROM public.permissions) AS permissions,
  (SELECT count(*)::int FROM public.classification_levels) AS classifications,
  (SELECT count(*)::int FROM public.watermark_configs) AS watermark_configs,
  (SELECT count(*)::int FROM public.detection_rule_configs) AS detection_rules,
  (SELECT count(*)::int FROM public._prisma_migrations WHERE finished_at IS NOT NULL) AS synced_migrations;
