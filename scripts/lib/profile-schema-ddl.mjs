/**
 * SDA Query Profiler DDL Schema Definition (Prisma-Aligned)
 * Extracted from scripts/lib/profile-schema-seed.mjs for Single Responsibility (Rule §3).
 */

// CONFLICT-RESOLVED: Đồng bộ 100% tên bảng, tên cột và chỉ mục với packages/database/prisma/schema/*.prisma (loại bỏ các cột cũ classification_id, grantee_user_id, session_token_hash, sequence).
export const PROFILE_SCHEMA_SQL = `
  CREATE TABLE IF NOT EXISTS departments (
    id BIGSERIAL PRIMARY KEY,
    code VARCHAR(30) UNIQUE NOT NULL,
    name VARCHAR(150) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE
  );
  CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(80) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(150) NOT NULL,
    department_id BIGINT REFERENCES departments(id),
    status VARCHAR(30) NOT NULL DEFAULT 'ACTIVE'
  );
  CREATE TABLE IF NOT EXISTS classification_levels (
    id BIGSERIAL PRIMARY KEY,
    code VARCHAR(40) UNIQUE NOT NULL,
    name VARCHAR(100) NOT NULL,
    rank INTEGER UNIQUE NOT NULL
  );
  CREATE TABLE IF NOT EXISTS business_categories (
    id BIGSERIAL PRIMARY KEY,
    code VARCHAR(50) UNIQUE NOT NULL,
    name VARCHAR(150) NOT NULL,
    department_id BIGINT REFERENCES departments(id)
  );
  CREATE TABLE IF NOT EXISTS documents (
    id UUID PRIMARY KEY,
    document_code VARCHAR(60) UNIQUE NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    owner_id BIGINT NOT NULL REFERENCES users(id),
    department_id BIGINT NOT NULL REFERENCES departments(id),
    current_version_id BIGINT,
    status VARCHAR(30) NOT NULL DEFAULT 'ACTIVE',
    discoverable BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );
  CREATE TABLE IF NOT EXISTS document_versions (
    id BIGSERIAL PRIMARY KEY,
    document_id UUID NOT NULL REFERENCES documents(id),
    version_no INTEGER NOT NULL,
    original_filename VARCHAR(255) NOT NULL,
    storage_key VARCHAR(500) UNIQUE NOT NULL,
    mime_type VARCHAR(150) NOT NULL,
    file_size_bytes BIGINT NOT NULL,
    sha256_hash CHAR(64) NOT NULL,
    encryption_key_ref VARCHAR(255) NOT NULL,
    scan_status VARCHAR(20) NOT NULL DEFAULT 'CLEAN',
    uploaded_by BIGINT NOT NULL REFERENCES users(id)
  );
  CREATE TABLE IF NOT EXISTS document_classification_history (
    id BIGSERIAL PRIMARY KEY,
    document_id UUID NOT NULL REFERENCES documents(id),
    classification_level_id BIGINT NOT NULL REFERENCES classification_levels(id),
    business_category_id BIGINT NOT NULL REFERENCES business_categories(id),
    classified_by BIGINT NOT NULL REFERENCES users(id),
    effective_from TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    effective_to TIMESTAMPTZ
  );
  CREATE TABLE IF NOT EXISTS access_grants (
    id UUID PRIMARY KEY,
    document_id UUID NOT NULL REFERENCES documents(id),
    principal_type VARCHAR(20) NOT NULL,
    principal_user_id BIGINT REFERENCES users(id),
    principal_role_id BIGINT,
    source VARCHAR(30) NOT NULL,
    valid_from TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ NOT NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'ACTIVE',
    granted_by BIGINT NOT NULL REFERENCES users(id),
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );
  CREATE TABLE IF NOT EXISTS access_sessions (
    id UUID PRIMARY KEY,
    access_grant_id UUID NOT NULL REFERENCES access_grants(id),
    document_version_id BIGINT NOT NULL REFERENCES document_versions(id),
    user_id BIGINT NOT NULL REFERENCES users(id),
    ip_address INET NOT NULL,
    device_fingerprint VARCHAR(255),
    status VARCHAR(30) NOT NULL DEFAULT 'ACTIVE',
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_activity_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ended_at TIMESTAMPTZ
  );
  CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGSERIAL PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor_user_id BIGINT,
    action VARCHAR(100) NOT NULL,
    object_type VARCHAR(80) NOT NULL,
    object_id VARCHAR(100),
    document_id UUID,
    outcome VARCHAR(20) NOT NULL,
    correlation_id UUID NOT NULL,
    previous_hash CHAR(64),
    entry_hash CHAR(64) NOT NULL,
    chain_partition VARCHAR(80) NOT NULL DEFAULT 'GLOBAL',
    chain_sequence BIGINT NOT NULL
  );
  CREATE INDEX idx_users_department_status ON users (department_id, status);
  CREATE INDEX idx_documents_department_status ON documents (department_id, status, created_at DESC);
  CREATE INDEX idx_documents_owner_status ON documents (owner_id, status);
  CREATE INDEX idx_document_versions_document ON document_versions (document_id, version_no DESC);
  CREATE UNIQUE INDEX uq_document_current_classification ON document_classification_history (document_id) WHERE effective_to IS NULL;
  CREATE INDEX idx_access_grants_user_active ON access_grants (principal_user_id, document_id, status, valid_until);
  CREATE INDEX idx_sessions_user_active ON access_sessions (user_id, status, last_activity_at DESC);
  CREATE UNIQUE INDEX uq_audit_chain_position ON audit_logs (chain_partition, chain_sequence);
  CREATE INDEX idx_audit_partition_time ON audit_logs (chain_partition, occurred_at DESC);
`;
