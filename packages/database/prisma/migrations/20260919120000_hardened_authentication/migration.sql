-- Authentication state is deliberately separated from users.
-- Tokens are opaque outside access JWTs; only SHA-256 token digests are persisted.
--
-- Thuật toán tổng quan migration:
-- Củng cố hạ tầng xác thực đa nhân tố (MFA) và xoay vòng Refresh Token theo họ phiên (`token_family_id`):
-- chỉ lưu trữ giá trị băm một chiều SHA-256 hex 64 ký tự, giới hạn duy nhất phương thức TOTP đang hoạt động bằng Partial Unique Index,
-- và cưỡng chế bất biến đồng bộ `token_family_id` giữa `refresh_tokens` và `auth_sessions` qua trigger PL/pgSQL.
CREATE TYPE auth_session_status AS ENUM ('ACTIVE', 'REVOKED', 'EXPIRED');
CREATE TYPE mfa_method_type AS ENUM ('TOTP');

CREATE TABLE auth_sessions (
    id UUID PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_family_id UUID NOT NULL UNIQUE,
    status auth_session_status NOT NULL DEFAULT 'ACTIVE',
    ip_address INET,
    user_agent TEXT,
    mfa_verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revocation_reason VARCHAR(80),
    CHECK (expires_at > created_at),
    CHECK ((status = 'ACTIVE' AND revoked_at IS NULL) OR
           (status <> 'ACTIVE' AND revoked_at IS NOT NULL)),
    CHECK (revoked_at IS NULL OR revocation_reason IS NOT NULL)
);

CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY,
    auth_session_id UUID NOT NULL REFERENCES auth_sessions(id) ON DELETE CASCADE,
    token_family_id UUID NOT NULL,
    token_hash CHAR(64) NOT NULL UNIQUE,
    parent_token_id UUID REFERENCES refresh_tokens(id) ON DELETE RESTRICT,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    revocation_reason VARCHAR(80),
    CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    CHECK (expires_at > issued_at),
    CHECK (revoked_at IS NULL OR revocation_reason IS NOT NULL),
    UNIQUE (id, token_family_id)
);

CREATE TABLE mfa_methods (
    id UUID PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    method_type mfa_method_type NOT NULL DEFAULT 'TOTP',
    label VARCHAR(80),
    secret_encrypted TEXT NOT NULL,
    recovery_code_hashes JSONB NOT NULL DEFAULT '[]'::jsonb,
    verified_at TIMESTAMPTZ,
    enabled_at TIMESTAMPTZ,
    disabled_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (enabled_at IS NULL OR verified_at IS NOT NULL),
    CHECK (disabled_at IS NULL OR enabled_at IS NOT NULL)
);

CREATE TABLE password_reset_tokens (
    id UUID PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash CHAR(64) NOT NULL UNIQUE,
    requested_ip INET,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    CHECK (expires_at > created_at)
);

CREATE INDEX idx_auth_sessions_user_status ON auth_sessions(user_id, status, expires_at);
CREATE INDEX idx_refresh_tokens_session_expiry ON refresh_tokens(auth_session_id, expires_at);
CREATE INDEX idx_refresh_tokens_family ON refresh_tokens(token_family_id, revoked_at);
CREATE INDEX idx_mfa_methods_user_active ON mfa_methods(user_id, enabled_at, disabled_at);
-- Thuật toán: Chỉ mục duy nhất từng phần (Partial Unique Index) giới hạn mỗi người dùng chỉ có tối đa 1 phương thức MFA cùng loại đang kích hoạt (`disabled_at IS NULL`).
CREATE UNIQUE INDEX uq_mfa_active_totp_per_user ON mfa_methods(user_id, method_type)
  WHERE disabled_at IS NULL;
CREATE INDEX idx_password_reset_user_expiry ON password_reset_tokens(user_id, expires_at);

-- A refresh token must stay in the session's token family.
-- Thuật toán: Ràng buộc toàn vẹn họ xoay vòng token (`validate_refresh_token_family` - Token Family Binding Invariant).
-- Đầu vào/Đầu ra: Khi chèn hoặc cập nhật dòng `refresh_tokens`, đối chiếu cặp `(NEW.auth_session_id, NEW.token_family_id)` với bảng `auth_sessions`
-- nhằm ngăn chặn việc gắn nhầm hoặc giả mạo token sang họ phiên khác trong cơ chế phát hiện tái sử dụng (Refresh Token Reuse Detection).
CREATE OR REPLACE FUNCTION validate_refresh_token_family() RETURNS trigger AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM auth_sessions s
    WHERE s.id = NEW.auth_session_id AND s.token_family_id = NEW.token_family_id
  ) THEN
    RAISE EXCEPTION 'refresh token family does not match auth session';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_validate_refresh_token_family
BEFORE INSERT OR UPDATE OF auth_session_id, token_family_id ON refresh_tokens
FOR EACH ROW EXECUTE FUNCTION validate_refresh_token_family();
