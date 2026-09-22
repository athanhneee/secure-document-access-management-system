-- Emergency rollback for pre-production verification only. Production uses forward fixes.
DROP TRIGGER IF EXISTS trg_validate_refresh_token_family ON refresh_tokens;
DROP FUNCTION IF EXISTS validate_refresh_token_family();
DROP TABLE IF EXISTS password_reset_tokens;
DROP TABLE IF EXISTS mfa_methods;
DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS auth_sessions;
DROP TYPE IF EXISTS mfa_method_type;
DROP TYPE IF EXISTS auth_session_status;
