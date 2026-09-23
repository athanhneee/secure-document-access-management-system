-- Migration: Add indexes for Access Grant overlap detection and expiry worker
-- Prompt 12: Time-bound grants, immediate revocation, session termination

-- Partial unique index prevents duplicate active grants per user-document pair.
-- When extending an existing grant, the service updates the row rather than inserting.
CREATE UNIQUE INDEX IF NOT EXISTS uq_access_grant_active_user
  ON access_grants(document_id, principal_user_id)
  WHERE status = 'ACTIVE' AND principal_type = 'USER';

-- Partial unique index prevents duplicate active grants per role-document pair.
CREATE UNIQUE INDEX IF NOT EXISTS uq_access_grant_active_role
  ON access_grants(document_id, principal_role_id)
  WHERE status = 'ACTIVE' AND principal_type = 'ROLE';

-- Index for worker batch expiry queries: find ACTIVE grants past valid_until.
CREATE INDEX IF NOT EXISTS idx_access_grants_expiry
  ON access_grants(status, valid_until)
  WHERE status = 'ACTIVE';

-- Index for finding active sessions by grant (used during revocation/expiry).
CREATE INDEX IF NOT EXISTS idx_access_sessions_grant_active
  ON access_sessions(access_grant_id, status)
  WHERE status = 'ACTIVE';
