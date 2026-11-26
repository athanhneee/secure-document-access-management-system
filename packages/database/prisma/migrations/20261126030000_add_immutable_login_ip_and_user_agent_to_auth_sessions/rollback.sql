-- Rollback: Remove Immutable Login IP & User-Agent Baseline Columns from `auth_sessions` (`BUG-042`)

ALTER TABLE public.auth_sessions
  DROP COLUMN IF EXISTS login_user_agent,
  DROP COLUMN IF EXISTS login_ip_address;
