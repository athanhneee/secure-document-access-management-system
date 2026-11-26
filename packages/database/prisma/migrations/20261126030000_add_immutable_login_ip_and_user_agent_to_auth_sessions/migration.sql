-- Migration: Add Immutable Login IP & User-Agent Baseline Columns to `auth_sessions` (`BUG-042`)
--
-- Thuật toán tổng quan migration (`BUG-042`):
-- 1. Bổ sung 2 cột bất biến `login_ip_address INET` và `login_user_agent TEXT` vào bảng `public.auth_sessions`
--    để lưu giữ nguyên vẹn mốc IP và User-Agent gốc lúc đăng nhập (tách biệt với cặp `ip_address`/`user_agent`
--    dùng làm dấu vết hoạt động gần nhất cho trang `/sessions`).
-- 2. Backfill lũy đẳng từ `ip_address` và `user_agent` hiện hữu cho các bản ghi phiên đã tạo trước đó.

ALTER TABLE public.auth_sessions
  ADD COLUMN IF NOT EXISTS login_ip_address INET,
  ADD COLUMN IF NOT EXISTS login_user_agent TEXT;

UPDATE public.auth_sessions
SET login_ip_address = COALESCE(login_ip_address, ip_address),
    login_user_agent = COALESCE(login_user_agent, user_agent)
WHERE login_ip_address IS NULL
   OR login_user_agent IS NULL;
