-- Rollback for 20260923200000_security_ops_and_incident_management
-- Thuật toán hoàn tác: Gỡ bỏ tuần tự các bảng cấu hình quy tắc phát hiện SOC, hàng đợi xuất báo cáo bất đồng bộ và hàng đợi thông báo Transactional Outbox.
DROP TABLE IF EXISTS public.detection_rule_configs;
DROP TABLE IF EXISTS public.async_export_jobs;
DROP TABLE IF EXISTS public.notification_outbox;
