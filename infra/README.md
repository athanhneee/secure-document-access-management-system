# Hạ tầng Local & Production Observability

`compose.yaml` cung cấp PostgreSQL, Redis, S3-Compatible Object Storage (`pgsty/silo`, tên service
`minio` để giữ tương thích), ClamAV, Gotenberg, Mailpit, Prometheus và Grafana cho phát triển local.
Credential được sinh tự động vào `.local/dev.env` đã gitignore (bao gồm `SMTP_HOST=127.0.0.1`,
`SMTP_PORT=1025`, `SMTP_SECURE=false`, `SMTP_FROM=noreply@sda.local` cho Mailpit cục bộ); Compose
không chứa mật khẩu cố định.

Ba bucket S3 cục bộ (`secure-documents`, `secure-derivatives`, `secure-quarantine`) được bootstrap
idempotent, private và bật versioning. Các named volume được giữ lại khi chạy `pnpm infra:down`;
chỉ `pnpm infra:reset-safe` có thể xóa chúng sau xác nhận chính xác. Trong CI, đặt
`ENABLE_CLAMAV_CI=true` nếu cần khởi chạy daemon `clamav` thật.

## Quy ước xác thực Prometheus (`METRICS_SCRAPE_TOKEN` & `bearer_token_file`)

- Trên môi trường Production (`compose.prod.yaml`), khi đặt `METRICS_SCRAPE_TOKEN` cho `api` và `worker`:
  1. Lưu cùng chuỗi token vào tệp chỉ đọc `/etc/prometheus/secrets/metrics_scrape_token` (`chmod 0400`).
  2. Bỏ ghi chú `bearer_token_file: /etc/prometheus/secrets/metrics_scrape_token` trong `observability/prometheus.yml` cho cả hai job `sda_api` (`/api/v1/health/metrics`) và `sda_worker` (`worker:9102/metrics`).
- Cảnh báo `AuditIntegrityCompromised` trong `observability/alert_rules.yml` giám sát bộ đếm `sda_audit_integrity_compromised_total` từ cả `sda_api` lẫn `sda_worker`.

Hướng dẫn khởi chạy và cấu hình cổng dịch vụ: xem tại [README.md gốc](../README.md).
`pnpm db:validate` kiểm chứng lược đồ cơ sở dữ liệu nền tảng bằng PGlite WASM độc lập.
