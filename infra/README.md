# Hạ tầng local

`compose.yaml` cung cấp PostgreSQL, Redis, MinIO, ClamAV, Mailpit, Prometheus và
Grafana cho phát triển local. Credential được sinh vào `.local/dev.env` đã gitignore;
Compose không chứa mật khẩu production hay mật khẩu local cố định.

Ba bucket MinIO được bootstrap idempotent, private và bật versioning. Các named volume
được giữ lại khi chạy `pnpm infra:down`; chỉ `pnpm infra:reset-safe` có thể xóa chúng
sau xác nhận chính xác.

Hướng dẫn khởi chạy và cấu hình cổng dịch vụ: xem tại [README.md gốc](../README.md).
`pnpm db:validate` kiểm chứng lược đồ cơ sở dữ liệu nền tảng bằng PGlite WASM độc lập.
