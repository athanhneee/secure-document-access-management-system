# Hạ tầng local

`compose.yaml` cung cấp PostgreSQL, Redis, MinIO, ClamAV, Mailpit, Prometheus và
Grafana cho phát triển local. Credential được sinh vào `.local/dev.env` đã gitignore;
Compose không chứa mật khẩu production hay mật khẩu local cố định.

Ba bucket MinIO được bootstrap idempotent, private và bật versioning. Các named volume
được giữ lại khi chạy `pnpm infra:down`; chỉ `pnpm infra:reset-safe` có thể xóa chúng
sau xác nhận chính xác.

Hướng dẫn vận hành, port và xử lý lỗi: [LOCAL_DEVELOPMENT.md](../docs/LOCAL_DEVELOPMENT.md).
`pnpm db:validate` vẫn chạy SQL tham chiếu nguyên bản độc lập bằng PGlite; test hạ tầng
không thay đổi database schema nguồn.
