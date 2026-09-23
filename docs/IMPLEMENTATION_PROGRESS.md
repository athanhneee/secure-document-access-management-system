# Implementation progress

## Prompt 05 — Hardened authentication

- Ngày: 2026-09-19.
- Đã làm: migration bốn bảng auth; Argon2id benchmark/policy; Ed25519 JWT/JWKS/key rotation;
  cookie + CSRF; opaque refresh rotation/reuse alert; session revoke; admin-create-user;
  login/logout/logout-all; change/forgot/reset password; TOTP/recovery codes; audit và limiter.
- Migration: `20260919120000_hardened_authentication`, có rollback pre-production riêng.
- Kiểm tra đã chạy trong quá trình phát triển: API typecheck/build/unit; kết quả gate cuối cùng
  được ghi trong commit/report sau khi chạy toàn bộ `pnpm check`.
- Rủi ro vận hành: production phải cấp signing/audit/master key qua secret manager; cấu hình
  SMTP và Origin allowlist; rotation theo ADR-007.
- Prompt 06: đã triển khai API/UI quản trị Users, Departments và scoped RBAC, guard resource/action,
  cache invalidation, audit before/after và optimistic concurrency. Trạng thái hoàn tất chỉ được
  xác nhận sau khi toàn bộ `pnpm check` đạt.
- Prompt 07: đã hoàn tất typed AST/operator allowlist, validator trước activation, default deny và
  deny-overrides, hard gate clearance, obligations, simulation có audit, Redis compiled-policy cache
  theo version cùng migration trigger invalidation. `pnpm check` đã đạt ngày 2026-09-22; coverage
  riêng ABAC đạt 92.22% line, 80.33% branch và 96.04% function.
- Bước tiếp theo theo lộ trình: Prompt 08 upload an toàn và mã hóa envelope.
- Prompt 08: Đã triển khai streaming multipart upload, kiểm tra allowlist format (PDF, DOCX, XLSX, PPTX) và magic bytes, quét virus ClamAV/EICAR và cách ly quarantine, chống zip bomb, mã hóa envelope AES-256-GCM với KMS DEK/KEK và compensation tự động dọn dẹp file mồ côi.
- Prompt 09: Đã triển khai đầy đủ vòng đời Documents và phân loại mật:
  - Tạo tài liệu ở `DRAFT`, bắt buộc đủ metadata (owner, department, title, business category, classification) và current version `CLEAN` trước khi `ACTIVE`.
  - Kiểm tra `current_version_id` chỉ trỏ tới phiên bản `CLEAN` thuộc đúng tài liệu.
  - Tăng số phiên bản nguyên tử trong transaction có khóa `FOR UPDATE`, bảo vệ chống race condition sinh trùng số phiên bản và không ghi đè file lưu trữ.
  - Lịch sử phân loại lưu dạng SCD Type 2 (`effective_from`/`effective_to`), đóng dòng cũ và mở dòng mới trong transaction.
  - Nâng mức mật tự động đánh giá lại grant hiện hành: thu hồi (`REVOKED`) grant của user clearance không đủ và kết thúc (`TERMINATED`) session liên quan; hạ mức mật không tự mở rộng quyền cũ.
  - Chuyển `ARCHIVED` chặn request mới, suspend grant cũ, terminate session và cập nhật `archived_at`.
  - Hỗ trợ `retention_until` và job cảnh báo sắp hết hạn lưu trữ, không tự xóa file khi chưa có phê duyệt.
  - Phân quyền mutation chặt chẽ: chỉ owner hoặc quản trị viên nghiệp vụ theo scope phòng ban mới được sửa metadata; kỹ thuật admin không mặc nhiên là owner.
  - Ghi audit log HMAC-SHA256 chained partition `DOCUMENT` cho toàn bộ sự kiện vòng đời.
  - Bước tiếp theo theo lộ trình: Prompt 10 tìm kiếm an toàn và quyền DISCOVER.
- Prompt 12: Đã triển khai Access Grant như giấy phép có thời hạn (time-bound license):
  - Owner cấp grant trực tiếp cho USER hoặc ROLE, không cho cả hai cùng lúc; quyền chỉ VIEW hoặc DOWNLOAD; bắt buộc valid_from và valid_until.
  - Pre-checks: RBAC, ownership, clearance ≥ classification, allow_download cho DOWNLOAD, ABAC evaluate.
  - Grant cho role vẫn kiểm tra clearance từng user tại mỗi lần truy cập. VIEW không suy ra DOWNLOAD.
  - Overlap detection: grant trùng document+principal+permissions → gia hạn (extend); permissions khác → reject.
  - Worker hết hạn grant theo lịch (60s default); mỗi API request vẫn tự kiểm tra thời gian.
  - Thu hồi có reason, đổi status REVOKED, lưu revoked_by/revoked_at; không xóa bản ghi. Idempotent.
  - Thu hồi lập tức terminate tất cả access_sessions ACTIVE dựa trên grant. Invalidate cache.
  - Notification gửi async, không rollback revoke nếu notification lỗi.
  - Endpoint dùng idempotency và optimistic concurrency.
  - Audit log HMAC-SHA256 chained partition ACCESS_GRANT cho toàn bộ sự kiện.
  - Database migration: partial unique indexes chống duplicate, performance indexes cho worker.
  - Prompt 20 — Cổng release cuối & Hoàn tất đóng gói v1.0.0:
  - Ngày: 2026-09-23.
  - Đã làm:
    - Rà soát toàn bộ 20 prompt, 31 bảng cơ sở dữ liệu, FR01-FR20, BR01-BR20, D-BR01-D-BR20, và Traceability Matrix.
    - Xây dựng tài liệu vận hành doanh nghiệp: `docs/DEPLOYMENT.md`, `docs/BACKUP_RESTORE.md`, `docs/KEY_ROTATION.md`, `docs/INCIDENT_RESPONSE.md`, `docs/USER_GUIDE.md`, và `docs/DEMO_SCRIPT.md`.
    - Tạo `RELEASE_CHECKLIST.md` kiểm tra toàn diện chất lượng xuất xưởng và đối soát exit code.
    - Cấu hình triển khai chuẩn `docker-compose.production.example.yaml` tuân thủ bảo mật non-root (UID 10001 / 1000), read-only rootfs, drop all capabilities, zero plaintext secrets.
    - Triển khai kịch bản kiểm thử tự động sau triển khai `scripts/smoke-test.mjs` (7/7 bước đạt 100%).
    - Diễn tập sao lưu và phục hồi thảm họa `scripts/backup-restore.mjs` (8/8 bước đạt 100%, bảo toàn chuỗi băm HMAC Audit Log).
    - Rà soát bản quyền giấy phép phụ thuộc và khởi tạo `docs/sbom-inventory.json` qua `scripts/check-licenses-sbom.mjs` (100% bản quyền MIT, Apache-2.0, ISC, BSD).
    - Chạy toàn bộ các cổng kiểm định chất lượng: format check, linting (0 error, 0 warning), typecheck (0 error), unit/integration test (211/211 passed), secret scanner (0 secret).
  - Trạng thái: Sẵn sàng phát hành phiên bản `v1.0.0`.
