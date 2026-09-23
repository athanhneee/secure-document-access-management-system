# Nhật ký quyết định

Mọi quyết định làm thay đổi nghiệp vụ hoặc database cần được ghi trước khi triển khai, có lý do, ảnh hưởng dữ liệu và cách kiểm chứng. Các mục bootstrap dưới đây không sửa nghiệp vụ hoặc schema nguyên bản.

## BOOT-001 — Phạm vi khởi tạo repository

- Ngày: 2026-09-13.
- Trạng thái: áp dụng cho bootstrap.
- Bối cảnh: yêu cầu hiện tại trùng phạm vi Prompt 01 của bộ lộ trình 20 prompt.
- Quyết định: tạo nền monorepo, công cụ phát triển, ứng dụng/package khởi tạo, kiểm tra và tài liệu. Prompt 02–20 là kế hoạch tương lai; không triển khai toàn bộ hệ thống, không seed tài khoản, không mở quyền truy cập nội dung tài liệu thật.
- Ảnh hưởng: không thay đổi quy trình nghiệp vụ, tên bảng, quan hệ hoặc dữ liệu. Báo cáo kết quả phải phân biệt smoke test nền với acceptance nghiệp vụ tương lai.

## BOOT-002 — Bảo toàn nguồn và tài liệu dẫn xuất

- Ngày: 2026-09-13.
- Trạng thái: áp dụng.
- Quyết định: sao chép nguyên byte bốn tài liệu đầu vào và AGENTS gốc vào `docs/reference`; lưu inventory/SHA-256. Không formatter hoặc Git line-ending normalization các bản gốc. Root AGENTS là hướng dẫn thực thi được cập nhật cho monorepo.
- Quy tắc nguồn: tài liệu tham chiếu giữ bằng chứng nghiệp vụ; các tài liệu dẫn xuất không được thay đổi nghĩa nguồn. Dùng thứ tự yêu cầu → business rules → API contract → SQL → tài liệu khác trong AGENTS cho tài liệu làm việc; nếu dẫn xuất mâu thuẫn nguồn, sửa truy vết/ghi quyết định, không dùng dẫn xuất để lách nghiệp vụ gốc.
- Thay đường dẫn: vị trí SQL được cung cấp là `docs/reference/database_secure_document_system.sql`; đường dẫn `database/database_secure_document_system.sql` trong AGENTS gốc chưa tồn tại khi nhận đầu vào. Monorepo quản lý lớp database tại `packages/database`; đây là tổ chức file, không đổi schema.
- Khoảng trống: thiếu báo cáo DOCX, FR/BR nguyên bản và NFR định lượng. Dùng mã D-BR01–D-BR20 cho bản tổng hợp và ghi nguồn; chưa xác nhận tương đương BR01–BR20 của báo cáo.
- Kiểm chứng: SHA-256 bản sao khớp nguồn, SQL/DBML có 31 bảng, PUML có 5 tác nhân và 30 use case.

## BOOT-003 — SQL PostgreSQL nguyên bản, chưa chuyển Prisma

- Ngày: 2026-09-13.
- Trạng thái: áp dụng cho bootstrap; mapping Prisma thuộc giai đoạn sau.
- Bối cảnh: SQL ghi PostgreSQL 15+ và mô tả đầy đủ 31 bảng; bộ prompt định hướng PostgreSQL 18/Prisma ở Prompt 03–04. DBML lược CHECK, index/trigger và dùng kiểu sơ đồ thay cho TIMESTAMPTZ/JSONB/INET.
- Quyết định: bảo toàn SQL raw làm thiết kế vật lý. Bootstrap không tái sinh schema từ DBML, không thêm Prisma model, không đổi enum/check/trigger hoặc thêm bảng auth/concurrency/HMAC. Kiểm tra migration/schema nền dùng bản SQL này trên database sạch hoặc môi trường kiểm chứng được ghi rõ.
- Ảnh hưởng: cài đặt SQL thành công chỉ chứng minh DDL tương thích môi trường đã chạy, không chứng minh đầy đủ authorization, integrity writer, database permissions hoặc nghiệp vụ. Prisma client, migration history triển khai, seed, auth tables và hạ tầng production còn thuộc các prompt tiếp theo.
- Điểm lưu ý: grant ROLE và truy cập thực tế cần policy backend; trigger clearance USER không thay thế việc đó. Audit có trigger chống UPDATE/DELETE nhưng chưa có writer/verifier HMAC. UNIQUE decision chưa đảm bảo một grant cho mỗi request. Các yêu cầu bổ sung đã có trong lộ trình, phải được giải quyết bằng ADR/migration phù hợp khi triển khai.

## BOOT-004 — Các khác biệt và câu hỏi chưa quyết định

| Vấn đề                                                                         | Bằng chứng                                                   | Cách xử lý hiện tại                                                                                           |
| ------------------------------------------------------------------------------ | ------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------- |
| Báo cáo/FR/BR/NFR chưa có                                                      | Bộ prompt phần Cách sử dụng, P17, P20; inventory đầu vào     | Công khai thiếu nguồn, không bịa định nghĩa hoặc số đo                                                        |
| SQL chi tiết hơn DBML                                                          | SQL có TIMESTAMPTZ/JSONB/INET, CHECK, partial index, trigger | SQL chuẩn vật lý; không chỉnh hai nguồn                                                                       |
| 31 bảng ban đầu và bảng auth tương lai                                         | P04 so với P05 nhiệm vụ 2                                    | Giữ 31 bảng bootstrap; bảng bổ sung phải có quyết định/migration riêng                                        |
| Nhiều combining algorithm trong SQL nhưng deny-overrides mặc định trong prompt | `policy_rules` CHECK/default; P07 nhiệm vụ 4                 | Giữ nguyên SQL; backend mặc định deny-overrides, thuật toán khác cần hợp đồng rõ                              |
| Quy tắc chưa được schema đảm bảo toàn bộ                                       | P09/P11/P12/P14 so với SQL                                   | Ghi khoảng trống, không tuyên bố acceptance nghiệp vụ đã đạt                                                  |
| Phiên bản mục tiêu có thể chưa phát hành                                       | Stack mục tiêu trong bộ prompt                               | Người phụ trách bootstrap xác minh official release/registry và ghi quyết định phiên bản riêng trước khi khóa |

## INFRA-001 — Hạ tầng local cô lập và secrets sinh theo máy

- Ngày: 2026-09-17.
- Trạng thái: áp dụng cho phát triển local và CI; không phải cấu hình production.
- Quyết định: dùng Docker Compose với PostgreSQL `18.6-alpine3.24`, Redis
  `8.2.9-alpine`, MinIO Community `quay.io/minio/minio:RELEASE.2025-07-23T15-54-02Z`,
  MinIO Client `quay.io/minio/mc:RELEASE.2025-08-13T08-35-41Z`, ClamAV `1.5.4`, Mailpit `1.30.6`, Prometheus
  `3.13.3` và Grafana `13.2.2`. Mỗi image khóa patch hoặc release timestamp; thay đổi
  phiên bản phải chạy lại toàn bộ gate và test persistence/privacy/malware.
- Secrets: không ghi credential cố định vào Compose. Node `crypto.randomBytes` sinh
  `.local/dev.env` đã gitignore; file production không dùng lại cơ chế này.
- Storage: ba bucket theo ADR-003 là private và versioned; bootstrap idempotent.
  `infra:down` giữ named volume, còn `infra:reset-safe` cần xác nhận target chính xác.
- Network: mọi port chỉ bind loopback. Network backend là internal; chỉ ClamAV nối
  thêm egress để cập nhật chữ ký. Resource/pid limit ngăn dependency local chiếm toàn
  bộ máy.
- MinIO: bản Community container là legacy và chỉ chấp nhận cho local đã cô lập;
  không dùng làm lựa chọn production. Production phải chọn S3-compatible storage còn
  được hỗ trợ và qua đánh giá license/security riêng.
- Database/nghiệp vụ: quyết định này không sửa SQL 31 bảng, không biến Redis thành
  source of truth và không mở public bucket/API nghiệp vụ.
- Kiểm chứng: Compose healthcheck, readiness ready/degraded, anonymous object `403`,
  restart persistence, versioning/private policy, EICAR qua ClamAV, secret scan và CI
  khởi tạo volume sạch.

## DB-001 — Triển khai Prisma cho 31 bảng và tiến hóa integrity

- Ngày: 2026-09-18.
- Trạng thái: áp dụng; thay thế giới hạn “chưa chuyển Prisma” của BOOT-003 cho giai đoạn Prompt 04, không thay đổi các bằng chứng baseline.
- Quyết định: chấp nhận [ADR-006](adr/ADR-006-prisma-schema-evolution-and-audit-integrity.md), mapping đủ 31 bảng, migration SQL đầy đủ, optimistic concurrency cho ba aggregate và metadata HMAC chain cho audit.
- Phạm vi sai khác có chủ đích: chỉ thêm cột vào `documents`, `access_requests`, `access_grants` và `audit_logs`; không thêm/bỏ bảng, không giản lược foreign key/check/index/trigger nguồn.
- Kiểm chứng: [bảng mapping](database-prisma-mapping.md), migration PostgreSQL 18 từ database trống, seed hai lần, test constraint/rollback và toàn bộ quality gate.

## AUTH-001 — Tách trạng thái authentication và dùng Ed25519

- Ngày: 2026-09-19.
- Trạng thái: áp dụng cho Prompt 05.
- Quyết định: chấp nhận [ADR-007](adr/ADR-007-hardened-authentication.md); thêm đúng bốn bảng
  auth bằng migration riêng, dùng Argon2id đã benchmark, access JWT Ed25519 có `kid`, opaque
  refresh token rotate theo family, TOTP/recovery code và cookie + Origin/double-submit CSRF.
- Ảnh hưởng: tổng schema triển khai là 35 bảng nhưng 31 bảng nghiệp vụ chuẩn giữ nguyên; bảng
  `access_sessions` tiếp tục chỉ dành cho truy cập tài liệu. Không lưu token plaintext hoặc
  signing key trong database/source/log.
- Kiểm chứng: migration từ database sạch và rollback; test expiry/issuer/audience, cookie,
  reuse/revoke family + alert, DISABLED/session revoked, CSRF, brute force, timing/message và MFA.

## RBAC-001 — Quản trị RBAC có phạm vi, ủy quyền không vượt quyền và concurrency

- Ngày: 2026-09-19.
- Trạng thái: áp dụng cho Prompt 06.
- Quyết định phạm vi: một `user_roles.scope_department_id` áp dụng cho đúng phòng ban đó và toàn
  bộ cây con còn active. Assignment không có scope là toàn cục. Quyền quản lý catalog role,
  permission và mapping system role chỉ được thực hiện bởi principal có `ROLE/MANAGE` toàn cục;
  quản trị có scope chỉ được quản lý user, gán role và phòng ban trong cây được ủy quyền.
- Quyết định chống tự nâng quyền: người gán chỉ được ủy quyền permission mà chính họ đang có ở
  cùng phạm vi hoặc phạm vi rộng hơn; không được gán/thu hồi role cho chính mình, sửa mapping của
  role mình đang giữ, disable chính mình hoặc disable role mình đang giữ. Ba vai trò đặc quyền
  `SYSTEM_ADMIN`, `SECURITY_OFFICER`, `AUDITOR` loại trừ lẫn nhau để bảo đảm separation of duties.
  `SYSTEM_ADMIN` không được cấp ngầm `DOCUMENT/VIEW`.
- Quyết định vòng đời: user chuyển phòng ban sẽ kết thúc tại thời điểm chuyển mọi assignment còn
  hiệu lực scoped đúng phòng ban cũ; assignment toàn cục không đổi. Phòng ban inactive không nhận
  user/scope mới và chỉ được vô hiệu khi không còn phòng ban con active, user chưa disable hoặc
  assignment scoped còn hiệu lực. User/role disable làm mất hiệu lực session hoặc authorization
  cache ngay trong luồng ghi.
- Thay đổi schema: thêm cột `version` cho `users`, `departments`, `roles` để optimistic concurrency;
  thêm trigger PostgreSQL từ chối self-parent và mọi chu trình phòng ban, kể cả ghi ngoài API.
  Không thêm bảng và không thay đổi ý nghĩa các quan hệ chuẩn.
- Audit: mọi mutation quản trị ghi before/after đã allowlist trong cùng serializable transaction,
  vào HMAC chain partition `RBAC`; không ghi password/hash/token/secret.
- Kiểm chứng: migration sạch/rollback, test ma trận năm role, 401/403, expiry/scope/IDOR, chuyển
  phòng ban, cache invalidation, optimistic concurrency và tính nguyên tử của audit.

## ABAC-001 — Policy version monotonic, obligations và mô hình đánh giá xác định

- Ngày: 2026-09-22.
- Trạng thái: áp dụng cho Prompt 07.
- Quyết định biểu diễn: giữ năm bảng ABAC chuẩn làm nguồn dữ liệu. Bổ sung `version BIGINT` cho
  `attribute_definitions` và `policy_rules`, cùng `policy_rules.obligations JSONB`; không thêm bảng
  nghiệp vụ. Obligation chỉ nhận năm loại đã phê duyệt và được backend validate trước khi activate.
- Quyết định version: sequence PostgreSQL dùng chung cấp version tăng đơn điệu. Trigger tăng version
  khi rule, condition, attribute definition hoặc option thay đổi, kể cả ghi ngoài API. Xóa cũng cấp
  version mới để cache theo version cũ không còn được chọn. Redis chỉ lưu AST đã compile, không là
  source of truth; lỗi cache quay về compile từ PostgreSQL và vẫn fail closed khi policy không hợp lệ.
- Quyết định đánh giá: AST typed, group OR và condition trong group AND; operator dùng allowlist cố
  định, không compile/thực thi chuỗi. Rule được sắp theo `priority`, sau đó `id`; combining algorithm
  duy nhất được activate là `DENY_OVERRIDES`, không có permit phù hợp thì DENY. Clearance thấp hơn
  classification và thiếu attribute bắt buộc là hard deny trước khi xét permit.
- Quyết định simulate: `POST /api/v1/abac/simulate` cần permission toàn cục `POLICY/SIMULATE`, chỉ
  cấp cho `SYSTEM_ADMIN` và `SECURITY_OFFICER`. Endpoint chỉ mô phỏng, không tạo grant/session/token;
  subject/resource lấy lại từ database, audit không chứa title, mô tả hoặc nội dung tài liệu.
- Kiểm chứng: migration sạch/rollback; unit table-driven và deterministic/property loop; timezone,
  CIDR IPv4/IPv6, null/missing, boundary time, deny conflict, assignment hết hạn; integration cho
  authorization, audit và Redis version invalidation.

## DOC-001 — Vòng đời tài liệu, quản lý phiên bản nguyên tử, SCD Type 2 lịch sử phân loại và xử lý tăng/giảm mức mật

- Ngày: 2026-09-23.
- Trạng thái: áp dụng cho Prompt 09.
- Quyết định vòng đời DRAFT/ACTIVE/ARCHIVED: tài liệu được tạo ở trạng thái `DRAFT`. Chỉ được chuyển `ACTIVE` khi đã đủ metadata bắt buộc gồm: `owner_id` (active user), `department_id` (active department), `title` (không rỗng), phân loại hiện hành (`classification_level_id` và `business_category_id` trong `document_classification_history`) và `current_version_id` trỏ tới phiên bản có `scan_status = 'CLEAN'`.
- Quyết định phiên bản và concurrency: upload phiên bản mới không ghi đè object cũ; storage key dùng UUID phân tách riêng. `version_no` tăng nguyên tử bên trong transaction có khóa bi quan `SELECT ... FOR UPDATE` trên bảng `documents`, bảo đảm loại trừ tương tranh và chống hai upload đồng thời sinh trùng số phiên bản. Không cho phép upload phiên bản mới lên tài liệu đã `ARCHIVED` hoặc `DELETED`.
- Quyết định lịch sử phân loại: `document_classification_history` lưu theo mô hình SCD Type 2 (`effective_from`, `effective_to`). Khi điều chỉnh phân loại, dòng hiện hành được đóng (`effective_to = now()`) và dòng mới được tạo (`effective_to = NULL`) trong cùng một transaction. Ràng buộc partial unique index `uq_document_current_classification` trên PostgreSQL bảo đảm tại mọi thời điểm chỉ có tối đa một bản ghi phân loại hiện hành cho mỗi tài liệu.
- Quyết định tăng/giảm mức mật:
  - Khi tăng mức mật (`newRank > oldRank`): hệ thống đánh giá lại toàn bộ `access_grants` đang `ACTIVE` của tài liệu. Các grant cho user có clearance rank thấp hơn mức mật mới bị chuyển thành `REVOKED` và mọi session liên quan bị `TERMINATED` ngay lập tức. Các session của role grant có user không đủ clearance cũng bị terminate. Xóa cache quyền của các user bị ảnh hưởng.
  - Khi giảm mức mật (`newRank < oldRank`): hệ thống tuyệt đối không tự ý phục hồi hoặc mở rộng các quyền đã bị thu hồi trước đó.
- Quyết định lưu trữ (ARCHIVED) và Retention:
  - Chuyển `ARCHIVED` bắt buộc cập nhật `archived_at = now()` (thỏa mãn DB check constraint), chuyển toàn bộ grant `ACTIVE` thành `SUSPENDED`, terminate toàn bộ session `ACTIVE`, và chặn vĩnh viễn các thao tác tải phiên bản mới hoặc gửi yêu cầu truy cập mới.
  - Cột `retention_until` được kiểm soát định dạng ngày hợp lệ. Job cảnh báo hạn lưu trữ định kỳ quét tài liệu sắp/đã hết hạn để gửi `Notification`, tạo `SecurityAlert` và ghi audit log. Tuyệt đối không tự xóa file khi chưa có quy trình và chính sách phê duyệt văn bản chính thức.
- Quyết định phân quyền mutation: chỉ `owner` của tài liệu hoặc người dùng có vai trò nghiệp vụ được ủy quyền trong phạm vi phòng ban tương ứng (`DOCUMENT/CLASSIFY`, `DOCUMENT/MANAGE`, `DOCUMENT/ARCHIVE`) mới được sửa metadata hoặc thay đổi trạng thái tài liệu. Vai trò kỹ thuật `SYSTEM_ADMIN` không mặc nhiên trở thành owner và bị chặn (403 `TECHNICAL_ADMIN_CANNOT_OWN`).
- Quyết định audit: toàn bộ sự kiện vòng đời (`DOCUMENT_CREATED`, `DOCUMENT_METADATA_UPDATED`, `DOCUMENT_ACTIVATED`, `DOCUMENT_CLASSIFIED`, `DOCUMENT_RECLASSIFIED`, `DOCUMENT_CURRENT_VERSION_SET`, `DOCUMENT_ARCHIVED`, `DOCUMENT_OWNER_TRANSFERRED`, `DOCUMENT_RETENTION_WARNING`) được ghi vào HMAC-SHA256 audit chain partition `DOCUMENT`.
- Kiểm chứng: unit test table-driven, test concurrency phiên bản, test SCD-2, test cascade revoke/terminate khi tăng mức mật, test không mở rộng khi giảm mức mật, test archive và retention job.

## SEARCH-001 — Tìm kiếm tài liệu có quyền DISCOVER, không rò rỉ sự tồn tại

- Ngày: 2026-09-23.
- Trạng thái: áp dụng cho Prompt 10.
- Quyết định search engine: dùng PostgreSQL `pg_trgm` GIN index cho fuzzy/partial matching và `to_tsvector('simple', ...)` cho full-text search. Config `'simple'` được chọn vì trung lập ngôn ngữ, hỗ trợ tiếng Việt có dấu, và không cần cài extension `unaccent` (yêu cầu superuser). Không index plaintext nội dung tài liệu ở phiên bản đầu — cần threat model và cơ chế mã hóa search phù hợp trước khi mở rộng.
- Quyết định visibility: kết quả search chỉ trả tài liệu mà user được phép biết theo ba điều kiện OR: (1) user là owner, (2) tài liệu `discoverable=true` AND `status=ACTIVE` AND user có permission `DOCUMENT/DISCOVER` trong phạm vi department tương ứng, (3) user có `access_grants` còn `ACTIVE` và trong thời hạn — bao gồm grant trực tiếp USER và grant qua ROLE. Toàn bộ logic lọc chạy phía server qua parameterized SQL (`Prisma.sql` tagged templates), không nối chuỗi input.
- Quyết định response: chỉ trả field tối thiểu (`id`, `documentCode`, `title`, `description` cắt 200 ký tự, `status`, `departmentName`, `classificationLevelName`, `classificationLevelCode`, `createdAt`, `updatedAt`). Không trả `owner_id` email, `storage_key`, `encryption_key_ref`, hash nội bộ hoặc tổng số tài liệu bị ẩn. Pagination dùng `page`, `pageSize`, `hasMore` — không có `totalCount`.
- Quyết định chống abuse: query tối đa 200 ký tự, strip regex/wildcard patterns (`*?[]{}\\^$|`), sort chỉ nhận allowlist (`created_at`, `updated_at`, `title`), page size tối đa 50. Stable tie-breaker bằng `d.id ASC`.
- Quyết định audit: search event ghi `DOCUMENT_SEARCHED` vào HMAC chain partition `DOCUMENT`. Search term được SHA-256 hash trước khi lưu vào `details.queryHash` — không log plaintext search term. `resultCount` và `page` cũng được ghi.
- Thay đổi schema: migration chỉ thêm index, không thêm/sửa cột hoặc bảng. Extension `pg_trgm` tạo via `CREATE EXTENSION IF NOT EXISTS`.
- Quyết định endpoint: `GET /documents` thay thế endpoint cũ (chưa có authorization) bằng search có quyền. `GET /documents/my-grants` cho phép user xem danh sách tài liệu đã được cấp grant mà không cần `DOCUMENT/DISCOVER`.
- Kiểm chứng: 13 unit test bao gồm IDOR prevention, owner visibility, grant visibility, revoked grant disappearance, sensitive field exclusion, totalCount exclusion, Vietnamese diacritics, fuzzy match, SQL injection neutralization, stable pagination, query length limit, audit hash verification và my-grants response format. Tổng 98/98 tests pass, lint/typecheck/format clean.

## FEAT-012 — Access Grant như giấy phép có thời hạn

- Ngày: 2026-09-23.
- Trạng thái: áp dụng cho Prompt 12.
- Quyết định overlap/extend: khi owner cấp grant mới trùng document+principal+permissions mà grant cũ còn ACTIVE, hệ thống gia hạn (extend) grant cũ bằng cách mở rộng valid_from/valid_until. Nếu permissions khác nhau → reject GRANT_OVERLAP_EXISTS. Đảm bảo bởi partial unique index trên database. Quyết định này tránh proliferation nhiều grants song song cho cùng một scope.
- Quyết định max duration: mặc định 365 ngày (env `GRANT_MAX_DURATION_DAYS`, min 1, max 730). Giới hạn này ngăn grant vĩnh viễn, đúng nguyên tắc giấy phép có thời hạn.
- Quyết định worker interval: mặc định 60 giây (env `GRANT_EXPIRY_INTERVAL_MS`). Mỗi API request vẫn tự kiểm tra valid_from/valid_until — worker là defense-in-depth, không thay thế realtime check. Worker dùng `FOR UPDATE SKIP LOCKED` cho batch safe với multiple instances.
- Quyết định notification: notification gửi async, fire-and-forget. Nếu notification lỗi → ghi log warn, không rollback grant creation/revocation. Lý do: thu hồi quyền truy cập tài liệu mật không được trì hoãn bởi hạ tầng notification không ổn định (D-BR20).
- Quyết định time interval: sử dụng half-open interval `[valid_from, valid_until)` — access valid khi `valid_from <= now < valid_until`. Consistent với database constraint và industry convention.
- Quyết định idempotency revoke: gọi revoke trên grant đã REVOKED trả bản ghi hiện tại không lỗi. Optimistic concurrency qua optional `expectedVersion`.
- Quyết định audit: HMAC-SHA256 chained partition `ACCESS_GRANT`, riêng biệt với partition `DOCUMENT`. Cùng HMAC key (`DOCUMENT_AUDIT_HMAC_KEY`). Actions: GRANT_CREATED, GRANT_EXTENDED, GRANT_REVOKED, GRANT_EXPIRED, GRANT_SESSIONS_TERMINATED.
- Thay đổi schema: migration chỉ thêm index (4 partial/performance indexes), không thêm/sửa cột hoặc bảng.
- Kiểm chứng: typecheck, lint, build và test suite phải pass.

## FEAT-013 — Phân phối tài liệu có kiểm soát và đóng dấu bản quyền động

- Ngày: 2026-09-23.
- Trạng thái: áp dụng cho Prompt 13.
- Bối cảnh: yêu cầu bảo vệ phân phối tài liệu mật (Controlled Distribution), tuyệt đối không trả storage URL dài hạn hoặc file thô chưa đóng dấu cho tài liệu bắt buộc watermark.
- Quyết định Policy Enforcement Point (PEP):
  - PEP chặn tại backend (`DocumentPepService`), nhận ngữ cảnh đầy đủ (user, document, action, time, IP, device, MFA, correlation ID).
  - Kiểm tra grant hợp lệ tại thời điểm yêu cầu (Zero Trust). Kiểm tra user clearance so với cấp độ mật của tài liệu.
  - Kiểm tra cấm tải: Classification `allow_download = false` hoặc ABAC trả obligation `FORBID_DOWNLOAD` đều từ chối yêu cầu tải.
  - Khi PERMIT, tạo nguyên tử bản ghi `access_sessions` ở trạng thái `ACTIVE` gắn kết chính xác grant, user, và phiên bản tài liệu hiện hành.
- Quyết định Preview an toàn:
  - Tài liệu PDF: hỗ trợ stream có kiểm soát và cắt trang độc lập (`extractPdfPage`) theo `pageNumber` 1-indexed.
  - Tài liệu Office OpenXML (.docx, .xlsx, .pptx): `OfficeConverterService` quét cấu trúc ZIP, chặn tuyệt đối mã macro VBA (`vbaProject.bin`, `vbaData.xml`, v.v. với mã lỗi `OFFICE_MACRO_BLOCKED`), không thực thi liên kết ngoài hay embedded objects, giới hạn timeout (mặc định 10s với `OFFICE_CONVERSION_TIMEOUT`), và trích xuất nội dung an toàn kết xuất thành PDF tiêu chuẩn.
- Quyết định Watermark động:
  - Định dạng hiển thị bắt buộc: họ tên hoặc username, mã nhân viên hoặc UID, timestamp UTC, mã tài liệu, token rút gọn (12 ký tự hex) và banner an ninh đầu/chân trang.
  - Sinh token ngẫu nhiên CSPRNG duy nhất (`WM-<48 hex chars>`), kết xuất mã QR khi cấu hình cho phép.
  - Lưu trữ `watermark_instances` liên kết chặt chẽ với session, user, version và watermark config phục vụ truy vết điều tra rò rỉ (UC28).
  - Fail-closed: mọi lỗi trong quá trình tạo watermark trên tài liệu bắt buộc đều dẫn đến DENY (`WATERMARK_GENERATION_FAILED`), tuyệt đối không fallback trả file trần.
- Quyết định Phân phối Download và Download Ticket:
  - Hỗ trợ vé tải một lần (Single-Use Download Ticket) có TTL ngắn (60 giây), gắn với session đang ACTIVE. Vé bị thu hồi/xóa ngay lập tức tại lần redeem đầu tiên.
  - Header bảo mật: `Cache-Control: no-store, no-cache, must-revalidate, private` và `Pragma: no-cache` trên mọi luồng phân phối.
- Quyết định dọn dẹp file tạm (Worker Cleanup):
  - `cleanStaleTempFiles` định kỳ dọn sạch các file giải mã tạm và file phái sinh vượt quá TTL (mặc định 60 phút) trên ổ đĩa.
- Quyết định Audit:
  - Ghi nhận `ACCESS_PERMITTED`, `ACCESS_DENIED`, `WATERMARK_GENERATED`, `DOCUMENT_PREVIEWED`, `DOCUMENT_DOWNLOADED` vào chuỗi HMAC-SHA256 partition `ACCESS_SESSION`.
- Kiểm chứng: 164/164 tests API và 7/7 tests Worker pass; bảo đảm đa trang PDF, chặn macro Office, timeout, file hỏng, single-use ticket, và concurrent access.

## FEAT-014 — Audit Trail chống sửa đổi và quy trách nhiệm không rò rỉ dữ liệu

- Ngày: 2026-09-23.
- Trạng thái: áp dụng cho Prompt 14.
- Bối cảnh: yêu cầu bảo vệ chuỗi kiểm toán (Audit Trail) chống giả mạo, chối bỏ, và rò rỉ thông tin nhạy cảm. Không dùng chuỗi hash toàn cục để tránh nghẽn khóa cơ sở dữ liệu trên tải cao.
- Quyết định Hash Chain phân vùng:
  - Phân chia chuỗi hash thành các phân vùng độc lập (`AUTH`, `DOCUMENT`, `ACCESS_GRANT`, `ACCESS_SESSION`, `SYSTEM`, `RBAC`, `ABAC`).
  - Mỗi phân vùng có `chain_sequence` độc lập và được cô lập khóa qua `pg_advisory_xact_lock(hashtext(chain_partition))`, triệt tiêu hoàn toàn lock contention xuyên phân vùng.
- Quyết định Chuẩn hóa & Tính toán HMAC:
  - Sử dụng thuật toán chuẩn hóa JSON xác định theo RFC 8785 (JSON Canonicalization Scheme).
  - Khóa toàn vẹn (`AUDIT_INTEGRITY_KEY`) được lưu trữ ngoài cơ sở dữ liệu (biến môi trường / Secret Manager), hỗ trợ xoay vòng khóa (`hmac_key_version`).
  - Mỗi bản ghi liên kết chặt chẽ `previous_hash` và `entry_hash = HMAC-SHA-256(canonicalPayload, key)`.
- Quyết định Append-Only & Ngăn chặn sửa đổi:
  - Trigger cơ sở dữ liệu `trg_audit_no_update` và `trg_audit_anchor_no_update` chặn toàn bộ thao tác `UPDATE` và `DELETE` trên bảng `audit_logs` và `audit_anchors`.
  - Trigger `trg_validate_audit_chain_link` xác thực tính liên tục của `previous_hash` ngay tại tầng database.
  - `AuditWriterService` không bao giờ nuốt lỗi audit; lỗi ghi audit luôn ném `AuditWriteException` làm rollback toàn bộ giao dịch nghiệp vụ (fail-closed).
- Quyết định Lọc dữ liệu nhạy cảm (Redaction Engine):
  - `AuditRedactionService` đệ quy làm sạch các trường nhạy cảm: `password`, `token`, `dek`, `kek`, `secret`, `cookie`, `plaintext`, `content`, `credit_card`, `totpSecret`.
  - Regex tự động che giấu Bearer tokens, chuỗi JWT và watermark tokens.
  - `userAgent` được cắt gọn an toàn (tối đa 255 ký tự) và loại bỏ ký tự điều khiển để chống log injection.
- Quyết định Mốc neo & Kiểm toán tính toàn vẹn (Verifier & Alerts):
  - Hỗ trợ tạo mốc neo đã ký (`audit_anchors`) theo định kỳ hoặc thủ công.
  - `AuditVerifierService` và Worker ngầm `startAuditVerificationJob` định kỳ quét toàn bộ các phân vùng, phát hiện đứt chuỗi (`AUDIT_CHAIN_BROKEN`), khoảng trống (`AUDIT_SEQUENCE_GAP`), sửa đổi dữ liệu (`AUDIT_LOG_TAMPERED`), hoặc sai lệch neo (`AUDIT_ANCHOR_MISMATCH`).
  - Khi phát hiện sai phạm: tự động kích hoạt bản ghi `SecurityAlert` mức độ `CRITICAL` và liên kết trực tiếp qua `alert_audit_links`.
- Quyết định Phân quyền Tra cứu & Chống IDOR:
  - `SECURITY_OFFICER` và `AUDITOR` có quyền xem toàn hệ thống. `AUDITOR` có quyền xuất dữ liệu CSV/JSON (`AUDIT_EXPORT`).
  - `DOCUMENT_OWNER` bị giới hạn phạm vi nghiêm ngặt, chỉ được xem nhật ký của chính tài liệu thuộc quyền sở hữu của họ. Truy vấn tài liệu khác bị chặn với 403 `Forbidden`.
  - `SYSTEM_ADMIN` bị từ chối truy cập theo nguyên tắc Separation of Duties (SoD).
  - Header bảo mật `Cache-Control: no-store, no-cache, must-revalidate, private` được áp dụng trên mọi luồng xuất kiểm toán.
- Kiểm chứng: unit test table-driven, test RFC 8785 canonicalization, test concurrency phân vùng, test tampering detection (HMAC mismatch), test sequence gap do xóa bản ghi, test append-only trigger, test IDOR và scoped permissions.


