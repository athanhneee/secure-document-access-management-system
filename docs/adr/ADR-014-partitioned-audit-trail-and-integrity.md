# ADR-014: Partitioned Audit Trail & Accountability Without Data Leakage

- Trạng thái: Accepted
- Ngày: 2026-09-23

## Bối cảnh

Hệ thống quản lý truy cập tài liệu mật yêu cầu lưu trữ nhật ký kiểm toán (audit trail) chống chối bỏ (non-repudiation) và chống sửa đổi (tamper-evident). Tuy nhiên, nếu áp dụng một chuỗi hash toàn cục (`GLOBAL`), tất cả các giao dịch ghi audit trên toàn hệ thống buộc phải tuần tự hóa qua một khóa duy nhất (`pg_advisory_xact_lock`), gây nghẽn nghiêm trọng (lock contention) khi lưu lượng ghi đồng thời tăng cao. Đồng thời, việc lưu trữ chi tiết nghiệp vụ nếu không được lọc kỹ lưỡng có nguy cơ biến nhật ký kiểm toán thành nguồn rò rỉ dữ liệu nhạy cảm (thông tin đăng nhập, token, khóa DEK/KEK, nội dung tài liệu plaintext).

## Quyết định

1. **Phân vùng chuỗi Hash theo nghiệp vụ (Partitioned Chains)**:
   - Thay vì dùng chuỗi toàn cục, nhật ký kiểm toán được phân chia thành các chuỗi độc lập theo phân vùng nghiệp vụ (`AUTH`, `DOCUMENT`, `ACCESS_GRANT`, `ACCESS_SESSION`, `SYSTEM`, `RBAC`, `ABAC`).
   - Mỗi phân vùng duy trì một chuỗi sequence độc lập (`chain_sequence`) và liên kết băm (`previous_hash` $\rightarrow$ `entry_hash`).
   - Khóa đồng thời cô lập ở mức phân vùng qua `pg_advisory_xact_lock(hashtext(chain_partition))`, cho phép các thao tác thuộc các phân vùng khác nhau diễn ra song song hoàn toàn mà không gây xung đột lock.

2. **Chuẩn hóa dữ liệu theo RFC 8785 (JSON Canonicalization Scheme)**:
   - Sử dụng thuật toán chuẩn hóa JSON xác định theo RFC 8785: sắp xếp key theo thứ tự từ điển UTF-16 code units, chuẩn hóa số và chuỗi, loại bỏ khoảng trắng dư thừa.
   - Bảo đảm tính xác định (`deterministic`) của payload giữa các nền tảng và môi trường khác nhau.

3. **HMAC-SHA-256 với Khóa bí mật nằm ngoài Database**:
   - `entry_hash = HMAC-SHA-256(canonicalPayload, integrityKey)`.
   - Khóa toàn vẹn (`AUDIT_INTEGRITY_KEY`) được lưu trữ hoàn toàn ngoài cơ sở dữ liệu qua biến môi trường hoặc Secret Manager, hỗ trợ xoay vòng khóa qua `hmac_key_version` và `AUDIT_KEY_ROTATION_JSON`.
   - Tuyệt đối không lưu khóa bí mật trong cơ sở dữ liệu, mã nguồn hoặc file log.

4. **Append-Only & Bảo vệ chống sửa đổi nhiều lớp**:
   - Cơ sở dữ liệu: Kích hoạt trigger `trg_audit_no_update` chặn mọi thao tác `UPDATE` hoặc `DELETE` trên bảng `audit_logs` và `audit_anchors`.
   - Cơ sở dữ liệu: Trigger `trg_validate_audit_chain_link` xác thực tính liên tục của `previous_hash` ngay tại thời điểm chèn bản ghi.
   - Ứng dụng: `AuditWriterService` không bao giờ nuốt lỗi audit; nếu ghi audit thất bại, toàn bộ giao dịch nghiệp vụ liên quan sẽ bị hủy bỏ (fail-closed).

5. **Bộ lọc dữ liệu nhạy cảm đệ quy (Redaction Engine)**:
   - `AuditRedactionService` đệ quy quét và che giấu (`[REDACTED]`) toàn bộ các trường nhạy cảm: `password`, `token`, `rawToken`, `refreshToken`, `accessToken`, `dek`, `kek`, `secret`, `cookie`, `key`, `plaintext`, `content`, `credit_card`, `totpSecret`, `recoveryCode`.
   - Regex lọc tự động Bearer token, JWT chuỗi và watermark token.
   - `userAgent` được cắt gọn tối đa 255 ký tự và loại bỏ ký tự điều khiển để phòng chống log injection.

6. **Mốc neo định kỳ (Audit Anchors) & Kiểm tra tính toàn vẹn (Audit Verifier)**:
   - Định kỳ ký phát hành các checkpoint neo (`audit_anchors`) lưu trữ `anchor_sequence`, `entry_hash` và chữ ký xác thực.
   - `AuditVerifierService` và worker ngầm `startAuditVerificationJob` định kỳ quét toàn bộ các phân vùng, phát hiện chuỗi đứt (`AUDIT_CHAIN_BROKEN`), thiếu bản ghi (`AUDIT_SEQUENCE_GAP`), sửa đổi dữ liệu (`AUDIT_LOG_TAMPERED`), hoặc sai lệch neo (`AUDIT_ANCHOR_MISMATCH`).
   - Khi phát hiện sai lệch: tự động sinh bản ghi `SecurityAlert` mức độ `CRITICAL` và liên kết trực tiếp qua `alert_audit_links`.

7. **Phân quyền truy cập & Chống IDOR**:
   - `SECURITY_OFFICER` và `AUDITOR` có quyền truy vấn audit toàn hệ thống.
   - `DOCUMENT_OWNER` chỉ có quyền xem nhật ký kiểm toán liên quan đến các tài liệu thuộc quyền sở hữu của họ. Truy vấn tài liệu của người khác lập tức bị chặn với lỗi `403 Forbidden`.
   - `SYSTEM_ADMIN` bị từ chối truy cập audit theo nguyên tắc phân tách nhiệm vụ (Separation of Duties).

## Hệ quả

- Hiệu năng ghi audit đồng thời cao, không bị thắt cổ chai bởi khóa toàn cục.
- Bất kỳ hành vi chỉnh sửa hoặc xóa bản ghi nào (kể cả bởi người quản trị database nếu can thiệp trực tiếp) đều bị phát hiện bởi Verifier Job và kích hoạt cảnh báo `CRITICAL`.
- Không có bất kỳ bí mật, token hay dữ liệu nội dung tài liệu nào bị rò rỉ trong log.

## Kiểm chứng

- Test tính xác định của RFC 8785 Canonicalization.
- Test khả năng ghi đồng thời trên nhiều phân vùng độc lập.
- Test phát hiện chỉnh sửa bản ghi (HMAC mismatch) và sinh cảnh báo `CRITICAL`.
- Test phát hiện khoảng trống sequence (do xóa bản ghi).
- Test cơ chế append-only chặn `UPDATE`/`DELETE` ở database trigger.
- Test phân quyền tra cứu và chống IDOR cho Document Owner.
