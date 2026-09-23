# Sổ Tay Vận Hành: Xoay Vòng Khóa Bảo Mật (Key Rotation Runbook)

Hệ thống Quản Lý Truy Cập Tài Liệu Mật Trong Tổ Chức (SDA v1.0.0).
Tài liệu hướng dẫn chuẩn hóa quy trình xoay vòng các loại khóa mật mã trong hệ thống mà không gây gián đoạn dịch vụ (Zero-Downtime Key Rotation).

---

## 1. Tổng Quan Các Loại Khóa Trong Hệ Thống

| Loại Khóa                | Biến Môi Trường / Cấu Hình           | Thuật Toán & Độ Dài       | Chu Kỳ Xoay Vòng               | Mức Độ Rủi Ro |
| :----------------------- | :----------------------------------- | :------------------------ | :----------------------------- | :------------ |
| **Token Signing Key**    | `JWT_PRIVATE_KEY` / `JWT_PUBLIC_KEY` | Ed25519 (EdDSA RFC 8032)  | 90 ngày hoặc khi nghi ngờ lộ   | Rất Cao       |
| **Master Key (KEK)**     | `KMS_MASTER_KEY`                     | AES-256-GCM / 256-bit Key | 180 ngày hoặc định kỳ hàng năm | Cực Kỳ Cao    |
| **Audit HMAC Key**       | `AUDIT_HMAC_KEY`                     | HMAC-SHA256               | Định kỳ theo năm (kèm anchor)  | Cao           |
| **Database Credentials** | `POSTGRES_PASSWORD`                  | SCRAM-SHA-256             | 90 ngày                        | Cao           |
| **Redis Secret**         | `REDIS_PASSWORD`                     | Pre-shared Secret         | 90 ngày                        | Trung bình    |

---

## 2. Quy Trình Xoay Vòng Khóa Ký Token (Ed25519 JWKS Rotation)

Hệ thống sử dụng cơ chế JWKS với nhiều `kid` (Key ID), cho phép xác thực đồng thời cả khóa cũ và khóa mới trong thời gian chuyển tiếp (Grace Period).

### Bước 1: Sinh Cặp Khóa Ed25519 Mới

```bash
node -e '
const { generateKeyPairSync } = require("crypto");
const { privateKey, publicKey } = generateKeyPairSync("ed25519");
console.log("=== NEW PRIVATE KEY ===");
console.log(privateKey.export({ format: "pem", type: "pkcs8" }));
console.log("=== NEW PUBLIC KEY ===");
console.log(publicKey.export({ format: "pem", type: "spki" }));
'
```

### Bước 2: Cập Nhật Cấu Hình Grace Period

1. Cấu hình khóa công khai mới song song với khóa cũ.
2. Triển khai API server hỗ trợ xác thực cả 2 khóa.
3. Ký các access token mới bằng khóa mới.
4. Đợi hết hạn token cũ (tối đa 5 phút + leeway 2 phút).
5. Xóa bỏ khóa cũ khỏi danh sách tin cậy.

---

## 3. Quy Trình Xoay Vòng Khóa Master KEK (Envelope Key Rotation)

Khóa Master KEK (`KMS_MASTER_KEY`) dùng để bọc (wrap) các khóa DEK 256-bit ngẫu nhiên của từng phiên bản tài liệu. Chuỗi `encryption_key_ref` trong cơ sở dữ liệu có dạng:
`local-kms:v1:<base64url_wrapped_dek>`.

### Chiến Lược: Multi-Version KEK Support

1. Hệ thống hỗ trợ định danh phiên bản khóa (`v1`, `v2`, ...).
2. Khi cấu hình KEK v2 mới, các tài liệu mới sẽ được bọc bằng KEK v2.
3. Tiến trình Worker chạy ngầm giải bọc DEK bằng KEK v1 và bọc lại bằng KEK v2 (Rewrap without re-encrypting ciphertext payload).
4. Cập nhật `encryption_key_ref` thành `local-kms:v2:<new_wrapped_dek>`.
5. Sau khi 100% tài liệu chuyển sang v2, loại bỏ KEK v1 khỏi cấu hình an toàn.

---

## 4. Xoay Vòng Khóa HMAC Nhật Ký Kiểm Toán (Audit HMAC Key Rotation)

1. Ghi nhận bản ghi neo (Anchor Log Record) đặc biệt có `action="KEY_ROTATION_ANCHOR"` được ký bởi cả khóa HMAC cũ và khóa HMAC mới.
2. Từ bản ghi kế tiếp, chuỗi băm HMAC tiếp tục liên tục bằng khóa mới.
3. Khi kiểm tra tính toàn vẹn (Verification), `AuditVerifierService` sử dụng khóa tương ứng theo mốc sequence được neo lại.

---

## 5. Diễn Tập Xoay Vòng Khóa Định Kỳ

Định kỳ mỗi quý (90 ngày), đội ngũ SRE và Security thực hiện diễn tập xoay vòng trên môi trường Staging:

```bash
node scripts/smoke-test.mjs
```

Đảm bảo tất cả các token hiện hữu tiếp tục hoạt động trong grace period và việc giải mã tài liệu diễn ra trơn tru không gián đoạn.
