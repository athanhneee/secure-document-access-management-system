# Sổ Tay Vận Hành: Xoay Vòng Khóa Bảo Mật (Key Rotation Runbook)

Tài liệu hướng dẫn chuẩn hóa quy trình xoay vòng các loại khóa mật mã trong hệ thống mà không gây gián đoạn dịch vụ (Zero-Downtime Key Rotation).

---

## 1. Tổng Quan Các Loại Khóa Trong Hệ Thống

| Loại Khóa | Biến Môi Trường / Cấu Hình | Thuật Toán & Độ Dài | Chu Kỳ Xoay Vòng | Mức Độ Rủi Ro |
| :--- | :--- | :--- | :--- | :--- |
| **Token Signing Key** | `AUTH_SIGNING_PRIVATE_KEY_PEM`<br>`AUTH_SIGNING_PUBLIC_KEYS_JSON` | Ed25519 (EdDSA RFC 8032) | 90 ngày hoặc khi nghi ngờ lộ | Rất Cao |
| **Master Key (KEK)** | `APP_ENCRYPTION_MASTER_KEY` | HKDF-SHA256 -> AES-256-GCM | 180 ngày hoặc định kỳ hàng năm | Cực Kỳ Cao |
| **Audit HMAC Key** | `AUDIT_HMAC_SECRET` | HMAC-SHA256 | Định kỳ theo năm (kèm anchor) | Cao |
| **Database Credentials** | `POSTGRES_PASSWORD` | SCRAM-SHA-256 | 90 ngày | Cao |
| **Redis Secret** | `REDIS_PASSWORD` | Pre-shared Secret | 90 ngày | Trung bình |

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

### Bước 2: Cập Nhật JWKS Cho Phép Xác Thực Cả Hai Khóa
1. Đặt `AUTH_ACTIVE_KID="key-2026-q4"` (Key ID mới).
2. Thêm khóa công khai mới vào mảng JSON trong `AUTH_SIGNING_PUBLIC_KEYS_JSON`, giữ lại khóa công khai cũ:
```json
[
  { "kid": "key-2026-q3", "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n..." },
  { "kid": "key-2026-q4", "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n..." }
]
```
3. Cập nhật `AUTH_SIGNING_PRIVATE_KEY_PEM` bằng Private Key mới.
4. Triển khai cấu hình lên toàn bộ cụm API (Rolling Update).

### Bước 3: Đợi Hết Hạn Token Cũ (Grace Period)
Thời hạn sống tối đa của Access Token là **300 giây (5 phút)**. Chờ tối thiểu 10 phút để tất cả Access Token ký bằng khóa cũ tự nhiên hết hạn.

### Bước 4: Thu Hồi Khóa Cũ Khỏi JWKS
Sau khi hết thời gian chờ, loại bỏ `key-2026-q3` khỏi `AUTH_SIGNING_PUBLIC_KEYS_JSON` và hoàn tất quy trình xoay vòng.

---

## 3. Quy Trình Xoay Vòng Khóa Master Mã Hóa File (KEK Rotation)

Khóa Master KEK (`APP_ENCRYPTION_MASTER_KEY`) dùng để bọc (wrap) các khóa DEK 256-bit ngẫu nhiên của từng phiên bản tài liệu. Chuỗi `encryption_key_ref` trong cơ sở dữ liệu có dạng:
`local-kms:v1:<base64url_wrapped_dek>`.

### Chiến Lược: Multi-Version KEK Support
1. Hệ thống hỗ trợ đa phiên bản KEK qua tiền tố `local-kms:v1`, `local-kms:v2`.
2. Khi xoay vòng sang `v2`:
   - Sinh chuỗi master key mới tối thiểu 32 ký tự ngẫu nhiên cao (CSPRNG).
   - Đặt `APP_ENCRYPTION_MASTER_KEY_V2` và thiết lập `KMS_ACTIVE_VERSION="v2"`.
   - Các file mới tải lên sẽ được wrap bằng `v2`.
   - Các file cũ được giải mã DEK bằng `v1` khi người dùng truy cập.
3. Chạy job nền re-wrap (tùy chọn) để bọc lại toàn bộ DEK trong DB sang `v2` mà không cần tải lại file ciphertext trên Object Storage:
```sql
-- Kiểm tra số lượng DEK cần re-wrap
SELECT COUNT(*) FROM document_versions WHERE encryption_key_ref LIKE 'local-kms:v1:%';
```

---

## 4. Quy Trình Xoay Vòng Khóa Kiểm Toán HMAC (Audit Anchor Rotation)

Nhật ký kiểm toán sử dụng chuỗi hash liên tục. Khi xoay vòng khóa HMAC:
1. Tạo một sự kiện neo đặc biệt (Audit Anchor): `AUDIT_KEY_ROTATED`.
2. Ghi nhận sequence hiện tại và hash chốt của phân vùng.
3. Cập nhật `AUDIT_HMAC_SECRET` mới cho các bản ghi tiếp theo.
4. Chạy `AuditVerifierService.verifyPartition()` để xác nhận chuỗi kiểm toán không bị gián đoạn.

---

## 5. Danh Sách Kiểm Tra Khẩn Cấp Khi Bị Lộ Khóa (Emergency Revocation Checklist)

Nếu phát hiện bất kỳ khóa nào bị lộ ra ngoài:
1. **Lập tức cô lập phiên**: Gọi API `/api/v1/auth/sessions/revoke-all` để hủy toàn bộ phiên đang hoạt động.
2. **Kích hoạt Emergency Key Rotation**: Thay thế ngay lập tức cặp khóa Ed25519 mà không cần chờ Grace Period.
3. **Quét rò rỉ**: Chạy script quét secret `pnpm security:secrets` và kiểm tra access log của các IP lạ.
4. **Ghi nhận sự cố**: Tạo báo cáo sự cố qua `IncidentsService` với mức độ `CRITICAL` và tiến hành điều tra truy vết.
