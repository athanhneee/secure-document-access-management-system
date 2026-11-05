# Hướng dẫn Triển khai Cơ sở dữ liệu trên Supabase PostgreSQL

Thư mục này chứa bộ mã SQL hoàn chỉnh được viết lại từ toàn bộ 11 bản migration và dữ liệu khởi tạo chuẩn của dự án **Secure Document Access System**, tối ưu hóa chuyên biệt cho **Supabase PostgreSQL** và đồng bộ 100% với **Prisma 7 (`@sda/database`)**.

---

## 1. Cấu trúc tệp SQL

| Tệp                                    | Mục đích                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| -------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `00_reset_clean.sql`                   | _(Tùy chọn — chỉ dùng trên Dev/Staging)_ Dọn sạch toàn bộ 39 bảng nghiệp vụ, `_prisma_migrations`, 9 hàm PL/pgSQL, sequence và 18 kiểu ENUM trong schema `public` mà không ảnh hưởng đến các schema hệ thống của Supabase (`auth`, `storage`, `realtime`, `vault`, `extensions`).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `01_supabase_full_schema_and_seed.sql` | **Kịch bản chính (All-in-One, Idempotent)**: Tạo đầy đủ extensions (`pgcrypto`, `pg_trgm`), 18 ENUM, sequence `abac_policy_version_seq`, 39 bảng nghiệp vụ + `_prisma_migrations`, khóa ngoại vòng `fk_documents_current_version`, toàn bộ chỉ mục B-Tree/GIN/Partial Unique, 9 hàm PL/pgSQL gắn cứng `search_path = public, extensions`, 21 trigger bất biến/toàn vẹn (gồm cả chặn `TRUNCATE` kiểm toán), cưỡng chế **`FORCE ROW LEVEL SECURITY` + 80 chính sách tường minh** chặn PostgREST (`anon`, `authenticated`) & giới hạn quyền tối thiểu `service_role`, đồng bộ SHA-256 checksum 11 migration của Prisma, và nạp dữ liệu nền tảng (phòng ban, danh mục, 4 độ mật, 5 vai trò, 34 quyền SoD, 15 thuộc tính ABAC, chính sách cơ sở, cấu hình đóng dấu mặc định, 6 quy tắc SOC). |

---

## 2. Các bước chạy trên Supabase SQL Editor

1. Đăng nhập **Supabase Dashboard** -> chọn Project của bạn -> mở mục **SQL Editor** -> nhấn **New query**.
2. _(Nếu database đã từng chạy bảng cũ bị dở dang)_: Mở tệp `supabase/00_reset_clean.sql`, sao chép toàn bộ nội dung vào SQL Editor và nhấn **Run**.
3. Mở tệp `supabase/01_supabase_full_schema_and_seed.sql`, sao chép toàn bộ nội dung dán vào SQL Editor và nhấn **Run**.
4. Kiểm tra bảng kết quả trả về ở cuối lần chạy (**PHẦN 10 — VERIFICATION SUMMARY**):
   - `business_tables`: `39`
   - `rls_locked_tables`: `40` (39 bảng nghiệp vụ + `_prisma_migrations` bật `FORCE ROW LEVEL SECURITY`)
   - `rls_policies`: `80` (cặp chính sách `RESTRICTIVE` + `PERMISSIVE` trên toàn bộ 40 bảng)
   - `enum_types`: `18`
   - `triggers`: `21`
   - `system_roles`: `5`
   - `permissions`: `34`
   - `classifications`: `4`
   - `watermark_configs`: `3`
   - `detection_rules`: `6`
   - `synced_migrations`: `11`
5. Mở **Database -> Security Advisor** trên Supabase Dashboard để xác nhận **0 cảnh báo Critical** về RLS hoặc `function_search_path_mutable`.

---

## 3. Cấu hình Chuỗi Kết nối (`DATABASE_URL` & `DIRECT_URL`)

Trên Supabase Dashboard, vào **Project Settings -> Database -> Connect**:

- **Khuyến nghị cho cả `DATABASE_URL` và `DIRECT_URL` (Hỗ trợ mạng IPv4 & đầy đủ `pg_advisory_xact_lock` + `SERIALIZABLE` transaction)**: dùng **Session Pooler (cổng `5432`)**:

```env
DATABASE_URL=postgresql://postgres.<PROJECT_REF>:<SUPABASE_DB_PASSWORD>@aws-0-<REGION>.pooler.supabase.com:5432/postgres?schema=public&sslmode=require
DIRECT_URL=postgresql://postgres.<PROJECT_REF>:<SUPABASE_DB_PASSWORD>@aws-0-<REGION>.pooler.supabase.com:5432/postgres?schema=public&sslmode=require
DATABASE_POOL_MAX=10
DATABASE_SSL=true
DATABASE_SSL_REJECT_UNAUTHORIZED=true
DATABASE_CA_CERT=/etc/ssl/certs/prod-ca-2021.crt
```

> **Cảnh báo Bảo mật TLS (Chống CWE-295 Man-in-the-Middle)**: Tải chứng chỉ gốc **Supabase Root CA (`prod-ca-2021.crt`)** tại mục **Project Settings -> Database -> SSL Configuration** trên Supabase Dashboard và trỏ biến `DATABASE_CA_CERT` (hoặc `NODE_EXTRA_CA_CERTS`) tới đường dẫn tệp chứng chỉ này. **Tuyệt đối không tắt cờ kiểm định chứng chỉ `DATABASE_SSL_REJECT_UNAUTHORIZED` (luôn giữ `true`) hay dùng `sslmode=no-verify`** trên Staging/Production (`packages/database/src/client.ts` và `EnvSchema` sẽ chặn khởi chạy fail-fast khi `NODE_ENV=production`).

Sau khi cập nhật `.local/dev.env` (hoặc biến môi trường triển khai), bạn có thể kiểm tra đồng bộ Prisma bằng lệnh:

```powershell
pnpm --filter @sda/database exec prisma migrate status --config prisma.config.ts
```

Kết quả sẽ báo `Database schema is up to date!` nhờ bảng `_prisma_migrations` đã được đồng bộ sẵn 11 mã băm SHA-256.

---

## 4. Kích hoạt Tài khoản Quản trị / Demo trên Supabase

Theo quy tắc bảo mật không lưu mật khẩu tĩnh của dự án (`../rule.md` và `packages/database/prisma/seed.ts`), kho mã nguồn tuyệt đối không nhúng thông tin xác thực sẵn; 5 tài khoản khung (`admin.demo`, `security.demo`, `auditor.demo`, `owner.demo`, `reader.demo`) được tạo ở trạng thái `DISABLED` với dấu hiệu khóa `!AUTHENTICATION_NOT_CONFIGURED_DEMO_ACCOUNT!`.

Để đặt mật khẩu chuẩn **Argon2id** (độ dài tối thiểu **15 ký tự**, không chứa tên đăng nhập) và mở khóa tài khoản trên Supabase:

1. Chạy lệnh tạo mã băm Argon2id cục bộ tại thư mục `secure-document-access-system` (thay mật khẩu của riêng bạn vào biến môi trường tạm `MY_PASS`):

```powershell
$env:MY_PASS="<YOUR_STRONG_PASSWORD_MIN_15_CHARS>"; node --input-type=module -e "import argon2 from 'argon2'; const h = await argon2.hash(process.env.MY_PASS, { type: argon2.argon2id, memoryCost: 65536, timeCost: 3, parallelism: 1, hashLength: 32 }); console.log(h);" ; Remove-Item Env:\MY_PASS
```

2. Sao chép chuỗi `$argon2id$v=19$...` vừa in ra và chạy lệnh sau trong **Supabase SQL Editor**:

```sql
UPDATE public.users
SET
  password_hash = '<PASTE_ARGON2ID_HASH_HERE>',
  status = 'ACTIVE',
  disabled_at = NULL,
  failed_login_count = 0,
  locked_until = NULL
WHERE username IN ('owner.demo', 'reader.demo');
```

> **Lưu ý về MFA bắt buộc**: Ba vai trò nhạy cảm (`SYSTEM_ADMIN`, `SECURITY_OFFICER`, `AUDITOR`) được cấu hình bắt buộc MFA trong chính sách đăng nhập của Backend. Khi kích hoạt `admin.demo`, `security.demo` hoặc `auditor.demo`, cần đăng ký phương thức MFA qua API `/api/v1/auth/mfa/enroll` (TOTP) hoặc `/api/v1/auth/mfa/webauthn/register/options` (FIDO2).

---

## 5. (Tùy chọn) Dùng Supabase Storage S3 thay cho S3 Cục bộ

Hệ thống lưu trữ tài liệu mã hóa phong bì (`AES-256-GCM`) qua giao thức S3 tương thích (`apps/api/src/modules/documents/object-storage.service.ts` sử dụng `@aws-sdk/client-s3`). Bạn có thể tạo 3 Private Bucket trên **Supabase Storage** (`secure-documents`, `secure-quarantine`, `secure-derivatives`) và bật **S3 Connection** trong **Project Settings -> Storage** để kết nối trực tiếp mà không cần chạy container S3 cục bộ:

```env
STORAGE_ENDPOINT=<PROJECT_REF>.storage.supabase.co
STORAGE_PORT=443
STORAGE_USE_SSL=true
STORAGE_ACCESS_KEY=<SUPABASE_S3_ACCESS_KEY_ID>
STORAGE_SECRET_KEY=<SUPABASE_S3_SECRET_ACCESS_KEY>
STORAGE_BUCKET_DOCUMENTS=secure-documents
STORAGE_BUCKET_QUARANTINE=secure-quarantine
STORAGE_BUCKET_DERIVATIVES=secure-derivatives
```
