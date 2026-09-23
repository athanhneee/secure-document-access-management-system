# Quy Trình Sao Lưu & Phục Hồi Thảm Họa (Disaster Recovery & Backup/Restore Runbook)

Hệ thống Quản Lý Truy Cập Tài Liệu Mật Trong Tổ Chức (SDA v1.0.0).
Tài liệu này quy định chi tiết chính sách, chu kỳ sao lưu, phương thức mã hóa gói sao lưu, và quy trình diễn tập phục hồi thảm họa định kỳ.

---

## 1. Chỉ Tiêu Mục Tiêu Phục Hồi (SLA / Objectives)

- **Mục tiêu điểm phục hồi (RPO - Recovery Point Objective)**: **< 1 giờ** (Dữ liệu mất mát tối đa trong kịch bản thảm họa nặng không quá 1 giờ nhờ kết hợp WAL archiving).
- **Mục tiêu thời gian phục hồi (RTO - Recovery Time Objective)**: **< 30 phút** (Hệ thống sẵn sàng phục vụ trở lại trong vòng 30 phút kể từ khi khởi động quy trình thảm họa).
- **Mục tiêu tính toàn vẹn**: **100% dữ liệu kiểm toán (Audit Trail) phải bảo toàn chuỗi HMAC**, không được có vết đứt gãy sequence hoặc sai lệch hash sau khi phục hồi.

---

## 2. Kế Hoạch & Chu Kỳ Sao Lưu (Backup Schedule)

| Thành phần dữ liệu           | Phương thức sao lưu                            | Chu kỳ thực hiện                      | Thời gian lưu trữ (Retention) | Nơi lưu trữ an toàn                  |
| :--------------------------- | :--------------------------------------------- | :------------------------------------ | :---------------------------- | :----------------------------------- |
| **Cơ sở dữ liệu PostgreSQL** | `pg_dump` nén nhị phân (`-Fc`) + WAL Archiving | Mỗi 6 giờ (Snapshot) + Liên tục (WAL) | 90 ngày                       | Kho lạnh mã hóa độc lập (Air-gapped) |
| **Kho đối tượng MinIO**      | `mc mirror` đồng bộ bucket nhị phân            | Mỗi 12 giờ                            | 365 ngày (WORM enabled)       | Secondary S3 Storage                 |
| **Trạng thái Redis**         | Snapshot `dump.rdb` & `appendonly.aof`         | Hàng ngày lúc 01:00 UTC               | 14 ngày                       | Backup Volume nội bộ                 |
| **Khóa mã hóa KMS / DEK**    | Bản xuất khóa bao bì (Envelope KEK)            | Khi có sự kiện xoay vòng khóa         | Vĩnh viễn (Offline Vault)     | Két sắt an toàn vật lý               |

---

## 3. Quy Trình Thực Hiện Sao Lưu Tự Động (Backup Execution)

### 3.1 Sao lưu cơ sở dữ liệu PostgreSQL

```bash
#!/usr/bin/env bash
set -euo pipefail

BACKUP_DIR="/var/backups/sda"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="${BACKUP_DIR}/sda_db_${TIMESTAMP}.dump"

mkdir -p "${BACKUP_DIR}"

# Thực thi pg_dump với định dạng custom nén
docker exec sda-postgres pg_dump -U sda_app -d sda_production -Fc > "${BACKUP_FILE}"

# Tạo chữ ký kiểm tra tính toàn vẹn SHA-256
sha256sum "${BACKUP_FILE}" > "${BACKUP_FILE}.sha256"

# Mã hóa gói sao lưu bằng OpenSSL trước khi đẩy sang kho thứ cấp
openssl enc -aes-256-gcm -pbkdf2 -in "${BACKUP_FILE}" -out "${BACKUP_FILE}.enc" -pass file:/etc/sda/backup.key
rm -f "${BACKUP_FILE}"

echo "Database backup completed: ${BACKUP_FILE}.enc"
```

### 3.2 Sao lưu kho đối tượng MinIO

```bash
# Đồng bộ bucket tài liệu mật sang cụm backup thứ cấp
mc mirror --overwrite sda-minio/sda-documents-encrypted secondary-minio/sda-documents-backup
mc mirror --overwrite sda-minio/sda-quarantine-isolated secondary-minio/sda-quarantine-backup
```

---

## 4. Quy Trình Phục Hồi Thảm Họa (Disaster Recovery Workflow)

Khi gặp thảm họa phá hủy hệ thống dữ liệu, quản trị viên thực hiện theo 6 bước sau:

### Bước 1: Chuẩn bị máy chủ hoặc vùng chứa trống

Khởi động hạ tầng cơ sở dữ liệu sạch:

```bash
docker compose -f docker-compose.prod.yaml up -d postgres redis minio
```

### Bước 2: Giải mã và xác thực tính toàn vẹn tệp sao lưu

```bash
# Giải mã gói sao lưu
openssl enc -d -aes-256-gcm -pbkdf2 -in sda_db_20260923_120000.dump.enc -out sda_db_restore.dump -pass file:/etc/sda/backup.key

# Xác minh mã băm SHA-256
sha256sum -c sda_db_20260923_120000.dump.sha256
```

### Bước 3: Khôi phục cơ sở dữ liệu

```bash
# Nạp dữ liệu vào cơ sở dữ liệu trống
docker exec -i sda-postgres pg_restore -U sda_app -d sda_production --clean --if-exists sda_db_restore.dump
rm -f sda_db_restore.dump
```

### Bước 4: Khôi phục kho đối tượng MinIO

```bash
mc mirror --overwrite secondary-minio/sda-documents-backup sda-minio/sda-documents-encrypted
```

### Bước 5: Kiểm tra tính toàn vẹn chuỗi Audit (Audit Chain Integrity)

Chạy script kiểm tra chữ ký số chuỗi HMAC để phát hiện bất kỳ sự can thiệp hoặc thất thoát nào:

```bash
node scripts/smoke-test.mjs
```

### Bước 6: Khởi động lại dịch vụ ứng dụng

```bash
docker compose -f docker-compose.prod.yaml up -d api worker web
```

---

## 5. Kịch Bản Diễn Tập Tự Động Hóa (Drill Automation)

Hệ thống cung cấp script diễn tập độc lập [`scripts/backup-restore.mjs`](file:///d:/PTVTKHT/secure-document-access-system/scripts/backup-restore.mjs). Script này thực hiện:

1. Sinh dữ liệu mẫu có chuỗi băm HMAC.
2. Xuất gói dữ liệu và băm SHA-256.
3. Giả lập thảm họa (làm trống database).
4. Phục hồi và kiểm tra số dòng 100% khớp.
5. Kiểm tra toán học tính liên tục của chuỗi audit hash.
6. Xác nhận khôi phục bit-for-bit tài liệu mã hóa.

Chạy diễn tập:

```bash
node scripts/backup-restore.mjs
```

Kết quả mong đợi: `SUCCESS: DISASTER RECOVERY & RESTORE DRILL COMPLETED WITH ZERO DATA LOSS.`
