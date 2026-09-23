# Hướng Dẫn Triển Khai Vận Hành (Production Deployment Guide)

Hệ thống Quản Lý Truy Cập Tài Liệu Mật Trong Tổ Chức (Secure Document Access System - SDA v1.0.0).
Tài liệu này chuẩn hóa quy trình triển khai ứng dụng trên môi trường máy chủ sản xuất theo các tiêu chuẩn an ninh nghiêm ngặt: Non-Root Containers, Read-Only Filesystems, Dropped Capabilities, Least Privilege, Zero Hardcoded Secrets.

---

## 1. Yêu Cầu Hạ Tầng (Infrastructure Prerequisites)

| Hạng mục           | Yêu cầu tối thiểu (Minimum)                 | Yêu cầu khuyến nghị (Production)           |
| :----------------- | :------------------------------------------ | :----------------------------------------- |
| **Hệ điều hành**   | Ubuntu LTS 22.04 / 24.04, Debian 12, RHEL 9 | Ubuntu Server 24.04 LTS (Kernel 6.8+)      |
| **CPU**            | 4 Cores (x86_64 hoặc arm64)                 | 8 Cores (AMD EPYC hoặc Intel Xeon)         |
| **Bộ nhớ RAM**     | 8 GB ECC RAM                                | 16 GB - 32 GB ECC RAM                      |
| **Ổ cứng lưu trữ** | 50 GB SSD / NVMe                            | 200+ GB NVMe RAID-10 (Lưu trữ mã hóa LUKS) |
| **Docker Engine**  | Docker Engine 26.0+                         | Docker Engine 27+                          |
| **Docker Compose** | Compose Plugin v2.26+                       | Compose Plugin v2.29+                      |
| **Tường lửa mạng** | UFW hoặc iptables chặn mọi port trừ 443     | DMZ riêng biệt, reverse proxy có WAF       |

---

## 2. Quản Lý Bí Mật & Biến Môi Trường (Secret Management)

Hệ thống vận hành theo nguyên tắc **Zero-Trust**: Mọi bí mật bắt buộc phải được cung cấp qua biến môi trường độc lập tại thời điểm khởi động máy chủ hoặc tích hợp từ HashiCorp Vault / AWS Secrets Manager.

### Danh mục biến môi trường bắt buộc:

| Tên biến                 | Kiểu giá trị                  | Mô tả mục đích                                     |
| :----------------------- | :---------------------------- | :------------------------------------------------- |
| `POSTGRES_DB`            | Chuỗi ký tự                   | Tên database sản xuất (mặc định: `sda_production`) |
| `POSTGRES_USER`          | Chuỗi ký tự                   | Tài khoản người dùng cơ sở dữ liệu (`sda_app`)     |
| `POSTGRES_PASSWORD`      | Mật khẩu mạnh (32+ ký tự)     | Mật khẩu kết nối PostgreSQL                        |
| `REDIS_PASSWORD`         | Chuỗi ngẫu nhiên (32+ ký tự)  | Mật khẩu xác thực Redis AUTH                       |
| `STORAGE_ACCESS_KEY`     | Chuỗi ngẫu nhiên (20+ ký tự)  | Khóa truy cập MinIO / S3                           |
| `STORAGE_SECRET_KEY`     | Chuỗi ngẫu nhiên (40+ ký tự)  | Khóa bí mật MinIO / S3                             |
| `JWT_PRIVATE_KEY`        | Ed25519 PKCS8 PEM hoặc 64-hex | Khóa ký số Token truy cập người dùng               |
| `JWT_PUBLIC_KEY`         | Ed25519 SPKI PEM hoặc 64-hex  | Khóa công khai đối soát Token                      |
| `COOKIE_SECRET`          | 32-byte hex hoặc base64       | Khóa ký bảo vệ cookie chống giả mạo                |
| `KMS_MASTER_KEY`         | 64 ký tự Hex (AES-256 KEK)    | Khóa mã hóa khóa bao bì (Master Key)               |
| `AUDIT_HMAC_KEY`         | 64 ký tự Hex (SHA-256 Key)    | Khóa ký chuỗi nhật ký kiểm toán chống giả mạo      |
| `GRAFANA_ADMIN_PASSWORD` | Mật khẩu quản trị             | Mật khẩu tài khoản admin Grafana                   |

> [!WARNING]
> Tệp `.env.production` phải được phân quyền `chmod 600 .env.production` và sở hữu bởi người dùng triển khai chuyên biệt. Tuyệt đối không commit tệp này vào Git.

---

## 3. Quy Trình Triển Khai Từng Bước (Rollout Workflow)

### Bước 1: Sao chép mã nguồn và thiết lập môi trường

```bash
git clone https://github.com/organization/secure-document-access-system.git /opt/sda
cd /opt/sda
git checkout v1.0.0
```

### Bước 2: Chuẩn bị tệp cấu hình triển khai

```bash
cp docker-compose.production.example.yaml docker-compose.prod.yaml
# Khởi tạo tệp bí mật sản xuất
node scripts/generate-dev-secrets.mjs --prod > .env.production
chmod 600 .env.production
```

### Bước 3: Khởi chạy hạ tầng phụ thuộc và kiểm tra sức khỏe

```bash
docker compose --env-file .env.production -f docker-compose.prod.yaml up -d postgres redis minio clamav
docker compose -f docker-compose.prod.yaml ps
```

### Bước 4: Thực thi di chuyển lược đồ database (Migrations)

```bash
docker compose --env-file .env.production -f docker-compose.prod.yaml run --rm api pnpm db:migrate
```

### Bước 5: Khởi động toàn bộ dịch vụ ứng dụng

```bash
docker compose --env-file .env.production -f docker-compose.prod.yaml up -d api worker web prometheus grafana
```

---

## 4. Kiểm Thử Khói Hậu Triển Khai (Post-Deploy Smoke Test)

Ngay sau khi tất cả container chuyển sang trạng thái `healthy`, thực thi script kiểm thử khói tự động:

```bash
node scripts/smoke-test.mjs
```

Kết quả thành công sẽ xác nhận:

- Liveness & Readiness probe trả về HTTP 200 OK.
- Kênh cạo metrics `/api/v1/health/metrics` hoạt động.
- Xác thực JWT và xoay vòng token hợp lệ.
- Động cơ ABAC PEP/PDP đánh giá chính xác.
- Thu hồi quyền truy cập chấm dứt phiên làm việc tức thì.

---

## 5. Cấu Hình Reverse Proxy & Bảo Vệ TLS (Nginx Example)

```nginx
server {
    listen 443 ssl http2;
    server_name sda.organization.gov.vn;

    ssl_certificate /etc/letsencrypt/live/sda.organization.gov.vn/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/sda.organization.gov.vn/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers on;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'none'; frame-ancestors 'none'; sandbox" always;

    # Reverse proxy Next.js Frontend
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Reverse proxy Fastify API
    location /api/ {
        proxy_pass http://127.0.0.1:3001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        client_max_body_size 50M;
    }
}
```

---

## 6. Chiến Lược Cập Nhật Không Gián Đoạn (Zero-Downtime Rolling Update)

1. Kéo image mới: `docker compose -f docker-compose.prod.yaml pull`
2. Kiểm tra tính tương thích ngược của database migration: `node scripts/validate-database.mjs`
3. Chạy migration: `docker compose -f docker-compose.prod.yaml run --rm api pnpm db:migrate`
4. Khởi động lại dịch vụ API với cơ chế rolling:
   ```bash
   docker compose -f docker-compose.prod.yaml up -d --no-deps --build api
   docker compose -f docker-compose.prod.yaml up -d --no-deps --build worker
   docker compose -f docker-compose.prod.yaml up -d --no-deps --build web
   ```
5. Chạy lại smoke test: `node scripts/smoke-test.mjs`
