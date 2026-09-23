# Mô Hình Đe Dọa (Threat Model) & Đánh Giá STRIDE

Tài liệu mô hình đe dọa cho **Hệ thống Quản lý Truy cập Tài liệu Mật (Secure Document Access System)** dựa trên khung phương pháp **STRIDE** (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) và tiêu chuẩn **OWASP ASVS v4.0.3 (Application Security Verification Standard)** cấp độ L3 (High Assurance).

---

## 1. Tác Nhân Đe Dọa (Threat Actors & Assets)

### 1.1 Tác Nhân Đe Dọa (Threat Actors)
- **External Attacker**: Kẻ tấn công từ Internet không có tài khoản, tìm cách thâm nhập qua lỗ hổng API, khai thác injection, bypass MFA hoặc tấn công từ chối dịch vụ (DoS/DDoS).
- **Compromised Reader**: Người dùng nội bộ hợp lệ nhưng có mức clearance thấp, cố gắng đọc trộm tài liệu mật của phòng ban khác (IDOR, privilege escalation), hoặc làm rò rỉ tài liệu ra ngoài.
- **Rogue Document Owner**: Chủ tài liệu cố ý upload mã độc, chèn macro/payload khai thác hoặc thay đổi phân loại trái phép.
- **Malicious Administrator**: Quản trị viên kỹ thuật lạm dụng quyền cấu hình để đọc nội dung tài liệu mật hoặc xóa dấu vết kiểm toán (vi phạm SoD).
- **Insider Infrastructure Operator / Compromised Host**: Người có quyền root máy chủ hoặc DB cố tình can thiệp trực tiếp vào database, file storage hoặc log.

### 1.2 Tài Sản Cần Bảo Vệ (Critical Assets)
1. **Nội dung tài liệu mật (Plaintext Content)**: Các tài liệu PDF/Office chứa thông tin tối mật, tuyệt mật của tổ chức.
2. **Khóa mã hóa (Cryptographic Keys)**: Master Key (KEK), Data Encryption Keys (DEK), Ed25519 Signing Keys, HMAC Secret Keys.
3. **Nhật ký kiểm toán (Audit Trail)**: Dữ liệu ghi nhận mọi hành động nhạy cảm, phục vụ pháp lý và điều tra số.
4. **Dữ liệu phân quyền & định danh (Auth & RBAC/ABAC State)**: Mật khẩu hash, TOTP secrets, vai trò, clearance và chính sách phân quyền.

---

## 2. Phân Tích Chi Tiết STRIDE Cho 8 Module Trọng Yếu

### 2.1 Module 1: Authentication & Session Management

| STRIDE | Mối Đe Dọa (Threat) | Vector Tấn Công | Biện Pháp Giảm Thiểu (Mitigations) | ASVS Ref |
| :--- | :--- | :--- | :--- | :--- |
| **Spoofing** | Giả mạo Access Token hoặc mạo danh phiên đăng nhập | Tráo đổi header JWT, giả chữ ký Ed25519, replay token cũ | Chữ ký phi đối xứng Ed25519 bắt buộc kiểm tra `kid`, `iss`, `aud`, `exp`; Access token TTL ngắn (300s); Token không lưu trong Web Storage. | V3.2, V3.5 |
| **Tampering** | Sửa đổi payload claims trong Token hoặc giả mạo Cookie | Sửa `userId`, `role`, `mfa` trong JWT payload | Fastify Cookie ký bảo mật (`signed`), JWT EdDSA được verify bằng Public Key trước khi giải nén context; Cookie `SameSite=Strict; HttpOnly; Secure`. | V3.4, V3.7 |
| **Repudiation** | Người dùng chối bỏ việc đăng nhập hoặc đổi mật khẩu | Tuyên bố tài khoản bị chiếm đoạt không rõ nguồn gốc | Ghi nhận Audit Log sự kiện AUTH (SUCCESS/FAILED/MFA_TRIGGERED) kèm IP, User-Agent, Session ID; Bắt buộc TOTP MFA cho các vai trò nhạy cảm. | V8.1, V8.2 |
| **Information Disclosure** | Lộ mật khẩu người dùng hoặc secret TOTP trong log/database | Xem trộm DB, memory dump hoặc server access log | Mật khẩu hash bằng Argon2id ($m=65536, t=3, p=1$); TOTP Secret mã hóa AES-256-GCM bằng KEK trước khi lưu DB; Secret redaction filter loại bỏ token/passwords trong log. | V2.1, V2.4 |
| **Denial of Service** | Argon2id Slowloris / Brute Force làm tê liệt CPU backend | Gửi hàng ngàn request login đồng thời để ép CPU tính Argon2id | IP & Account Rate Limiting phân cấp; Dummy Argon2 work cân bằng thời gian (chống timing attack) nhưng có giới hạn concurrency; Connection timeout 15s. | V2.2, V11.1 |
| **Elevation of Privilege** | Vượt qua bước MFA TOTP để chiếm phiên quyền cao | Truy cập thẳng dashboard admin sau khi nhập đúng password | Auth Guard kiểm tra claim `mfa: true`; các vai trò `SYSTEM_ADMIN`, `SECURITY_OFFICER`, `AUDITOR` bị chặn mọi API nghiệp vụ cho đến khi hoàn tất xác thực MFA. | V2.8, V4.1 |

---

### 2.2 Module 2: Document Upload & Ingestion Pipeline

| STRIDE | Mối Đe Dọa (Threat) | Vector Tấn Công | Biện Pháp Giảm Thiểu (Mitigations) | ASVS Ref |
| :--- | :--- | :--- | :--- | :--- |
| **Spoofing** | Giả mạo định dạng file (MIME Spoofing) | Đổi đuôi `malware.exe` thành `invoice.pdf` | Kiểm tra đa tầng: Khớp Extension Allowlist (PDF, DOCX, XLSX, PPTX), Content-Type Header và Magic Bytes thực tế (`%PDF-`, `PK\x03\x04`). | V12.1, V12.4 |
| **Tampering** | Chèn mã độc ClamAV / EICAR vào tài liệu hợp lệ | Nhúng virus macro hoặc shellcode vào file Office/PDF | Socket stream quét ClamAV tự động; Phát hiện EICAR/malware lập tức cô lập vào Quarantine Bucket, giữ tài liệu ở DRAFT và KHÔNG BAO GIỜ active. | V12.2 |
| **Repudiation** | Chủ tài liệu chối bỏ việc tải lên file độc hại | Xóa file hoặc log upload | Tạo SHA-256 digest của file ngay khi tiếp nhận; Ghi nhận 4 giai đoạn upload vào chuỗi HMAC audit log bất biến. | V8.2, V14.2 |
| **Information Disclosure** | Rò rỉ tài liệu đang xử lý hoặc lộ đường dẫn lưu trữ | Path Traversal (`../../etc/passwd`), UUID prediction | Chuẩn hóa tên file, loại bỏ path separators và null bytes; Storage key sử dụng UUID ngẫu nhiên độc lập với tên file gốc; Xóa temp file an toàn sau xử lý. | V12.3, V13.2 |
| **Denial of Service** | Zip Bomb / Decompression Bomb làm cạn kiệt RAM và ổ đĩa | Tải file zip nén 1MB bung ra 50GB dữ liệu | `ZipBombGuardService` kiểm tra kích thước tối đa sau giải nén, tỷ lệ nén (max ratio 100:1), số lượng entry tối đa (10,000) và độ sâu thư mục (max 10 level). | V12.5 |
| **Elevation of Privilege** | Upload polyglot file hoặc file thực thi để chạy mã từ xa | Tải file thực thi hoặc script độc hại | Không bao giờ lưu file trực tiếp trong web root; File lưu trên Object Storage MinIO dưới dạng mã hóa AES-256-GCM. | V12.6, V14.1 |

---

### 2.3 Module 3: Object Storage & Key Management System (KMS)

| STRIDE | Mối Đe Dọa (Threat) | Vector Tấn Công | Biện Pháp Giảm Thiểu (Mitigations) | ASVS Ref |
| :--- | :--- | :--- | :--- | :--- |
| **Spoofing** | Truy cập trực tiếp Object Storage MinIO bypass API | Quét port 9000 MinIO bằng credential mặc định | Mạng MinIO đặt trong network nội bộ cô lập (`sda-local-internal`); Bucket private, vô hiệu hóa anonymous access; API sử dụng IAM credentials ngẫu nhiên. | V14.2 |
| **Tampering** | Sửa đổi trái phép ciphertext lưu trữ trên đĩa | Tấn công bit-flipping trên ciphertext đã lưu | Envelope Encryption AES-256-GCM với 128-bit authentication tag; Mọi thay đổi dù chỉ 1 bit đều làm quá trình giải mã thất bại và kích hoạt cảnh báo an ninh. | V6.2, V6.3 |
| **Repudiation** | Thay thế hoặc xóa object tài liệu mà không để lại vết | Gọi S3 DeleteObject trực tiếp | Bật tính năng Object Versioning trên MinIO; Mọi thao tác qua API đều ghi nhận audit log kèm hash ciphertext. | V8.3 |
| **Information Disclosure** | Rò rỉ Data Encryption Key (DEK) hoặc Master Key (KEK) | Đọc trộm cơ sở dữ liệu để lấy khóa giải mã | DEK được wrap qua Local KMS/KEK bằng AES-256-GCM; Database CHỈ lưu trữ wrapped DEK và key reference; KEK lưu ở environment riêng biệt, không lưu trong DB. | V6.4, V6.5 |
| **Denial of Service** | Tải xuống hàng loạt gây cạn kiệt băng thông hoặc I/O | Vòng lặp tải liên tục file mã hóa | Phân phối qua single-use download ticket (TTL 60s, dùng một lần); Giới hạn tốc độ tải và kiểm soát rate limit. | V11.2 |
| **Elevation of Privilege** | Dùng KEK của hệ thống để wrap/unwrap dữ liệu trái phép | Gọi hàm KMS với key reference không thuộc hệ sinh thái | KMS xác thực chặt chẽ tiền tố `keyRef` (`local-kms:v1`), kiểm tra tính hợp lệ của auth tag trước khi trả về plaintext DEK. | V6.1 |

---

### 2.4 Module 4: ABAC Policy Engine

| STRIDE | Mối Đe Dọa (Threat) | Vector Tấn Công | Biện Pháp Giảm Thiểu (Mitigations) | ASVS Ref |
| :--- | :--- | :--- | :--- | :--- |
| **Spoofing** | Giả mạo thuộc tính môi trường hoặc người dùng (IP, Dept) | Gửi header `X-Forwarded-For` giả hoặc sửa Department ID | Mọi thuộc tính Subject và Resource được dựng lại từ database tin cậy phía server; IP được trích xuất an toàn từ socket kết nối; Không tin tưởng client input. | V4.1, V4.2 |
| **Tampering** | Chỉnh sửa AST chính sách ABAC để tự cấp quyền | Chèn điều kiện luôn đúng (OR true = true) vào policy | Chính sách ABAC được biên dịch (compiled) thành AST bất biến; Kiểm tra tính hợp lệ qua `PolicyValidator` trước khi kích hoạt; Lưu trữ version monotonic. | V4.3 |
| **Repudiation** | Người dùng chối bỏ việc truy cập tài liệu qua chính sách | Đổ lỗi cho lỗi phân quyền hệ thống | Lưu trữ quyết định PDP (`PERMIT` / `DENY`), danh sách obligations thực thi và policy ID trong nhật ký kiểm toán phiên làm việc. | V8.2 |
| **Information Disclosure** | Rò rỉ thông tin tài liệu khi simulate chính sách | Kiểm tra phân quyền để suy đoán sự tồn tại của tài liệu mật | Chức năng Simulation chỉ dành riêng cho System Admin / Security Officer; Kết quả simulate đã được lọc dữ liệu nhạy cảm; Không tạo quyền thật. | V4.1 |
| **Denial of Service** | Regular Expression Denial of Service (ReDoS) trong rule | Gửi input chuỗi phức tạp vào operator MATCHES | Giới hạn độ dài chuỗi regex; Chỉ cho phép các operator trong allowlist (`EQUALS`, `IN`, `GREATER_THAN`, `LESS_THAN`); Không hỗ trợ regex tùy ý không giới hạn. | V5.2 |
| **Elevation of Privilege** | Mặc định PERMIT khi chính sách không xác định hoặc lỗi | Gây lỗi engine để bypass phân quyền (Fail-Open) | Nguyên tắc cốt lõi **Fail-Closed & Default-Deny**: Mọi lỗi hoặc thiếu policy đều trả về `DENY`; Thuật toán kết hợp mặc định `DENY_OVERRIDES`. | V4.1 |

---

### 2.5 Module 5: Watermark Engine & Forensic Traceability

| STRIDE | Mối Đe Dọa (Threat) | Vector Tấn Công | Biện Pháp Giảm Thiểu (Mitigations) | ASVS Ref |
| :--- | :--- | :--- | :--- | :--- |
| **Spoofing** | Giả mạo Watermark Token để đổ tội cho người khác | Tự sinh mã token `WM-...` chèn vào ảnh chụp màn hình | Token được liên kết mật mã với phiên làm việc, User ID, Version ID và hash bí mật trong DB; Tra cứu đối chiếu ngược yêu cầu khớp toàn bộ metadata. | V3.6, V10.2 |
| **Tampering** | Xóa lớp Watermark overlay hoặc bóc tách chữ ký PDF | Dùng công cụ PDF editor để xóa text watermark | Watermark được vẽ trực tiếp lên canvas nội dung PDF (rasterize/flatten); Mã QR và text chéo góc 45 độ trên mọi trang; Metadata chứa token ẩn. | V10.3 |
| **Repudiation** | Người làm rò rỉ tài liệu chối bỏ hành vi | Khẳng định bản chụp tài liệu không phải của mình | Module Watermark Lookup (Forensics) giải mã token, truy ngược chính xác thời điểm tải, User tải, IP và thiết bị thực hiện. | V8.2, V10.2 |
| **Information Disclosure** | Lộ bản gốc chưa đóng dấu thủy vân khi engine bị lỗi | Gây crash engine watermark để nhận file sạch | **Fail-Closed Watermarking**: Nếu engine gặp lỗi hoặc buffer bị corrupt, hệ thống lập tức ném lỗi `ForbiddenException` và HỦY toàn bộ luồng phân phối file. | V10.1, V13.1 |
| **Denial of Service** | Gửi file PDF 10,000 trang để ép server render watermark | Làm tràn bộ nhớ Node.js process khi xử lý PDF lớn | Giới hạn số trang xử lý tối đa; Sử dụng streaming và giải phóng bộ nhớ `pdf-lib` sau khi hoàn thành từng phần; Timeout xử lý 10,000ms. | V11.1 |
| **Elevation of Privilege** | Thay đổi cấu hình watermark để tắt đóng dấu cho role mình | Sửa watermark config của mức phân loại mật | Chỉ người dùng có quyền quản trị an ninh phù hợp mới được sửa config; Mức phân loại yêu cầu watermark không thể bị override bởi người đọc. | V4.1 |

---

### 2.6 Module 6: Audit Trail & Tamper-Evident Hash Chaining

| STRIDE | Mối Đe Dọa (Threat) | Vector Tấn Công | Biện Pháp Giảm Thiểu (Mitigations) | ASVS Ref |
| :--- | :--- | :--- | :--- | :--- |
| **Spoofing** | Chèn audit log giả mạo vào cơ sở dữ liệu | Inject bản ghi log với sequence ngẫu nhiên | Mỗi bản ghi kiểm toán chứa HMAC-SHA256 tính từ bản ghi trước đó (`prev_hash + canonical_event`); Không thể chèn bản ghi mà không phá vỡ chuỗi hash. | V8.3 |
| **Tampering** | Sửa đổi nội dung log cũ hoặc xóa bớt bản ghi vi phạm | Chạy câu lệnh UPDATE/DELETE trong SQL | Trigger PostgreSQL `trg_audit_no_update` chặn đứng 100% lệnh UPDATE/DELETE; Service định kỳ kiểm tra tính toàn vẹn (Audit Verifier) phát hiện sửa đổi. | V8.3 |
| **Repudiation** | Quản trị viên tắt ghi log để thực hiện hành vi xấu | Bỏ qua middleware audit trong code | Mọi hành động nhạy cảm đều gắn liền trong database transaction nghiệp vụ; Nếu ghi audit thất bại, toàn bộ transaction bị ROLLBACK. | V8.1 |
| **Information Disclosure** | Ghi thông tin nhạy cảm vào audit log | Lộ mật khẩu, access token, DEK hoặc nội dung file | Bộ lọc `AuditRedactionService` loại bỏ trường nhạy cảm; Từ khóa tìm kiếm được SHA-256 hash trước khi ghi; Không log file content. | V8.2, V13.3 |
| **Denial of Service** | Log Flooding làm đầy dung lượng ổ cứng chứa DB | Gửi hàng triệu request lỗi để làm nghẽn audit table | Audit log được phân vùng (partitioned) theo tháng; Đặt quota dung lượng; Alert an ninh khi tốc độ ghi log tăng đột biến. | V11.2 |
| **Elevation of Privilege** | Người dùng thông thường đọc trộm audit log của toàn hệ thống | Truy cập endpoint audit tra cứu vết điều tra | Phân quyền nghiêm ngặt: Owner chỉ xem log tài liệu mình sở hữu; Security Officer tra cứu điều tra; Auditor đọc và xuất báo cáo (Read-only). | V4.1 |

---

### 2.7 Module 7: Export & Asynchronous Reporting Jobs

| STRIDE | Mối Đe Dọa (Threat) | Vector Tấn Công | Biện Pháp Giảm Thiểu (Mitigations) | ASVS Ref |
| :--- | :--- | :--- | :--- | :--- |
| **Spoofing** | Đoán ID job xuất báo cáo của người khác để tải trộm | Duyệt tuần tự Job ID (`/export/jobs/1, 2, 3`) | Job ID sử dụng UUIDv4; API kiểm tra quyền sở hữu job: chỉ người tạo job hoặc Security Officer mới có quyền tải kết quả. | V4.1, V4.2 |
| **Tampering** | CSV Formula Injection (Excel Macro / DDE payload) | Nhập tên người dùng hoặc tiêu đề chứa `=CMD|' /C ...'` | Bộ lọc `CSV Formula Sanitizer` tự động escape các ký tự nguy hiểm (`=`, `+`, `-`, `@`, `\t`, `\r`) bằng dấu nháy đơn `'` trước khi xuất file. | V5.3 |
| **Repudiation** | Auditor xuất toàn bộ audit log ra ngoài mà không ai biết | Xuất dữ liệu quy mô lớn trong im lặng | Hành động tạo Export Job và tải file export đều sinh sự kiện kiểm toán đặc biệt `AUDIT_EXPORT_REQUESTED` và `AUDIT_EXPORT_DOWNLOADED`. | V8.2 |
| **Information Disclosure** | File export lưu trữ vô thời hạn bị rò rỉ trên storage | File CSV kết xuất nằm vĩnh viễn trên server | Cơ chế tự động dọn dẹp (TTL 24 giờ); Sau khi hết hạn, file vật lý bị xóa và job chuyển trạng thái `EXPIRED`. | V13.2 |
| **Denial of Service** | Tạo hàng loạt job export lớn làm cạn kiệt worker pool | Gửi liên tục yêu cầu xuất log khoảng thời gian 10 năm | Giới hạn số lượng bản ghi xuất tối đa (50,000 dòng); Giới hạn số job active đồng thời cho mỗi người dùng (tối đa 2 job). | V11.1 |
| **Elevation of Privilege** | Auditor sửa đổi kết luận sự cố trong báo cáo xuất | Thêm bớt dữ liệu điều tra của Security Officer | Đảm bảo nguyên tắc Phân tách nhiệm vụ (Separation of Duties - SoD): Auditor hoàn toàn ở chế độ Read-only, không thể chỉnh sửa sự cố hay hành động khắc phục. | V4.1 |

---

### 2.8 Module 8: Administration & Scoped RBAC

| STRIDE | Mối Đe Dọa (Threat) | Vector Tấn Công | Biện Pháp Giảm Thiểu (Mitigations) | ASVS Ref |
| :--- | :--- | :--- | :--- | :--- |
| **Spoofing** | Quản trị viên giả mạo danh tính để gán quyền cho chính mình | Tự cấp thêm vai trò Security Officer hoặc Auditor | Quy tắc loại trừ lẫn nhau (Mutual Exclusion): `SYSTEM_ADMIN`, `SECURITY_OFFICER`, `AUDITOR` không thể đồng thời được gán cho một tài khoản. | V4.1 |
| **Tampering** | Sửa đổi cây phòng ban để tạo vòng lặp vô tận | Gán cha của phòng ban A thành phòng ban con của chính A | Kiểm tra chống chu trình (Acyclic Tree Validation); Sử dụng transaction và optimistic locking (`version`) khi cập nhật cấu trúc tổ chức. | V5.1 |
| **Repudiation** | Gán hoặc thu hồi vai trò của nhân sự mà không lưu vết | Xóa quyền của người khác trong âm thầm | Mọi thao tác RBAC Mutation đều bắt buộc lưu audit log trước và sau (`before/after`) trong cùng database transaction. | V8.2 |
| **Information Disclosure** | Liệt kê tài khoản người dùng ngoài phạm vi quản lý (IDOR) | Truy cập `/admin/users/:id` của phòng ban khác | Phân quyền RBAC có phạm vi (Scoped RBAC): Quản trị viên chi nhánh chỉ xem được người dùng thuộc phòng ban của mình và cây con. | V4.2 |
| **Denial of Service** | Deactivate phòng ban gốc khiến toàn bộ hệ thống tê liệt | Vô hiệu hóa root department | Chặn vô hiệu hóa phòng ban nếu vẫn còn phòng ban con, người dùng hoặc role assignment đang hoạt động (`RBAC-BR05`). | V11.1 |
| **Elevation of Privilege** | Admin kỹ thuật lợi dụng quyền DB/App để đọc tài liệu mật | Dùng quyền Admin mở API `/documents/:id/download` | Nguyên tắc **Quyền Tối Thiểu (Least Privilege)**: System Admin KHÔNG có quyền xem nội dung tài liệu mật nếu không có grant nghiệp vụ độc lập được duyệt. | V4.1 |

---

## 3. Ma Trận Đánh Giá Nguy Cơ & Mức Độ Ưu Tiên Giảm Thiểu

```
Mức độ Nghiêm trọng (Impact)
  ^
Cao |   [Zip Bomb / DoS]        [SSRF in Office]        [Auth Bypass / Privilege Escalation]
    |
Trung|  [Rate Limit / Flooding]  [CSV Injection]         [IDOR Traversal]
bình|
Thấp|   [Timing Side-channel]   [Banner Disclosure]     [Information Leakage in Error]
    +------------------------------------------------------------------------>
                   Thấp                  Trung bình                 Cao
                                     Khả năng xảy ra (Likelihood)
```

Mọi nguy cơ nằm trong vùng Đỏ (Critical / High) đều đã có các chốt kiểm soát tự động và test suite hồi quy đi kèm.
