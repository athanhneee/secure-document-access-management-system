# Ma Trận Truy Vết Kiểm Thử (Traceability Matrix)

Hệ thống quản lý truy cập tài liệu mật trong tổ chức (Secure Document Access System).
Tài liệu này đối chiếu toàn bộ các Yêu cầu chức năng (**FR01–FR20**), Quy tắc nghiệp vụ (**BR01–BR20 / D-BR01–D-BR20**, **AUTH-BR**, **RBAC-BR**) và Yêu cầu phi chức năng (**NFR-SEC**, **NFR-REL**, **NFR-PERF**, **NFR-AUDIT**) tới các automated test suite đang thực thi trong mã nguồn.

---

## 1. Yêu Cầu Chức Năng (Functional Requirements FR01–FR20)

| Mã FR | Tên và Nội Dung Yêu Cầu | Use Case / Prompt | Test Suite / File Kiểm Thử | Trạng Thái |
| :--- | :--- | :--- | :--- | :--- |
| **FR01** | Xác thực đa yếu tố (TOTP) và quản lý phiên bảo mật | UC01, P05 | `apps/api/test/auth-security.test.mjs`<br>`apps/api/test/integration/auth-repository.integration.test.mjs` | PASS |
| **FR02** | Xoay vòng và phát hiện tái sử dụng Refresh Token | UC02, P05 | `apps/api/test/auth-security.test.mjs`<br>`apps/api/test/concurrency.test.mjs` | PASS |
| **FR03** | Quản trị người dùng, phòng ban đa cấp và phân quyền RBAC | UC03, UC04, P06 | `apps/api/test/rbac-security.test.mjs`<br>`apps/api/test/integration/rbac-administration.integration.test.mjs` | PASS |
| **FR04** | Động cơ thuộc tính và chính sách ABAC tất định | UC05, UC06, P07 | `apps/api/test/abac-engine.test.mjs`<br>`apps/api/test/abac-property.test.mjs`<br>`apps/api/test/abac-security.test.mjs` | PASS |
| **FR05** | Tiếp nhận tài liệu an toàn, kiểm tra định dạng và Magic Bytes | UC07, P08 | `apps/api/test/document-ingestion.test.mjs`<br>`apps/api/test/dangerous-files.test.mjs` | PASS |
| **FR06** | Quét mã độc ClamAV và xử lý cách ly an toàn file nhiễm EICAR | UC07, P08 | `test/infrastructure/clamav.test.mjs`<br>`apps/api/test/dangerous-files.test.mjs` | PASS |
| **FR07** | Mã hóa Envelope AES-256-GCM với khóa DEK độc lập và KMS | UC08, P08 | `apps/api/test/document-ingestion.test.mjs`<br>`apps/api/test/crypto-wrapper.test.mjs` | PASS |
| **FR08** | Quản lý vòng đời tài liệu, phân loại SCD Type-2 và phiên bản | UC08, UC09, P09 | `apps/api/test/document-lifecycle.test.mjs`<br>`apps/api/test/domain-state-machines.test.mjs` | PASS |
| **FR09** | Thay đổi mức mật và tự động điều chỉnh quyền truy cập/phiên | UC10, UC11, P09 | `apps/api/test/document-lifecycle.test.mjs`<br>`apps/api/test/concurrency.test.mjs` | PASS |
| **FR10** | Tìm kiếm siêu dữ liệu bảo mật DISCOVER không rò rỉ dữ liệu ẩn | UC19, P10 | `apps/api/test/document-search.test.mjs` | PASS |
| **FR11** | Tạo và quản lý yêu cầu truy cập tài liệu có lý do và thời hạn | UC13, UC14, UC15, P11 | `apps/api/test/access-grants.test.mjs`<br>`apps/api/test/domain-state-machines.test.mjs` | PASS |
| **FR12** | Phê duyệt/từ chối yêu cầu truy cập với kiểm soát tranh chấp | UC16, P11 | `apps/api/test/access-grants.test.mjs`<br>`apps/api/test/concurrency.test.mjs` | PASS |
| **FR13** | Cấp quyền trực tiếp theo người dùng hoặc vai trò (Role Grant) | UC12, P12 | `apps/api/test/access-grants.test.mjs`<br>`packages/database/test/migration.integration.test.mjs` | PASS |
| **FR14** | Thu hồi quyền truy cập tức thì và hủy phiên đang hoạt động | UC17, P12 | `apps/api/test/access-grants.test.mjs`<br>`apps/api/test/concurrency.test.mjs` | PASS |
| **FR15** | Điểm thực thi chính sách (PEP) kết hợp RBAC và ABAC lúc truy cập | UC20, UC21, UC22, P13 | `apps/api/test/document-delivery.test.mjs`<br>`apps/api/test/default-deny.test.mjs` | PASS |
| **FR16** | Đóng dấu thủy vân (Watermark) động định danh và chống rò rỉ | UC23, P13 | `apps/api/test/document-delivery.test.mjs`<br>`apps/api/test/watermark-token.test.mjs` | PASS |
| **FR17** | Phân phối file an toàn, vé tải một lần và stream có kiểm soát | UC20, UC22, P13 | `apps/api/test/document-delivery.test.mjs`<br>`test/infrastructure/object-storage.test.mjs` | PASS |
| **FR18** | Chuỗi nhật ký kiểm toán chống giả mạo (HMAC-SHA256 Chained) | UC24, UC25, P14 | `apps/api/test/audit-trail.test.mjs`<br>`apps/api/test/audit-canonicalization.test.mjs` | PASS |
| **FR19** | Giám sát an ninh, phát hiện tải ồ ạt và quản lý sự cố (SoD) | UC26, UC27, UC29, P15 | `apps/api/test/security-operations.test.mjs` | PASS |
| **FR20** | Truy vết nguồn gốc rò rỉ qua mã Watermark (Forensics) | UC28, P15 | `apps/api/test/document-delivery.test.mjs`<br>`apps/api/test/watermark-token.test.mjs` | PASS |

---

## 2. Quy Tắc Nghiệp Vụ (Business Rules D-BR01–D-BR20, AUTH-BR, RBAC-BR)

| Mã BR | Tóm Tắt Quy Tắc Nghiệp Vụ | Nguồn Quy Tắc | Test Suite / File Kiểm Thử | Trạng Thái |
| :--- | :--- | :--- | :--- | :--- |
| **D-BR01** | Mặc định DENY khi thiếu policy; kết hợp RBAC + ABAC tại server | AGENTS, P07, UC22 | `apps/api/test/default-deny.test.mjs`<br>`apps/api/test/abac-engine.test.mjs` | PASS |
| **D-BR02** | Không tin tưởng role, clearance hoặc department từ frontend gửi lên | AGENTS, P06, P16 | `apps/api/test/rbac-security.test.mjs`<br>`apps/api/test/api-contract.test.mjs` | PASS |
| **D-BR03** | Quyền chỉ hiệu lực trong thời hạn (`valid_from <= now < valid_to`) | P06, P12 | `apps/api/test/access-grants.test.mjs`<br>`apps/api/test/rbac-security.test.mjs` | PASS |
| **D-BR04** | Clearance < Classification hoặc thiếu thuộc tính bắt buộc luôn bị từ chối | P07, P12 | `apps/api/test/abac-engine.test.mjs`<br>`apps/api/test/access-grants.test.mjs` | PASS |
| **D-BR05** | Thuật toán gộp DENY_OVERRIDES: chỉ 1 deny là toàn bộ bị từ chối | P07, P13 | `apps/api/test/abac-engine.test.mjs`<br>`apps/api/test/abac-property.test.mjs` | PASS |
| **D-BR06** | File tải lên phải qua kiểm tra extension, MIME, magic bytes và ClamAV | P08, P09 | `apps/api/test/document-ingestion.test.mjs`<br>`apps/api/test/dangerous-files.test.mjs` | PASS |
| **D-BR07** | Mã hóa Envelope AES-256-GCM; không phát plaintext trước xác thực tag | P08, P14 | `apps/api/test/crypto-wrapper.test.mjs`<br>`apps/api/test/document-ingestion.test.mjs` | PASS |
| **D-BR08** | Tài liệu bắt buộc có Owner, Department, Title, Business Category, Classification | P09, UC07–UC11 | `apps/api/test/document-lifecycle.test.mjs` | PASS |
| **D-BR09** | Phiên bản tăng nguyên tử; current_version thuộc đúng tài liệu | P09 | `apps/api/test/document-lifecycle.test.mjs`<br>`apps/api/test/concurrency.test.mjs` | PASS |
| **D-BR10** | Tăng mức mật kết thúc phiên không hợp lệ; hạ mức không tự cấp quyền | P09 | `apps/api/test/document-lifecycle.test.mjs`<br>`apps/api/test/concurrency.test.mjs` | PASS |
| **D-BR11** | Tìm kiếm chỉ hiển thị tài liệu được DISCOVER, không leak tổng số ẩn | P10, UC19 | `apps/api/test/document-search.test.mjs` | PASS |
| **D-BR12** | Yêu cầu truy cập chỉ xin VIEW/DOWNLOAD; lý do tối thiểu 10 ký tự | P11, UC13–UC15 | `apps/api/test/access-grants.test.mjs` | PASS |
| **D-BR13** | Quyết định duyệt/từ chối là bất biến, xử lý nguyên tử chống duyệt kép | P11, UC16 | `apps/api/test/access-grants.test.mjs`<br>`apps/api/test/concurrency.test.mjs` | PASS |
| **D-BR14** | Cấp quyền trực tiếp độc lập giữa VIEW và DOWNLOAD; kiểm tra clearance | P12, UC12 | `apps/api/test/access-grants.test.mjs` | PASS |
| **D-BR15** | Quyền hết hạn hoặc thu hồi mất hiệu lực ngay lập tức, chấm dứt phiên | P12, UC17, UC20 | `apps/api/test/access-grants.test.mjs`<br>`apps/api/test/concurrency.test.mjs` | PASS |
| **D-BR16** | Phân phối tài liệu gắn phiên bảo mật; áp dụng chỉ thị HTTP Cache-Control no-store | P13, UC20–UC22 | `apps/api/test/document-delivery.test.mjs` | PASS |
| **D-BR17** | Tài liệu yêu cầu watermark phải sinh bản dẫn xuất; lỗi watermark fail-closed | P13, UC23 | `apps/api/test/document-delivery.test.mjs`<br>`apps/api/test/dangerous-files.test.mjs` | PASS |
| **D-BR18** | Hành động nhạy cảm phải tạo audit HMAC bất biến, không xóa cứng | P14, UC24–UC25 | `apps/api/test/audit-trail.test.mjs`<br>`apps/api/test/audit-canonicalization.test.mjs` | PASS |
| **D-BR19** | Phân tách phạm vi audit; Auditor chỉ xem/xuất dữ liệu, không cấp quyền | P14, P15, UC25–30 | `apps/api/test/security-operations.test.mjs`<br>`apps/api/test/rbac-security.test.mjs` | PASS |
| **D-BR20** | Xử lý thông báo bất đồng bộ an toàn; cảnh báo/sự cố chuyển trạng thái hợp lệ | P11, P12, P15 | `apps/api/test/security-operations.test.mjs`<br>`apps/api/test/domain-state-machines.test.mjs` | PASS |
| **AUTH-BR** | Argon2id, TOTP bắt buộc cho 3 vai trò cao cấp, phát hiện reuse token | P05 | `apps/api/test/auth-security.test.mjs`<br>`apps/api/test/concurrency.test.mjs` | PASS |
| **RBAC-BR** | Thừa kế phòng ban dạng cây, phân tách nhiệm vụ (SoD), ngăn leo thang đặc quyền | P06 | `apps/api/test/rbac-security.test.mjs`<br>`apps/api/test/integration/rbac-administration.integration.test.mjs` | PASS |

---

## 3. Yêu Cầu Phi Chức Năng (Non-Functional Requirements NFR)

| Mã NFR | Tiêu Chuẩn & Chỉ Số Mục Tiêu | Test Suite / Bằng Chứng Thực Thi | Kết Quả |
| :--- | :--- | :--- | :--- |
| **NFR-SEC01** | Zero-Trust & Default-Deny: Mọi API từ chối mặc định nếu không có policy cụ thể | `apps/api/test/default-deny.test.mjs`<br>`packages/security/test/public-policy.test.mjs` | Đạt |
| **NFR-SEC02** | Khóa mã hóa tách biệt: KEK lưu ở environment/KMS, DEK ngẫu nhiên riêng mỗi version | `apps/api/test/crypto-wrapper.test.mjs`<br>`apps/api/test/document-ingestion.test.mjs` | Đạt |
| **NFR-SEC03** | Audit Log bất biến: Trigger SQL chặn UPDATE/DELETE, chuỗi HMAC chống chèn/sửa | `apps/api/test/audit-trail.test.mjs`<br>`apps/api/test/audit-canonicalization.test.mjs` | Đạt |
| **NFR-SEC04** | Fail-Closed Watermarking: Lỗi sinh watermark lập tức từ chối cung cấp tài liệu gốc | `apps/api/test/dangerous-files.test.mjs`<br>`apps/api/test/document-delivery.test.mjs` | Đạt |
| **NFR-REL01** | Khởi động từ DB sạch & Nâng cấp Migration không gián đoạn | `packages/database/test/migration.integration.test.mjs`<br>`packages/database/test/snapshot-upgrade.integration.test.mjs` | Đạt |
| **NFR-REL02** | Kiểm soát tương tranh & Race Condition: 5 kịch bản đồng thời đều xử lý đúng | `apps/api/test/concurrency.test.mjs` | Đạt |
| **NFR-PERF01** | Argon2id dummy work cân bằng thời gian (chống timing attack / side-channel) | `apps/api/test/auth-security.test.mjs` | Đạt |
| **NFR-PERF02** | Zip Bomb Guard & Streaming I/O: Ngăn cạn kiệt tài nguyên RAM / Disk | `apps/api/test/dangerous-files.test.mjs`<br>`apps/api/test/document-ingestion.test.mjs` | Đạt |
| **NFR-AUDIT01** | Canonicalization chuẩn hóa JSON: Tránh tráo đổi thứ tự key làm sai lệch HMAC | `apps/api/test/audit-canonicalization.test.mjs` | Đạt |
