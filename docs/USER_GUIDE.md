# Hướng Dẫn Sử Dụng Hệ Thống (Enterprise User Guide)

Hệ thống Quản Lý Truy Cập Tài Liệu Mật Trong Tổ Chức (SDA v1.0.0).
Tài liệu hướng dẫn chi tiết quy trình thao tác và phân tách chức năng (Separation of Duties - SoD) cho 5 vai trò nghiệp vụ chính.

---

## 1. Tổng Quan 5 Vai Trò Người Dùng (Role Overview)

| Vai trò                                  | Phạm vi chức năng cốt lõi                                                                        | Nguyên tắc an ninh bắt buộc                                                             |
| :--------------------------------------- | :----------------------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------- |
| **ADMINISTRATOR** (Quản Trị Hệ Thống)    | Quản trị tài khoản, phòng ban, vai trò, thuộc tính ABAC, mẫu Watermark, System Health            | **Không được xem nội dung tài liệu mật** (Không IDOR, Least Privilege).                 |
| **DOCUMENT_OWNER** (Chủ Sở Hữu Tài Liệu) | Tải lên, phân loại mức mật bắt buộc, quản lý phiên bản, duyệt yêu cầu, thu hồi quyền tức thì     | Chỉ quản lý tài liệu do mình sở hữu hoặc thuộc phạm vi phòng ban được giao.             |
| **READER** (Người Đọc Tài Liệu)          | Tìm kiếm khám phá (Discover), gửi yêu cầu truy cập, xem tài liệu có đóng dấu Watermark định danh | Luôn đóng dấu Watermark động; quyền có thời hạn và mất hiệu lực tức thì khi bị thu hồi. |
| **SECURITY_OFFICER** (Cán Bộ An Ninh)    | Giám sát hàng đợi cảnh báo, điều tra sự cố, tra cứu Watermark Token giải mã nguồn rò rỉ          | Được quyền cô lập tài khoản và thu hồi khẩn cấp, nhưng không tự ý sửa đổi audit log.    |
| **AUDITOR** (Kiểm Toán Viên)             | Tra cứu nhật ký kiểm toán bất biến, thẩm định chuỗi băm HMAC, xuất báo cáo phục vụ thanh tra     | **Chế độ chỉ đọc (Strict Read-Only)**; không có quyền phê duyệt hay chỉnh sửa dữ liệu.  |

---

## 2. Hướng Dẫn Dành Cho Quản Trị Viên (Administrator)

### 2.1 Quản trị người dùng & Phân cấp phòng ban

- **Đường dẫn**: `/admin` -> Tab **Người Dùng & Phòng Ban**.
- **Chức năng**:
  - Tạo mới người dùng, chỉ định Phòng ban, Mức độ tin cậy bảo mật (Clearance Level 1 đến 4).
  - Khóa tài khoản (`DISABLED`) hoặc buộc kích hoạt MFA (TOTP).
  - Quản lý cây phòng ban đa cấp, ngăn chặn vòng lặp cha-con (Acyclic Tree Trigger).

### 2.2 Quản trị thuộc tính & Chính sách ABAC

- **Đường dẫn**: `/admin` -> Tab **Thuộc Tính & ABAC**.
- **Chức năng**:
  - Định nghĩa thuộc tính động (Ví dụ: `device_trust_level`, `network_zone`, `project_membership`).
  - Biên dịch và lưu trữ phiên bản chính sách tất định (Deterministic Policy Compilation).

### 2.3 Cấu hình tem Watermark & Sức khỏe hệ thống

- **Đường dẫn**: `/admin` -> Tab **Watermark Config & Health**.
- **Chức năng**:
  - Thiết lập mẫu Watermark hiển thị: màu sắc (`color_hex`), độ mờ (`opacity_percent`), góc xoay, nhúng mã QR.
  - Theo dõi trạng thái liveness, readiness probe và các thành phần phụ thuộc (Postgres, Redis, Storage).

---

## 3. Hướng Dẫn Dành Cho Chủ Sở Hữu Tài Liệu (Document Owner)

### 3.1 Tải lên và phân loại mức mật tài liệu

- **Đường dẫn**: `/owner` -> Tab **Tải Lên Tài Liệu**.
- **Các bước thực hiện**:
  1. Nhập Mã tài liệu (duy nhất), Tiêu đề, Mô tả tóm tắt.
  2. Chọn Danh mục nghiệp vụ (`business_category`) và **Mức độ mật bắt buộc** (`PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `TOP_SECRET`).
  3. Đính kèm tệp văn bản (`.pdf`, `.docx`, `.xlsx`, `.pptx`).
  4. Hệ thống tự động kiểm tra Magic bytes, rà soát zip-bomb và quét virus qua ClamAV. File nhiễm mã độc lập tức bị cách ly và từ chối kích hoạt.

### 3.2 Phê duyệt yêu cầu truy cập (Access Requests)

- **Đường dẫn**: `/owner` -> Tab **Yêu Cầu Chờ Duyệt**.
- **Các bước thực hiện**:
  1. Xem danh sách yêu cầu kèm lý do đề xuất (tối thiểu 10 ký tự) và thời hạn mong muốn.
  2. Bấm **Phê Duyệt (Approve)** hoặc **Từ Chối (Reject)** kèm ghi chú.
  3. Thao tác được bảo vệ bằng khóa chống tranh chấp đồng thời (Optimistic Concurrency Control).

### 3.3 Thu hồi quyền truy cập tức thì (Immediate Revocation)

- **Đường dẫn**: `/owner` -> Tab **Quyền Đã Cấp (Active Grants)**.
- **Các bước thực hiện**:
  1. Tìm quyền cần thu hồi, bấm nút **Thu Hồi Quyền (Revoke)**.
  2. Nhập lý do thu hồi (Bắt buộc để lưu vết kiểm toán).
  3. **Hiệu lực tức thì**: Quyền chuyển sang trạng thái `REVOKED`, toàn bộ phiên đọc (`access_sessions`) và vé tải đang hoạt động của người dùng bị hủy ngay lập tức. Người đọc đang xem tài liệu sẽ bị chặn ngay ở lượt tải trang kế tiếp.

---

## 4. Hướng Dẫn Dành Cho Người Đọc (Reader)

### 4.1 Khám phá và gửi yêu cầu truy cập tài liệu

- **Đường dẫn**: `/reader` -> Tab **Khám Phá Tài Liệu**.
- **Quy trình**:
  1. Tìm kiếm theo từ khóa có dấu, số hiệu tài liệu hoặc phòng ban.
  2. Danh sách chỉ hiển thị các tài liệu cho phép DISCOVER mà không làm rò rỉ dữ liệu nhạy cảm.
  3. Bấm **Yêu Cầu Truy Cập**, chọn quyền mong muốn (`XEM_TRUC_TUYEN` hoặc `TAI_XUONG`), nhập lý do chi tiết và thời hạn cần thiết.

### 4.2 Xem trực tuyến tài liệu có Watermark

- **Đường dẫn**: `/reader` -> Tab **Tài Liệu Của Tôi**.
- **Quy trình**:
  1. Chọn tài liệu đã được duyệt cấp quyền, bấm **Xem Trực Tuyến**.
  2. Hệ thống sinh phiên truy cập độc lập và nhúng Watermark định danh động lên tất cả các trang:
     - `Họ và tên người xem - Mã nhân viên - Mã tài liệu - Thời điểm xem UTC - Mã Token bảo mật`.
     - Mã QR ở góc trang phục vụ truy vết bằng camera.

---

## 5. Hướng Dẫn Dành Cho Cán Bộ An Ninh (Security Officer)

### 5.1 Giám sát hàng đợi cảnh báo an ninh

- **Đường dẫn**: `/security` -> Tab **Hàng Đợi Cảnh Báo**.
- **Quy trình**:
  1. Theo dõi các cảnh báo tự động sinh: `MASS_DOWNLOAD` (tải ồ ạt), `AUDIT_INTEGRITY_COMPROMISED` (nghi ngờ can thiệp audit), `MALWARE_DETECTED`.
  2. Tiếp nhận xử lý: Chuyển trạng thái từ `OPEN` sang `INVESTIGATING`.
  3. Thực hiện cô lập khẩn cấp tài khoản hoặc thu hồi quyền nếu phát hiện dấu hiệu rò rỉ dữ liệu.
  4. Đóng cảnh báo: Chuyển sang `RESOLVED` hoặc `FALSE_POSITIVE` kèm giải trình bắt buộc.

### 5.2 Điều tra số qua mã Watermark (Forensics Trace)

- **Đường dẫn**: `/security` -> Tab **Truy Vết Watermark**.
- **Quy trình**:
  1. Khi phát hiện một trang tài liệu bị rò rỉ ngoài thực tế, nhập chuỗi Token Watermark hoặc quét mã QR trên ảnh.
  2. Bấm **Tra Cứu Nguồn Rò Rỉ**.
  3. Hệ thống trả về danh tính người mở xem, thời điểm chính xác, phiên làm việc và địa chỉ IP kết nối tại thời điểm tài liệu được phát hành.

---

## 6. Hướng Dẫn Dành Cho Kiểm Toán Viên (Auditor)

### 6.1 Tra cứu nhật ký kiểm toán bất biến

- **Đường dẫn**: `/auditor` -> Tab **Nhật Ký Kiểm Toán**.
- **Tính năng**:
  - Tra cứu toàn bộ thao tác nhạy cảm phân vùng theo `DOCUMENT`, `GRANT`, `SESSION`, `AUTH`, `SECURITY`.
  - Bộ lọc đa chiều: Người thực hiện, Mã tài liệu, Kết quả (`SUCCESS` / `FAILED`), Khoảng thời gian.

### 6.2 Thẩm định tính toàn vẹn chuỗi băm (HMAC Verification)

- **Đường dẫn**: `/auditor` -> Tab **Xác Minh Toàn Vẹn**.
- **Quy trình**:
  1. Bấm **Kiểm Tra Tính Toàn Vẹn Chuỗi**.
  2. Hệ thống duyệt qua từng sequence của phân vùng, băm lại nội dung và so sánh với `record_hash` và `previous_record_hash`.
  3. Báo cáo trạng thái xanh `HEALTHY` hoặc phát hiện vị trí sai lệch tức thì nếu có ai can thiệp trực tiếp vào database.

### 6.3 Xuất báo cáo an toàn (Formula-Injection Protected Export)

- **Đường dẫn**: `/auditor` -> Tab **Xuất Báo Cáo**.
- **Tính năng**:
  - Khởi tạo công việc xuất bất đồng bộ (24h TTL) định dạng CSV hoặc JSON.
  - Tự động áp dụng cơ chế làm sạch công thức bảng tính (CSV Formula Sanitization): tự động prefix dấu nháy đơn `'` cho các ô bắt đầu bằng `=`, `+`, `-`, `@`, `\t`, `\r` để bảo vệ ứng dụng Excel/LibreOffice của thanh tra viên khỏi mã độc.
