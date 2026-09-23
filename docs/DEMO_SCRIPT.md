# Kịch Bản Trình Diễn Hệ Thống (Interactive Demo Script: 10 - 15 Phút)

Kịch bản trình diễn luồng nghiệp vụ thực tế của Hệ thống Quản Lý Truy Cập Tài Liệu Mật (SDA v1.0.0).  
Kịch bản được thiết kế cho buổi báo cáo kỹ thuật và kiểm thử chấp nhận (UAT), thể hiện đầy đủ 7 bước nghiệp vụ cốt lõi, bảo mật Zero-Trust, phân quyền ABAC và cơ chế thu hồi quyền tức thì.

---

## 1. Bảng Phân Bổ Thời Gian & Nhân Vật Trình Diễn

| Khoảng thời gian  | Bước thực hiện                           | Nhân vật (Persona)           | Mục tiêu bảo mật / Nghiệp vụ kiểm chứng                                      |
| :---------------- | :--------------------------------------- | :--------------------------- | :--------------------------------------------------------------------------- |
| **00:00 - 02:30** | Bước 1: Tải lên & Phân loại tài liệu     | `owner.demo` (Owner)         | Quét mã độc, mã hóa phong bì AES-256-GCM, phân loại CONFIDENTIAL.            |
| **02:30 - 04:30** | Bước 2: Tìm kiếm & Gửi yêu cầu truy cập  | `reader.demo` (Reader)       | Discover metadata (tiêu đề, phân loại), gửi Access Request kèm lý do.        |
| **04:30 - 06:30** | Bước 3: Phê duyệt yêu cầu cấp quyền      | `owner.demo` (Owner)         | Kiểm tra lý do, phê duyệt và sinh Access Grant có thời hạn.                  |
| **06:30 - 09:00** | Bước 4: Xem tài liệu gắn Watermark động  | `reader.demo` (Reader)       | Đóng dấu Watermark động: Tên người đọc, IP, Timestamp, mã QR Token bí mật.   |
| **09:00 - 11:30** | Bước 5: Tra cứu Audit & Đối chiếu Token  | `security.demo` (Security)   | Thẩm định chuỗi HMAC nhật ký, giải mã Watermark Token truy vết nguồn gốc.    |
| **11:30 - 14:00** | Bước 6 & 7: Thu hồi tức thì khi phiên mở | `owner.demo` & `reader.demo` | Thu hồi Grant; Redis vô hiệu hóa Session ngay; Reader bị chặn lập tức (403). |
| **14:00 - 15:00** | Tổng kết & Hỏi đáp kỹ thuật              | Người trình bày              | Tóm tắt kiến trúc phòng thủ đa lớp và giải đáp câu hỏi hội đồng.             |

---

## 2. Chuẩn Bị Môi Trường Trình Diễn (Pre-requisites)

### 2.1 Tài khoản và thông tin đăng nhập demo

Hệ thống sử dụng các tài khoản định danh trong môi trường kiểm thử:

- **Chủ sở hữu tài liệu (Document Owner)**:
  - Tên đăng nhập: `owner.demo`
  - Phòng ban: Khối văn phòng (`HEAD_OFFICE`)
  - Cấp độ thẩm tra: `SECRET` (Cấp 3)
- **Người đọc tài liệu (Document Reader)**:
  - Tên đăng nhập: `reader.demo`
  - Phòng ban: Khối văn phòng (`HEAD_OFFICE`)
  - Cấp độ thẩm tra: `INTERNAL` (Cấp 1)
- **Cán bộ an ninh thông tin (Security Officer)**:
  - Tên đăng nhập: `security.demo`
  - Phòng ban: Phòng An toàn thông tin (`INFORMATION_SECURITY`)
  - Cấp độ thẩm tra: `TOP_SECRET` (Cấp 4)

### 2.2 Dữ liệu tài liệu mẫu

- Chuẩn bị sẵn một tệp PDF mẫu: `CHIEN_LUOC_KINH_DOANH_2026.pdf` (khoảng 2-5 trang).
- Nội dung văn bản kinh doanh chiến lược cần bảo vệ mức `CONFIDENTIAL` (Mật).

---

## 3. Kịch Bản Chi Tiết Từng Bước

### Bước 1: Owner Tải Lên Và Phân Loại Mức Mật (00:00 - 02:30)

#### Thao tác trên giao diện:

1. Đăng nhập tài khoản `owner.demo` tại cổng thông tin `http://localhost:3000/login`.
2. Truy cập thanh điều hướng: **Quản Lý Tài Liệu** -> **Tải lên tệp mới** (`/owner/documents/upload`).
3. Điền thông tin văn bản:
   - **Mã tài liệu**: `DOC-STRAT-2026-001`
   - **Tiêu đề**: `Chiến Lược Kinh Doanh & Đầu Tư Công Nghệ 2026`
   - **Danh mục**: `Nghiệp vụ chung` (`GENERAL_OPERATIONS`)
   - **Cấp độ mật bắt buộc**: Chọn `CONFIDENTIAL (Mật)`.
4. Chọn tệp `CHIEN_LUOC_KINH_DOANH_2026.pdf` và nhấn nút **Tải lên & Mã hóa**.

#### Diễn giải kỹ thuật cho hội đồng:

- _File được kiểm tra Magic Bytes (PDF `%PDF-`), rà quét mã độc qua ClamAV daemon._
- _Dữ liệu được mã hóa phong bì (Envelope Encryption) bằng Data Encryption Key (DEK) 256-bit sinh ngẫu nhiên._
- _DEK được khóa lại bằng Key Encryption Key (KEK) từ dịch vụ KMS._
- _Metadata tài liệu được ghi vào cơ sở dữ liệu với trạng thái `ACTIVE`._

---

### Bước 2: Reader Tìm Kiếm Khám Phá & Gửi Yêu Cầu Truy Cập (02:30 - 04:30)

#### Thao tác trên giao diện:

1. Mở cửa sổ ẩn danh mới (hoặc trình duyệt phụ), đăng nhập tài khoản `reader.demo`.
2. Truy cập màn hình **Tìm Kiếm Tài Liệu** (`/reader/discover`).
3. Nhập từ khóa: `Chiến Lược Kinh Doanh`.
4. Kết quả tìm kiếm hiển thị:
   - Thấy tiêu đề `Chiến Lược Kinh Doanh & Đầu Tư Công Nghệ 2026` và mức mật `CONFIDENTIAL`.
   - Nút **Xem nội dung** bị khóa do Reader chỉ có Clearance cấp 1 (`INTERNAL`), không đủ thẩm tra để mở trực tiếp.
5. Reader nhấn nút **Yêu Cầu Truy Cập (Request Access)**:
   - **Mục đích truy cập**: `Phục vụ nghiên cứu xây dựng kế hoạch dự toán tài chính quý 1/2026 cho dự án tích hợp hệ thống`.
   - **Thời hạn đề xuất**: `24 giờ`.
6. Nhấn nút **Gửi yêu cầu**. Hệ thống thông báo tạo thành công mã yêu cầu `REQ-XXXXX`.

#### Diễn giải kỹ thuật cho hội đồng:

- _Cơ chế Zero-Trust: Người dùng có thể phát hiện sự tồn tại của tài liệu (Metadata Discovery) nhưng không được cấp URL tải tệp khi chưa có Grant._
- _Lý do yêu cầu bắt buộc tối thiểu 10 ký tự để phục vụ hậu kiểm SoD._

---

### Bước 3: Owner Phê Duyệt Yêu Cầu Cấp Quyền (04:30 - 06:30)

#### Thao tác trên giao diện:

1. Quay lại phiên làm việc của `owner.demo`.
2. Truy cập menu **Yêu Cầu Chờ Duyệt** (`/owner/requests`).
3. Mở chi tiết yêu cầu `REQ-XXXXX` gửi từ `reader.demo`:
   - Kiểm tra lý do nghiệp vụ, thời gian yêu cầu (24 giờ).
4. Nhấn nút **Phê Duyệt (Approve)**:
   - Nhập ghi chú duyệt: `Đồng ý cấp quyền đọc trong 24h phục vụ dự toán tài chính`.
   - Xác nhận phê duyệt.
5. Yêu cầu chuyển trạng thái sang `APPROVED`, hệ thống tự sinh `ACCESS_GRANT` với thời hạn hết hiệu lực cụ thể.

#### Diễn giải kỹ thuật cho hội đồng:

- _Quy trình được thực thi dưới Serializable Transaction kèm Optimistic Concurrency Control (OCC)._
- _Ghi nhận một bản ghi Audit Log bất biến: `ACCESS_REQUEST_APPROVED` liên kết ID người duyệt và người được duyệt._

---

### Bước 4: Reader Xem Bản Đóng Dấu Watermark Động (06:30 - 09:00)

#### Thao tác trên giao diện:

1. Quay lại phiên `reader.demo`, tải lại trang **Tài Liệu Của Tôi** (`/reader/my-documents`).
2. Tài liệu `DOC-STRAT-2026-001` đã chuyển sang trạng thái **Được cấp quyền (Granted)**.
3. Reader nhấn nút **Xem Trực Tuyến (Secure Viewer)**.
4. Trình xem tài liệu bảo mật mở ra:
   - Các trang PDF hiển thị rõ ràng nội dung.
   - **Tem Watermark động** chéo 45 độ trên từng trang:
     - `NGƯỜI XEM: reader.demo (Nguyen Van Doc)`
     - `IP: 127.0.0.1 | 2026-09-23 15:30:00`
     - `MÃ GIÁM SÁT: WTM-7B8A9C12`
   - Góc dưới mỗi trang chứa mã QR nhỏ mã hóa thông tin Token giám định.
   - Nút chuột phải, in ấn và sao chép văn bản bị chặn hoàn toàn.

#### Diễn giải kỹ thuật cho hội đồng:

- _Watermark Engine sinh động trong bộ nhớ (Streamed On-the-Fly), không lưu bản Watermark tĩnh ra đĩa._
- _Token `WTM-7B8A9C12` là mã nhận dạng duy nhất cho từng phiên xem (Session Instance), được ký HMAC bí mật phía backend._

---

### Bước 5: Security Tra Cứu Audit & Đối Chiếu Forensic Token (09:00 - 11:30)

#### Tình huống giả định:

_Một bức ảnh chụp màn hình tài liệu bị rò rỉ trên mạng xã hội, chỉ thấy góc trang có mã `WTM-7B8A9C12`._

#### Thao tác trên giao diện:

1. Mở cửa sổ trình duyệt mới, đăng nhập tài khoản `security.demo`.
2. Truy cập màn hình **Giám Định Dấu Vết (Watermark Forensics)** (`/security/watermarks/trace`).
3. Nhập mã giám định: `WTM-7B8A9C12` và nhấn nút **Truy Vết Nguồn Gốc**.
4. Kết quả truy vết trả về tức thì:
   - **Người dùng thực hiện xem**: `reader.demo` (Nguyễn Văn Đọc)
   - **Tài liệu**: `DOC-STRAT-2026-001` (Chiến Lược Kinh Doanh 2026)
   - **Địa chỉ IP truy cập**: `127.0.0.1`
   - **Thời điểm mở phiên**: `2026-09-23 15:30:12`
   - **Mã Session ID tương ứng**: `sess_live_89a7fbc2`
5. Truy cập màn hình **Nhật Ký Kiểm Toán (Audit Trail)** (`/security/audit`):
   - Thấy chuỗi bản ghi sự kiện nối tiếp nhau: `LOGIN` -> `DISCOVER` -> `ACCESS_REQUEST` -> `APPROVE` -> `SESSION_START`.
   - Trạng thái chữ ký HMAC: **Toàn vẹn hợp lệ (HMAC Verified Valid)**.

#### Diễn giải kỹ thuật cho hội đồng:

- _Chứng minh tính bất khả chối từ (Non-repudiation) và khả năng truy vết rò rỉ chính xác 100% trong vòng dưới 3 giây._

---

### Bước 6 & 7: Owner Thu Hồi Khi Phiên Đang Mở & Reader Bị Chặn Ngay (11:30 - 14:00)

#### Thao tác trên giao diện (Thực hiện song song trên 2 màn hình chia đôi):

1. **Màn hình bên trái (`reader.demo`)**: Reader vẫn đang cuộn xem tài liệu `CHIEN_LUOC_KINH_DOANH_2026.pdf`.
2. **Màn hình bên phải (`owner.demo`)**:
   - Owner phát hiện nghi vấn hoặc hết nhu cầu công việc, truy cập **Quản Lý Quyền Truy Cập** (`/owner/grants`).
   - Tìm quyền cấp cho `reader.demo` với tài liệu `DOC-STRAT-2026-001`.
   - Nhấn nút **Thu Hồi Quyền Khẩn Cấp (Revoke Immediately)**.
   - Nhập lý do thu hồi: `Yêu cầu thu hồi khẩn cấp phục vụ kiểm tra bảo mật đột xuất`.
   - Nhấn **Xác nhận thu hồi**.
3. **Quan sát phản ứng tức thì trên màn hình bên trái (`reader.demo`)**:
   - Ngay khi Owner bấm xác nhận (trong vòng < 100ms):
   - Reader nhấn chuyển sang trang tiếp theo hoặc thao tác cuộn: Trình xem tài liệu lập tức chuyển sang màn hình đỏ cảnh báo:
     > **TRUY CẬP BỊ TỪ CHỐI (403 FORBIDDEN)**  
     > _Quyền truy cập của bạn đối với tài liệu này đã bị thu hồi hoặc đã hết hiệu lực. Phiên làm việc đã bị hủy bỏ._
   - Reader thử F5 tải lại trang: Giao diện chuyển hướng về trang chủ và tài liệu biến mất khỏi danh sách được phép đọc.

#### Diễn giải kỹ thuật cho hội đồng:

- _Hệ thống áp dụng cơ chế xác thực quyền đa lớp tại backend PEP (Policy Enforcement Point)._
- _Lệnh thu hồi lập tức xuất tín hiệu vô hiệu hóa khóa phiên trên Redis Cache cluster (`revocation:grant:<id>`) và cập nhật cơ sở dữ liệu._
- _Mọi request lấy luồng dữ liệu trang (chunk/stream) đều phải qua PEP xác thực; khi grant bị revoke, hệ thống lập tức ngắt kết nối theo nguyên tắc Fail-Closed._

---

## 4. Lệnh Thử Nghiệm Tự Động Qua Terminal (Headless Verification)

Nếu buổi trình diễn được thực hiện qua dòng lệnh hoặc kiểm thử tự động, toàn bộ quy trình trên có thể tái hiện độc lập bằng script:

```bash
# Chạy bộ kịch bản kiểm thử tích hợp mô phỏng toàn bộ luồng nghiệp vụ trên
node scripts/smoke-test.mjs
```

Kết quả mong đợi:

```text
[SMOKE TEST] Step 1: Healthcheck API & Database ... PASS (200 OK)
[SMOKE TEST] Step 2: KMS Envelope Encryption & Decryption ... PASS (Ciphertext verified)
[SMOKE TEST] Step 3: JWT Ed25519 Token Minting & Verification ... PASS
[SMOKE TEST] Step 4: ABAC Decision Engine (PDP Clearance check) ... PASS (Deny lower rank)
[SMOKE TEST] Step 5: Watermark Token Generation & QR Forensic ... PASS (Signed token verified)
[SMOKE TEST] Step 6: Tamper-Evident Audit HMAC Chaining ... PASS (Hash chain continuous)
[SMOKE TEST] Step 7: Zero-Trust Active Session Immediate Revocation ... PASS (Fail-closed verified)

============================================================
ALL 7/7 SMOKE TEST CHECKS PASSED SUCCESSFULLY.
============================================================
```

---

## 5. Tóm Tắt Giá Trị Kỹ Thuật Đạt Được

1. **Bảo mật tuyệt đối**: Dữ liệu lưu trữ luôn mã hóa phong bì; không lộ plaintext trên ổ đĩa.
2. **Kiểm soát chặt chẽ**: Quyền hạn ABAC kết hợp Clearance Level đánh giá động theo ngữ cảnh.
3. **Truy vết không thể chối cãi**: Watermark động định danh cá nhân kèm mã QR và chuỗi kiểm toán HMAC bất biến.
4. **Phản ứng thời gian thực**: Thu hồi quyền có hiệu lực ngay lập tức (< 100ms) trên các phiên đọc đang hoạt động.
