# Sổ Tay Vận Hành: Ứng Phó Sự Cố An Ninh (Incident Response Runbook)

Hệ thống Quản Lý Truy Cập Tài Liệu Mật Trong Tổ Chức (SDA v1.0.0).
Quy trình chuẩn mực xử lý sự cố an ninh thông tin theo tiêu chuẩn **NIST SP 800-61 Rev. 2 (Computer Security Incident Handling Guide)**, tích hợp trực tiếp với các module giám sát và điều tra số của hệ thống.

---

## 1. Các Mức Độ Nghiêm Trọng Của Sự Cố (Severity Levels)

| Mức Độ               | Tiêu Chí Xác Định                                                             | Ví Dụ Điển Hình                                                                              | Thời Gian Phản Hồi    |
| :------------------- | :---------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------- | :-------------------- |
| **SEV-1 (CRITICAL)** | Toàn vẹn hệ thống bị xâm nhập, rò rỉ tài liệu Tối mật, phá vỡ chuỗi kiểm toán | Phát hiện chuỗi HMAC audit bị đứt gãy, lộ Master Key KEK, phát hiện rò rỉ tài liệu ra ngoài  | Dưới **15 phút**      |
| **SEV-2 (HIGH)**     | Phát hiện hành vi tấn công tự động hoặc tái sử dụng token bất thường          | Tái sử dụng Refresh Token (Reuse Detection), Tải hàng loạt (MASS_DOWNLOAD > 5 tài liệu/phút) | Dưới **1 giờ**        |
| **SEV-3 (MEDIUM)**   | Cố gắng leo thang đặc quyền bất thành hoặc upload mã độc bị chặn              | EICAR malware bị ClamAV tống vào Quarantine, vi phạm chính sách ABAC nhiều lần               | Dưới **4 giờ**        |
| **SEV-4 (LOW)**      | Cảnh báo thăm dò, sai mật khẩu nhiều lần nhưng chưa vượt ngưỡng lock          | Người dùng nhập sai TOTP 3 lần, quét cổng thăm dò từ IP lạ                                   | Trong vòng **24 giờ** |

---

## 2. Quy Trình Ứng Phó 5 Giai Đoạn

```
[1. Phát Hiện] -> [2. Cô Lập (Containment)] -> [3. Điều Tra (Forensics)] -> [4. Khắc Phục] -> [5. Báo Cáo]
```

### Giai Đoạn 1: Phát Hiện & Nhận Diện (Detection & Identification)

- **Nguồn phát hiện**:
  1. Hàng đợi `SecurityAlertsService` tự động sinh alert: `MASS_DOWNLOAD`, `REFRESH_TOKEN_REUSE`, `HMAC_CHAIN_BROKEN`, `MALWARE_DETECTED`.
  2. Báo cáo từ người dùng hoặc thông báo qua kênh an ninh.
  3. Metric bất thường trên Prometheus/Grafana (tỷ lệ lỗi 403, 401 tăng đột biến).
- **Hành động**:
  - Security Officer mở dashboard `/security` hoặc gọi API `/api/v1/security/alerts`.
  - Chuyển trạng thái Alert từ `OPEN` sang `INVESTIGATING`.

### Giai Đoạn 2: Cô Lập Tức Thì (Containment)

Mục tiêu là chặn đứng ngay thiệt hại mà không làm mất dấu vết điều tra:

1. **Cô lập phiên người dùng (Account Isolation)**:
   - Nếu phát hiện nghi ngờ xâm nhập tài khoản, thu hồi toàn bộ phiên và chuyển người dùng sang `DISABLED`.
2. **Thu hồi quyền truy cập tài liệu khẩn cấp (Grant Revocation)**:
   - Thu hồi grant và hủy toàn bộ phiên mở file đang hoạt động:
     ```http
     POST /api/v1/access-grants/:id/revoke
     Content-Type: application/json
     { "reason": "Emergency containment due to suspected data exfiltration" }
     ```
3. **Cách ly file nghi ngờ (Object Quarantine)**:
   - File độc hại tự động chuyển vào bucket `quarantine` và tài liệu giữ trạng thái `DRAFT`.

### Giai Đoạn 3: Điều Tra Số & Giám Định Pháp Y (Forensics & Analysis)

1. **Kiểm tra tính toàn vẹn của Audit Trail**:
   - Chạy xác minh chuỗi HMAC qua `AuditVerifierService` để xác định chính xác bản ghi bị can thiệp.
2. **Truy vết rò rỉ tài liệu qua Watermark Forensics**:
   - Khi phát hiện một trang tài liệu bị rò rỉ ra ngoài (ảnh chụp hoặc bản in PDF), trích xuất mã Watermark Token hoặc quét mã QR ở góc trang (ví dụ `WM-4c2f89...`).
   - Gọi API tra cứu:
     ```http
     GET /api/v1/watermarks/lookup?token=WM-4c2f89...
     ```
   - Hệ thống phản hồi chính xác: Người xem, Mã nhân viên, Mã tài liệu, Phiên bản, Thời điểm xem UTC, IP truy cập lúc hiển thị.
3. **Liên kết vết kiểm toán (Alert Audit Links)**:
   - Tra cứu bảng `alert_audit_links` để lấy toàn bộ các thao tác nghiệp vụ dẫn đến sự cố.

### Giai Đoạn 4: Khắc Phục Triệt Để & Khôi Phục (Eradication & Recovery)

1. Vô hiệu hóa tài khoản bị xâm nhập hoặc xoay vòng chứng thư người dùng.
2. Nếu nghi ngờ lộ khóa ký hoặc Master Key: Thực hiện xoay vòng khóa theo [`docs/KEY_ROTATION.md`](file:///d:/PTVTKHT/secure-document-access-system/docs/KEY_ROTATION.md).
3. Đóng trạng thái cảnh báo trên `/security`: chuyển sang `RESOLVED` kèm ghi chú giải trình (`resolutionNote`).

### Giai Đoạn 5: Đánh Giá & Báo Cáo Sự Cố (Post-Incident Review)

1. Tạo báo cáo sự cố chính thức (`IncidentReport`) với phạm vi ảnh hưởng, nguyên nhân gốc rễ và bài học kinh nghiệm.
2. Báo cáo phân tách nhiệm vụ (SoD): Auditor chỉ xem báo cáo và lịch sử audit, Security Officer thực thi hành động điều tra.
