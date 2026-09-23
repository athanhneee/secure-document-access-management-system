# Sổ Tay Vận Hành: Ứng Phó Sự Cố An Ninh (Incident Response Runbook)

Quy trình chuẩn mực xử lý sự cố an ninh thông tin theo tiêu chuẩn **NIST SP 800-61 Rev. 2 (Computer Security Incident Handling Guide)**, tích hợp trực tiếp với các module giám sát và điều tra số của hệ thống.

---

## 1. Các Mức Độ Nghiêm Trọng Của Sự Cố (Severity Levels)

| Mức Độ | Tiêu Chí Xác Định | Ví Dụ Điển Hình | Thời Gian Phản Hồi |
| :--- | :--- | :--- | :--- |
| **SEV-1 (CRITICAL)** | Toàn vẹn hệ thống bị xâm nhập, rò rỉ tài liệu Tối mật/Tuyệt mật, phá vỡ chuỗi kiểm toán | Phát hiện chuỗi HMAC audit bị đứt gãy, lộ Master Key KEK, phát hiện rò rỉ tài liệu ra ngoài Internet | Dưới **15 phút** |
| **SEV-2 (HIGH)** | Phát hiện hành vi tấn công tự động hoặc tái sử dụng token bất thường | Tái sử dụng Refresh Token (Reuse Detection), Tải hàng loạt (MASS_DOWNLOAD > 5 tài liệu/phút) | Dưới **1 giờ** |
| **SEV-3 (MEDIUM)** | Cố gắng leo thang đặc quyền bất thành hoặc upload mã độc bị chặn | EICAR malware bị ClamAV tống vào Quarantine, vượt quyền ABAC nhiều lần liên tiếp | Dưới **4 giờ** |
| **SEV-4 (LOW)** | Cảnh báo thăm dò, sai mật khẩu nhiều lần nhưng chưa vượt ngưỡng lock | Người dùng nhập sai TOTP 3 lần, quét cổng thăm dò từ IP lạ | Trong vòng **24 giờ** |

---

## 2. Quy Trình Ứng Phó 5 Giai Đoạn

```
[1. Phát Hiện] -> [2. Cô Lập (Containment)] -> [3. Điều Tra (Forensics)] -> [4. Khắc Phục] -> [5. Báo Cáo]
```

### Giai Đoạn 1: Phát Hiện & Nhận Diện (Detection & Identification)
- **Nguồn phát hiện**:
  1. Hàng đợi `SecurityAlertsService` tự động sinh alert: `MASS_DOWNLOAD`, `REFRESH_TOKEN_REUSE`, `HMAC_CHAIN_BROKEN`, `MALWARE_DETECTED`.
  2. Báo cáo từ người dùng hoặc thông báo từ kênh tiếp nhận lỗ hổng `SECURITY.md`.
  3. Metric bất thường trên Prometheus/Grafana (tỷ lệ lỗi 403, 401 tăng đột biến).
- **Hành động**:
  - Security Officer mở dashboard `/security` hoặc gọi API `/api/v1/security/alerts`.
  - Chuyển trạng thái Alert từ `NEW` sang `INVESTIGATING`.

### Giai Đoạn 2: Cô Lập Tức Thì (Containment)
Mục tiêu là chặn đứng ngay thiệt hại mà không làm mất dấu vết điều tra:
1. **Cô lập phiên người dùng (Account Isolation)**:
   - Nếu phát hiện nghi ngờ xâm nhập tài khoản:
     ```http
     POST /api/v1/auth/sessions/revoke-user
     Content-Type: application/json
     { "targetUserId": "123", "reason": "Incident response containment SEV-2" }
     ```
   - Chuyển trạng thái người dùng sang `DISABLED` trong `/admin/users`.
2. **Thu hồi quyền truy cập tài liệu khẩn cấp (Grant Revocation)**:
   - Thu hồi grant và hủy toàn bộ phiên mở file đang hoạt động:
     ```http
     POST /api/v1/access-grants/:id/revoke
     Content-Type: application/json
     { "reason": "Emergency containment due to suspected data exfiltration" }
     ```
3. **Cách ly file nghi ngờ (Object Quarantine)**:
   - File độc hại tự động bị chuyển sang bucket `secure-quarantine` và tài liệu giữ trạng thái `DRAFT`.

### Giai Đoạn 3: Điều Tra Số & Giám Định Pháp Y (Forensics & Analysis)
1. **Kiểm tra tính toàn vẹn của Audit Trail**:
   - Chạy xác minh chuỗi HMAC qua `AuditVerifierService`:
     ```bash
     pnpm --filter @sda/api test apps/api/test/audit-trail.test.mjs
     ```
   - Xác định sequence và partition nếu phát hiện vi phạm tính toàn vẹn (`AUDIT_VIOLATION_DETECTED`).
2. **Truy vết rò rỉ tài liệu qua Watermark Forensics**:
   - Nếu phát hiện bản chụp tài liệu rò rỉ ra ngoài có watermark:
   - Nhập mã token (`WM-...`) vào công cụ tra cứu `/security/trace`:
     ```http
     POST /api/v1/watermarks/trace
     Content-Type: application/json
     { "token": "WM-7a9f8e..." }
     ```
   - Trích xuất: User ID tải, Session ID, IP, thiết bị, thời điểm tải chính xác đến mili-giây.

### Giai Đoạn 4: Triệt Tiêu & Khắc Phục (Eradication & Recovery)
1. Thực hiện xoay vòng khóa theo [Key Rotation Runbook](KEY_ROTATION.md) nếu nghi ngờ lộ secret.
2. Cập nhật rule ClamAV hoặc mở rộng danh sách mẫu nhận diện mã độc.
3. Vá lỗ hổng mã nguồn (nếu có), bổ sung regression test bắt buộc.
4. Mở lại quyền truy cập cho người dùng hợp lệ sau khi đặt lại mật khẩu và đăng ký lại TOTP MFA.

### Giai Đoạn 5: Báo Cáo Sau Sự Cố (Post-Incident Review & SoD)
- **Nguyên tắc Phân tách nhiệm vụ (SoD)**:
  - Security Officer tạo `incident_reports` và thêm các `incident_actions`.
  - Cập nhật ghi chú xử lý bắt buộc `resolutionNote` khi đóng cảnh báo sang `RESOLVED`.
  - Auditor kiểm tra độc lập toàn bộ quá trình xử lý sự cố ở chế độ Read-only.
- **Biên soạn Báo Cáo Sự Cố (Post-Mortem)**:
  - Nguyên nhân gốc rễ (Root Cause Analysis - RCA).
  - Tác động thực tế (Impact Assessment).
  - Dòng thời gian sự kiện (Timeline).
  - Các biện pháp phòng ngừa dài hạn.
