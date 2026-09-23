# Chính Sách Bảo Mật (Security Policy)

Hệ thống Quản lý Truy cập Tài liệu Mật (Secure Document Access System) cam kết tuân thủ các tiêu chuẩn an ninh nghiêm ngặt nhất nhằm bảo vệ tài sản thông tin của tổ chức.

---

## 1. Các Phiên Bản Được Hỗ Trợ (Supported Versions)

Chúng tôi chỉ phát hành các bản vá bảo mật cho các phiên bản đang được hỗ trợ tích cực:

| Phiên Bản              | Hỗ Trợ Bảo Mật | Trạng Thái                   |
| :--------------------- | :------------- | :--------------------------- |
| `0.1.x` (Current Main) | Có             | Đang phát triển / Nghiệm thu |
| `< 0.1.0`              | Không          | Không hỗ trợ                 |

---

## 2. Quy Trình Báo Cáo Lỗ Hổng (Reporting a Vulnerability)

Nếu bạn phát hiện một lỗ hổng bảo mật tiềm ẩn trong hệ thống, vui lòng **KHÔNG** công khai thông tin qua GitHub Issues, Pull Requests hoặc các kênh trao đổi mở. Hãy thực hiện theo quy trình Tiết lộ có trách nhiệm (Coordinated Vulnerability Disclosure):

### 2.1 Kênh Liên Hệ

- **Email Khẩn Cấp**: `security@secure-docs.internal` (hoặc mở Private Security Advisory trên GitHub Repository).
- **Mã Hóa PGP**: Khuyến khích mã hóa nội dung báo cáo bằng PGP Key công khai của Security Team (Fingerprint: `A1B2 C3D4 E5F6 7890 1234 5678 9ABC DEF0 1234 5678`).

### 2.2 Thông Tin Cần Cung Cấp

Vui lòng gửi báo cáo chi tiết bao gồm:

1. Mô tả chi tiết lỗ hổng và phạm vi ảnh hưởng (Authentication, ABAC, Upload, Watermark, IDOR...).
2. Bằng chứng khái niệm (Proof-of-Concept / PoC) hoặc các bước tái hiện cụ thể.
3. Đánh giá sơ bộ về mức độ rủi ro (CVSS v3.1 score).
4. Các biện pháp khắc phục hoặc giải pháp tạm thời đề xuất (nếu có).

---

## 3. Cam Kết Thời Gian Phản Hồi (Response SLAs)

Đội ngũ An ninh Thông tin cam kết tuân thủ quy trình xử lý khẩn cấp:

| Giai Đoạn                                 | Thời Gian Mục Tiêu     | Hành Động                                                                                                 |
| :---------------------------------------- | :--------------------- | :-------------------------------------------------------------------------------------------------------- |
| **Xác nhận tiếp nhận (Triage)**           | Trong vòng **24 giờ**  | Phản hồi xác nhận đã nhận báo cáo và chỉ định điều tra viên phụ trách.                                    |
| **Đánh giá & Xác minh (Verification)**    | Trong vòng **48 giờ**  | Tái hiện lỗ hổng trong môi trường cô lập và xác định điểm CVSS chính thức.                                |
| **Bản vá khẩn cấp (Critical Fix)**        | Trong vòng **72 giờ**  | Phát hành bản vá hotfix cho các lỗ hổng Critical / High.                                                  |
| **Bản vá tiêu chuẩn (Standard Fix)**      | Trong vòng **14 ngày** | Đưa vào chu kỳ phát hành thường kỳ cho các lỗ hổng Medium / Low.                                          |
| **Công bố thông tin (Public Disclosure)** | Sau khi vá thành công  | Phối hợp với người báo cáo để ghi nhận đóng góp (Hall of Fame) sau khi bản vá đã được triển khai an toàn. |

---

## 4. Tài Liệu Vận Hành Liên Quan

- [Mô Hình Đe Dọa STRIDE](docs/THREAT_MODEL.md)
- [Quy Trình Xoay Vòng Khóa Bảo Mật (Key Rotation Runbook)](docs/runbooks/KEY_ROTATION.md)
- [Quy Trình Ứng Phó Sự Cố (Incident Response Runbook)](docs/runbooks/INCIDENT_RESPONSE.md)
- [Ma Trận Truy Vết Kiểm Thử (Traceability Matrix)](docs/TRACEABILITY_MATRIX.md)
