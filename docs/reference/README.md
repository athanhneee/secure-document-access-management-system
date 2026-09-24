# Tài liệu tham chiếu nguyên bản

Năm file dưới đây được sao chép nguyên byte từ thư mục làm việc `D:\PTVTKHT` khi khởi tạo repository ngày 2026-09-13. Không chỉnh định dạng, đổi xuống dòng hoặc sửa nội dung các bản gốc. SHA-256 được tính trên bytes của file; `.gitattributes` và cấu hình formatter phải giữ nguyên các file này.

| File | Vai trò | SHA-256 |
| --- | --- | --- |
| [20_prompt_A_Z_secure_document_access_system.md](20_prompt_A_Z_secure_document_access_system.md) | Lộ trình 20 giai đoạn, phạm vi và yêu cầu kỹ thuật/nghiệp vụ được cung cấp | `87E08546776E454630625BFE5B41D510CE6C2DE6F20BFC589649932991458E8E` |
| [database_secure_document_system.sql](database_secure_document_system.sql) | Thiết kế vật lý PostgreSQL: 31 bảng, enum, quan hệ, ràng buộc, index và trigger | `9DF2F049C8AF410C13C41842320952A58F49CAAB0302112DBF3BCE44C377C4AB` |
| [database_secure_document_system.dbml](database_secure_document_system.dbml) | Mô hình sơ đồ của cùng 31 bảng | `A5C3C702193939208AA65BF10FA297211DC3EFB8F298CFB6061E3CC9CDC11F56` |
| [usecase_secure_document_system.puml](usecase_secure_document_system.puml) | Năm tác nhân, 30 use case và quan hệ include/extend | `145D7C29786E010938874606CF9C455B8DAA4B45D9C62E8FEE482CC27F78A0F4` |
| [AGENTS.original.md](AGENTS.original.md) | Quy tắc làm việc và an toàn dữ liệu ban đầu; bản thực thi trong repo là `../../AGENTS.md` | `48AED9843FB7C2603B78D7673AFC6A22BA7CCEC00B72645B66D33EDE30C0A267` |

## Phạm vi nguồn sự thật

Đây là bằng chứng nguồn nghiệp vụ được cung cấp. [Yêu cầu dẫn xuất](../01-requirements.md), [quy tắc dẫn xuất](../03-business-rules.md) và [bối cảnh dự án](../PROJECT_CONTEXT.md) giúp đọc và truy vết; chúng không được âm thầm tạo yêu cầu mới hay sửa nghĩa tài liệu gốc. Nếu phát hiện mâu thuẫn, ghi vào [decision log](../decision-log.md) trước khi thay đổi nghiệp vụ hoặc schema.

File `Bao_cao_giua_ky_He_thong_quan_ly_truy_cap_tai_lieu_mat.docx` được bộ prompt nhắc đến nhưng không hiện diện trong đầu vào. Không có bản định nghĩa nguyên văn `FR01–FR20`, `BR01–BR20` hoặc NFR định lượng. Hai mươi prompt là các giai đoạn triển khai, không phải hai mươi quy tắc nghiệp vụ. Vì vậy các quy tắc tổng hợp mang mã `D-BR01–D-BR20`; chúng chưa phải bản đối chiếu đã xác nhận với báo cáo còn thiếu.

SQL và DBML có cùng tập 31 tên bảng. DBML là bản lược đồ, dùng `timestamp`, `json`, `varchar` ở những nơi SQL dùng `TIMESTAMPTZ`, `JSONB`, `INET` và không mô tả đầy đủ CHECK, partial index, index hay trigger. Khi cần dựng database, dùng SQL để bảo toàn chi tiết vật lý; không tái tạo schema chỉ từ DBML.

Các mục tiêu phiên bản trong bộ prompt là định hướng tại thời điểm tác giả soạn. Phiên bản thực tế phải được xác minh từ nguồn phát hành/registry chính thức và ghi quyết định riêng. Bootstrap chỉ thực hiện Prompt 01; các prompt còn lại là lộ trình, không phải bằng chứng chức năng đã tồn tại.
