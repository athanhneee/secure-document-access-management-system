-- Migration: document_search_indexes
-- Prompt 10: Add pg_trgm extension and GIN indexes for authorization-aware document search
--
-- Thuật toán tổng quan migration:
-- Tăng tốc tìm kiếm tài liệu có nhận thức phân quyền (Authorization-Aware Document Search) không rò rỉ dữ liệu mật:
-- kết hợp chỉ mục đảo GIN bộ ba ký tự (`pg_trgm` trigram) cho khớp mờ/chuỗi con, chỉ mục toàn văn `tsvector` cấu hình `'simple'`
-- đa ngôn ngữ (hỗ trợ tiếng Việt), và các chỉ mục từng phần (Partial Index) lọc sẵn trạng thái hiệu lực.

-- Enable pg_trgm extension (non-superuser safe, available by default in PostgreSQL 15+)
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- Thuật toán: Chỉ mục đảo GIN Trigram (`gin_trgm_ops`) phân rã tiêu đề `title` thành các bộ 3 ký tự liên tiếp,
-- cho phép truy vấn khớp mờ (`ILIKE`, `%`, `<->`) đạt độ phức tạp dưới tuyến tính thay vì quét tuần tự bảng.
-- GIN trigram index for fuzzy/partial matching on title
CREATE INDEX IF NOT EXISTS idx_documents_title_trgm
  ON documents USING gin (title gin_trgm_ops);

-- Thuật toán: Chỉ mục đảo GIN Trigram trên mã tài liệu `document_code` tối ưu tra cứu nhanh theo tiền tố hoặc mảnh mã hiệu.
-- GIN trigram index for document_code
CREATE INDEX IF NOT EXISTS idx_documents_code_trgm
  ON documents USING gin (document_code gin_trgm_ops);

-- Thuật toán: Chỉ mục tìm kiếm toàn văn GIN trên biểu thức vector từ vựng `to_tsvector('simple', ...)` hợp nhất `title`, `description` và `document_code`;
-- dùng từ điển `'simple'` giữ nguyên hình thái từ tiếng Việt không bị cắt gốc sai như bộ stemmer tiếng Anh.
-- Full-text search index using 'simple' config (language-neutral, supports Vietnamese characters)
CREATE INDEX IF NOT EXISTS idx_documents_fts
  ON documents USING gin (
    to_tsvector('simple', coalesce(title, '') || ' ' || coalesce(description, '') || ' ' || coalesce(document_code, ''))
  );

-- Thuật toán: Chỉ mục B-Tree từng phần (Partial Composite Index) loại bỏ sẵn các tài liệu đã xóa mềm (`status NOT IN ('DELETED')`),
-- thu gọn kích thước cây chỉ mục khi lọc cờ khám phá `discoverable` trong truy vấn danh mục.
-- Composite index for authorization-filtered search (discoverable + status)
CREATE INDEX IF NOT EXISTS idx_documents_discoverable_status
  ON documents (discoverable, status) WHERE status NOT IN ('DELETED');

-- Thuật toán: Chỉ mục bao phủ từng phần (Covering Partial Index) chỉ lập chỉ mục trên các quyền `status = 'ACTIVE'`,
-- tăng tốc phép kết nối kiểm tra quyền hiệu lực thời gian (`valid_from`, `valid_until`) ngay trong bước lọc tìm kiếm.
-- Index on access_grants for efficient grant lookup during search
CREATE INDEX IF NOT EXISTS idx_access_grants_doc_user_active
  ON access_grants (document_id, principal_user_id, status, valid_from, valid_until)
  WHERE status = 'ACTIVE';
