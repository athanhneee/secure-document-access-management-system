-- Rollback for 20260923120000_document_search_indexes
-- Thuật toán hoàn tác: Gỡ bỏ tuần tự các chỉ mục tìm kiếm mờ Trigram, Full-Text Search và Partial Index của tài liệu/quyền truy cập.
DROP INDEX IF EXISTS public.idx_access_grants_doc_user_active;
DROP INDEX IF EXISTS public.idx_documents_discoverable_status;
DROP INDEX IF EXISTS public.idx_documents_fts;
DROP INDEX IF EXISTS public.idx_documents_code_trgm;
DROP INDEX IF EXISTS public.idx_documents_title_trgm;
