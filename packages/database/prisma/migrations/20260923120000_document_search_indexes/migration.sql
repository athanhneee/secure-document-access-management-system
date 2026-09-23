-- Migration: document_search_indexes
-- Prompt 10: Add pg_trgm extension and GIN indexes for authorization-aware document search

-- Enable pg_trgm extension (non-superuser safe, available by default in PostgreSQL 15+)
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- GIN trigram index for fuzzy/partial matching on title
CREATE INDEX IF NOT EXISTS idx_documents_title_trgm
  ON documents USING gin (title gin_trgm_ops);

-- GIN trigram index for document_code
CREATE INDEX IF NOT EXISTS idx_documents_code_trgm
  ON documents USING gin (document_code gin_trgm_ops);

-- Full-text search index using 'simple' config (language-neutral, supports Vietnamese characters)
CREATE INDEX IF NOT EXISTS idx_documents_fts
  ON documents USING gin (
    to_tsvector('simple', coalesce(title, '') || ' ' || coalesce(description, '') || ' ' || coalesce(document_code, ''))
  );

-- Composite index for authorization-filtered search (discoverable + status)
CREATE INDEX IF NOT EXISTS idx_documents_discoverable_status
  ON documents (discoverable, status) WHERE status NOT IN ('DELETED');

-- Index on access_grants for efficient grant lookup during search
CREATE INDEX IF NOT EXISTS idx_access_grants_doc_user_active
  ON access_grants (document_id, principal_user_id, status, valid_from, valid_until)
  WHERE status = 'ACTIVE';
