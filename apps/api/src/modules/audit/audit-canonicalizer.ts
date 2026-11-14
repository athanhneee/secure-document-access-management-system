/**
 * @module AuditCanonicalizer
 * Thuật toán: Tái xuất bộ tuần tự hóa JSON chuẩn tắc tất định theo RFC 8785 (JSON Canonicalization Scheme - JCS)
 * từ `@sda/contracts`, sắp xếp khóa từ điển đệ quy theo mã UTF-16 để băm chuỗi HMAC-SHA256 nhất quán tuyệt đối.
 */
export { canonicalizeJson } from '@sda/contracts';
