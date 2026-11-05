import type { ClassificationCode } from '@/components/classification-badge';
import type { AccessGrantApiDto, AccessGrantItem, DocumentApiDto, DocumentItem } from './types';

/**
 * Thuật toán: Định dạng Mốc Thời gian Cục bộ Tương thích `datetime-local` (`toLocalISO`)
 * Mục đích: Biến đổi đối tượng `Date` sang chuỗi `YYYY-MM-DDTHH:mm` theo múi giờ máy trạm mà không bị lệch giờ UTC như `toISOString()`.
 * Cơ chế hoạt động: Đệm số `0` hai chữ số (`padStart(2, '0')`) cho tháng, ngày, giờ, phút trong thời gian `O(1)`.
 */
export function toLocalISO(d: Date): string {
  const pad = (n: number) => n.toString().padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/**
 * Algorithm: Owner Document DTO Normalizer
 * Normalizes heterogeneous snake_case/camelCase document API payloads and derives
 * Bell-LaPadula rank & download-policy defaults when nested classification metadata is partial.
 * Time Complexity: O(1) per record | Space Complexity: O(1)
 */
export function mapDocumentDtoToItem(d: DocumentApiDto): DocumentItem {
  const clsCode = (d.classification?.code ||
    d.classificationCode ||
    'CONFIDENTIAL') as ClassificationCode;
  const clsRank = d.classification?.rank ?? 3;
  const clsAllowDownload = d.classification?.allowDownload ?? clsRank <= 2;
  const deptName = d.department?.name || d.departments?.name;
  const catName = d.businessCategory?.name || d.business_categories?.name;

  return {
    id: d.id,
    title: d.title || 'Tài liệu không tên',
    documentCode: d.documentCode || d.document_code,
    classificationCode: clsCode,
    classificationRank: clsRank,
    classificationLevelId: d.classification?.id ?? d.classification_level_id,
    businessCategoryId: d.business_category_id,
    businessCategoryName: catName,
    status: d.status || 'ACTIVE',
    departmentId: d.department_id,
    departmentName: deptName,
    allowDownload: d.allowDownload ?? clsAllowDownload,
    versionCount: d.versions?.length ?? 1,
    createdAt: d.createdAt || d.created_at || new Date().toISOString(),
  };
}

/**
 * Algorithm: Access Grant DTO Normalizer
 * Projects raw grant records into display-ready grant rows with safe fallback labels
 * and optimistic-concurrency version numbers.
 * Time Complexity: O(1) per record | Space Complexity: O(1)
 */
export function mapGrantDtoToItem(g: AccessGrantApiDto): AccessGrantItem {
  return {
    id: g.id,
    documentId: g.documentId,
    documentTitle: g.document?.title || 'Tài liệu ' + g.documentId.slice(0, 8),
    principalType: g.principalType || 'USER',
    principalName: g.principalUser?.fullName || g.principalRole?.name || 'Đối tượng được cấp',
    permissions: g.permissions || ['VIEW'],
    validFrom: g.validFrom || new Date().toISOString(),
    validUntil: g.validUntil || new Date(Date.now() + 7 * 86400000).toISOString(),
    status: g.status || 'ACTIVE',
    version: g.version || 0,
  };
}

/**
 * Algorithm: Case-Insensitive Document Substring Filter
 * Filters owned documents by matching normalized query against title or document code.
 * Time Complexity: O(N * M) where N is document count and M is title/code length | Space Complexity: O(N)
 */
export function filterOwnerDocuments(
  documents: DocumentItem[],
  searchQuery: string,
): DocumentItem[] {
  const q = searchQuery.toLowerCase();
  return documents.filter(
    (d) =>
      d.title.toLowerCase().includes(q) ||
      (d.documentCode && d.documentCode.toLowerCase().includes(q)),
  );
}

/**
 * Algorithm: Access Request Window Day Span Calculator
 * Computes bounded day count (>= 1 day, default 7 days) from ISO start/end timestamps.
 * Time Complexity: O(1) | Space Complexity: O(1)
 */
export function calculateRequestedDays(requestedFrom?: string, requestedUntil?: string): number {
  if (!requestedFrom || !requestedUntil) {
    return 7;
  }
  return Math.max(
    1,
    Math.round((new Date(requestedUntil).getTime() - new Date(requestedFrom).getTime()) / 86400000),
  );
}

/**
 * Triggers ephemeral Blob download via temporary Object URL and immediately releases memory.
 */
export function triggerBlobDownload(blob: Blob, filename: string): void {
  const downloadUrl = window.URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = downloadUrl;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.URL.revokeObjectURL(downloadUrl);
}
