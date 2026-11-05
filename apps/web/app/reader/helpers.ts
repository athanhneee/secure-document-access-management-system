import type { ClassificationCode } from '@/components/classification-badge';
import type {
  DiscoverableDoc,
  MyGrantedDoc,
  ReaderDocumentApiDto,
  ReaderGrantApiDto,
} from './types';

/**
 * Algorithm: Zero-IDOR Catalog Metadata Mapper
 * Normalizes discoverable document metadata records while enforcing safe fallback defaults
 * for classification level, rank, and offline download restrictions.
 * Time Complexity: O(1) per record | Space Complexity: O(1)
 */
export function mapReaderDocumentDto(d: ReaderDocumentApiDto): DiscoverableDoc {
  return {
    id: d.id,
    title: d.title || 'Tài liệu không tên',
    documentCode: d.documentCode || d.document_code,
    classificationCode: (d.classification?.code ||
      d.classificationCode ||
      'UNCLASSIFIED') as ClassificationCode,
    classificationRank: d.classification?.rank ?? 1,
    departmentName: d.department?.name || '—',
    allowDownload: d.allowDownload ?? false,
    hasAccess: false,
  };
}

/**
 * Algorithm: Active Reader Grant Projector
 * Flattens nested document grant DTO fields into a uniform granted-document view model.
 * Time Complexity: O(1) per record | Space Complexity: O(1)
 */
export function mapReaderGrantDto(g: ReaderGrantApiDto): MyGrantedDoc {
  return {
    id: g.id || g.documentId || 'grant-id',
    documentId: g.documentId || g.id || 'doc-id',
    title: g.title || g.document?.title || 'Tài liệu đã cấp quyền',
    documentCode: g.documentCode || g.document?.documentCode,
    classificationCode: (g.classificationCode ||
      g.document?.classificationCode ||
      'UNCLASSIFIED') as ClassificationCode,
    permissions: g.permissions || ['VIEW'],
    validUntil: g.validUntil || '—',
    allowDownload: g.allowDownload ?? false,
  };
}

/**
 * Thuật toán: Lọc Đa Tiêu chí Danh mục Tài liệu Khám phá (`filterDiscoverableDocs`)
 * Mục đích: Kết hợp tìm kiếm chuỗi con không phân biệt hoa thường trên tiêu đề/mã tài liệu với bộ lọc phân diện cấp độ mật.
 * Cơ chế hoạt động: Chuẩn hóa từ khóa về chữ thường và đánh giá phép hội logic `matchesSearch && matchesClass` trong thời gian `O(N * M)`.
 */
export function filterDiscoverableDocs(
  docs: DiscoverableDoc[],
  searchQuery: string,
  selectedClassification: string,
): DiscoverableDoc[] {
  const q = searchQuery.toLowerCase();
  return docs.filter((doc) => {
    const matchesSearch =
      doc.title.toLowerCase().includes(q) ||
      (doc.documentCode && doc.documentCode.toLowerCase().includes(q));
    const matchesClass =
      selectedClassification === 'ALL' || doc.classificationCode === selectedClassification;
    return matchesSearch && matchesClass;
  });
}

/**
 * Algorithm: Request Duration Day Span Calculator
 * Computes positive integer day count (>= 1) between ISO start and end timestamps.
 * Time Complexity: O(1) | Space Complexity: O(1)
 */
export function computeRequestSpanDays(requestedFrom: string, requestedUntil: string): number {
  return Math.max(
    1,
    Math.round((new Date(requestedUntil).getTime() - new Date(requestedFrom).getTime()) / 86400000),
  );
}

/**
 * Resolves ISO validity timestamps from either explicit custom datetime inputs or a preset day offset.
 */
export function buildRequestWindowIso(
  isCustomDuration: boolean,
  customRequestedFrom: string,
  customRequestedUntil: string,
  requestDurationDays: number,
): { fromIso: string; untilIso: string } {
  if (isCustomDuration && customRequestedFrom && customRequestedUntil) {
    return {
      fromIso: new Date(customRequestedFrom).toISOString(),
      untilIso: new Date(customRequestedUntil).toISOString(),
    };
  }
  const now = new Date();
  return {
    fromIso: now.toISOString(),
    untilIso: new Date(now.getTime() + requestDurationDays * 86400000).toISOString(),
  };
}

/**
 * Saves a watermarked PDF Blob via a temporary anchor element and immediately revokes the Object URL.
 */
export function triggerWatermarkedDownload(blob: Blob, documentCode?: string): void {
  const downloadUrl = window.URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = downloadUrl;
  link.download = `${documentCode || 'DOCUMENT'}_watermarked.pdf`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.URL.revokeObjectURL(downloadUrl);
}
