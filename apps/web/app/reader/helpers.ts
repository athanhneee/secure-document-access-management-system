import type { ClassificationCode } from '@/components/classification-badge';
import type {
  DiscoverableDoc,
  MyGrantedDoc,
  ReaderDocumentApiDto,
  ReaderGrantApiDto,
} from './types';

/**
 * Thuật toán: Ánh xạ Mã Mức Mật sang Thứ Bậc Bell-LaPadula (`rankFromCode`)
 * Chuẩn hóa mã mức độ mật về thang số nguyên đơn điệu `0..4` khớp chính sách CSDL (`UNCLASSIFIED/PUBLIC: 0`, `INTERNAL/RESTRICTED: 1`, `CONFIDENTIAL: 2`, `SECRET: 3`, `TOP_SECRET: 4`) trong `O(1)`.
 */
export function rankFromCode(code?: string | null): number {
  switch ((code ?? '').trim().toUpperCase()) {
    case 'UNCLASSIFIED':
    case 'PUBLIC':
      return 0;
    case 'INTERNAL':
    case 'RESTRICTED':
      return 1;
    case 'CONFIDENTIAL':
      return 2;
    case 'SECRET':
      return 3;
    case 'TOP_SECRET':
      return 4;
    default:
      return 1;
  }
}

/**
 * Thuật toán: Suy diễn Mã Mức Mật Chuẩn từ Nhãn Tên Tiếng Việt/Tiếng Anh (`deriveClassificationCodeFromName`)
 * Chuẩn hóa chuỗi tên mức mật và đối sánh theo thứ tự ưu tiên từ cụm đặc thù (`tuyệt mật`, `tối mật`, `không mật`) trước `mật` nhằm ngăn khớp nhầm chuỗi con trong `O(1)`.
 */
export function deriveClassificationCodeFromName(
  name?: string | null,
): ClassificationCode | undefined {
  if (!name) return undefined;
  const norm = name.trim().toLowerCase();
  if (!norm) return undefined;
  if (norm.includes('tuyệt mật') || norm.includes('top secret') || norm === 'top_secret') {
    return 'TOP_SECRET';
  }
  if (norm.includes('tối mật') || norm.includes('secret')) {
    return 'SECRET';
  }
  if (
    norm.includes('không mật') ||
    norm.includes('công khai') ||
    norm.includes('unclassified') ||
    norm === 'public'
  ) {
    return 'UNCLASSIFIED';
  }
  if (
    norm.includes('nội bộ') ||
    norm.includes('hạn chế') ||
    norm.includes('internal') ||
    norm.includes('restricted')
  ) {
    return 'INTERNAL';
  }
  if (norm.includes('mật') || norm.includes('confidential')) {
    return 'CONFIDENTIAL';
  }
  return undefined;
}

/**
 * Thuật toán: Ánh xạ Siêu dữ liệu Danh mục Khám phá Không Rò rỉ (`mapReaderDocumentDto`)
 * Chuẩn hóa trường phẳng từ `GET /api/v1/documents` và suy diễn `allowDownload` theo bậc mật `<= 2` (`UNCLASSIFIED`, `INTERNAL`, `CONFIDENTIAL` cho phép tải; `SECRET`, `TOP_SECRET` cấm tải) trong `O(1)`.
 */
export function mapReaderDocumentDto(d: ReaderDocumentApiDto): DiscoverableDoc {
  // CONFLICT-RESOLVED: Đọc trường phẳng classificationLevelCode/departmentName và suy diễn allowDownload theo bậc mật <= 2 thay vì mặc định false.
  const clsCode = (d.classificationLevelCode ||
    d.classification?.code ||
    d.classificationCode ||
    deriveClassificationCodeFromName(d.classificationLevelName) ||
    'UNCLASSIFIED') as ClassificationCode;
  const clsRank = d.classification?.rank ?? rankFromCode(clsCode);

  return {
    id: d.id,
    title: d.title || 'Tài liệu không tên',
    documentCode: d.documentCode || d.document_code,
    classificationCode: clsCode,
    classificationRank: clsRank,
    departmentName: d.departmentName || d.department?.name || '—',
    allowDownload: d.allowDownload ?? d.classification?.allowDownload ?? clsRank <= 2,
    hasAccess: false,
  };
}

/**
 * Thuật toán: Kiểm định Hiệu lực Thời gian Thực Giấy phép Người đọc (`isActiveReaderGrant`)
 * Đánh giá đồng thời trạng thái giấy phép `ACTIVE`, trạng thái tài liệu `ACTIVE` và khoảng nửa mở `[validFrom, validUntil)` tại mốc `nowMs` trong `O(1)`.
 */
export function isActiveReaderGrant(g: ReaderGrantApiDto, nowMs: number = Date.now()): boolean {
  if ((g.grantStatus ?? g.status ?? 'ACTIVE') !== 'ACTIVE') {
    return false;
  }
  if ((g.document?.status ?? 'ACTIVE') !== 'ACTIVE') {
    return false;
  }
  if (g.validFrom !== undefined) {
    const fromMs = Date.parse(g.validFrom);
    if (Number.isNaN(fromMs) || fromMs > nowMs) {
      return false;
    }
  }
  if (g.validUntil !== undefined) {
    const untilMs = Date.parse(g.validUntil);
    if (Number.isNaN(untilMs) || untilMs <= nowMs) {
      return false;
    }
  }
  return true;
}

/**
 * Thuật toán: Chiếu Bản ghi Giấy phép Đang Hiệu lực sang Mô hình Hiển thị (`mapReaderGrantDto`)
 * Làm phẳng DTO lồng của `GET /api/v1/documents/my-grants` mà không sinh khóa giả trùng lặp, đồng thời chuẩn hóa tập quyền và cờ `allowDownload` trong `O(1)`.
 */
export function mapReaderGrantDto(g: ReaderGrantApiDto, index = 0): MyGrantedDoc {
  // CONFLICT-RESOLVED: Ánh xạ chuẩn grantId, document.id, classificationLevelName và chính sách tải theo bậc mật <= 2, loại bỏ hằng giả 'grant-id'/'doc-id'.
  const documentId = g.document?.id || g.documentId || '';
  const id =
    g.grantId || g.id || (documentId ? `${documentId}:${g.validFrom || index}` : `grant-${index}`);
  const clsCode = (g.document?.classificationLevelCode ||
    g.classificationCode ||
    g.document?.classificationCode ||
    deriveClassificationCodeFromName(g.document?.classificationLevelName) ||
    'INTERNAL') as ClassificationCode;
  const clsRank = rankFromCode(clsCode);
  const rawPerms = (g.permissions ?? []).filter(
    (p): p is 'VIEW' | 'DOWNLOAD' => p === 'VIEW' || p === 'DOWNLOAD',
  );
  const permissions: Array<'VIEW' | 'DOWNLOAD'> = rawPerms.includes('DOWNLOAD')
    ? ['VIEW', 'DOWNLOAD']
    : rawPerms.length > 0
      ? rawPerms
      : ['VIEW'];

  return {
    id,
    documentId,
    title: g.document?.title || g.documentTitle || g.title || 'Tài liệu đã cấp quyền',
    documentCode: g.document?.documentCode || g.documentCode,
    classificationCode: clsCode,
    permissions,
    validUntil: g.validUntil || '—',
    allowDownload: g.document?.allowDownload ?? g.allowDownload ?? clsRank <= 2,
  };
}

/**
 * Thuật toán: Lọc Đa Tiêu chí Danh mục Tài liệu Khám phá (`filterDiscoverableDocs`)
 * Kết hợp đối sánh chuỗi con không phân biệt hoa thường với bộ lọc mức mật (đồng nhất bí danh `INTERNAL` và `RESTRICTED`) trong `O(N * M)`.
 */
export function filterDiscoverableDocs(
  docs: DiscoverableDoc[],
  searchQuery: string,
  selectedClassification: string,
): DiscoverableDoc[] {
  const q = searchQuery.toLowerCase();
  const isInternalTier = (code: string) => code === 'INTERNAL' || code === 'RESTRICTED';

  return docs.filter((doc) => {
    const matchesSearch =
      doc.title.toLowerCase().includes(q) ||
      Boolean(doc.documentCode && doc.documentCode.toLowerCase().includes(q));
    // CONFLICT-RESOLVED: Coi INTERNAL và RESTRICTED tương đương khi lọc mức Nội bộ để khớp mã chuẩn CSDL.
    const matchesClass =
      selectedClassification === 'ALL' ||
      doc.classificationCode === selectedClassification ||
      (isInternalTier(selectedClassification) && isInternalTier(doc.classificationCode));
    return matchesSearch && matchesClass;
  });
}

/**
 * Thuật toán: Tính Số Ngày Sử dụng Yêu cầu (`computeRequestSpanDays`)
 * Chuyển hiệu hai mốc ISO sang số nguyên dương tối thiểu 1 ngày trong `O(1)`.
 */
export function computeRequestSpanDays(requestedFrom: string, requestedUntil: string): number {
  return Math.max(
    1,
    Math.round((new Date(requestedUntil).getTime() - new Date(requestedFrom).getTime()) / 86400000),
  );
}

/**
 * Thuật toán: Dựng Khung Thời gian Hiệu lực ISO-8601 (`buildRequestWindowIso`)
 * Sinh cặp mốc `fromIso`/`untilIso` từ đầu vào tùy chỉnh hoặc độ lệch ngày đặt sẵn trong `O(1)`.
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
 * Thuật toán: Kích hoạt Tải Tệp PDF Gắn Thủy vân & Thu hồi Tức thời Object URL (`triggerWatermarkedDownload`)
 * Tạo thẻ neo tạm thời để lưu luồng Blob đã đóng dấu thủy vân và thu hồi URL bộ nhớ ngay sau thao tác nhấp.
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
