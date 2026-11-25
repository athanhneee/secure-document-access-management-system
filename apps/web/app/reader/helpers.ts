import { ClassificationRank, resolveClassificationRank } from '@sda/contracts';
import type { ClassificationCode } from '@/components/classification-badge';
import type { DownloadBlob } from '@/lib/api-client';
import type {
  DiscoverableDoc,
  MyGrantedDoc,
  ReaderDocumentApiDto,
  ReaderGrantApiDto,
} from './types';

/**
 * Thuật toán: Ánh xạ Mã Mức Mật sang Thứ Bậc Bell-LaPadula Qua Hợp Đồng `@sda/contracts` (`rankFromCode`)
 * Chuẩn hóa mã mức độ mật về thang số nguyên đơn điệu `0..4` khớp chính sách CSDL (`UNCLASSIFIED/PUBLIC: 0`, `INTERNAL/RESTRICTED: 1`, `CONFIDENTIAL: 2`, `SECRET: 3`, `TOP_SECRET: 4`) trong `O(1)`.
 */
export function rankFromCode(code?: string | null): number {
  const upper = (code ?? '').trim().toUpperCase();
  if (upper === 'PUBLIC') return ClassificationRank.UNCLASSIFIED;
  if (upper === 'RESTRICTED') return ClassificationRank.INTERNAL;
  return resolveClassificationRank(upper) ?? ClassificationRank.INTERNAL;
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
 * Chuẩn hóa trường phẳng từ `GET /api/v1/documents` (bao gồm `description` và `businessCategoryName`), loại bỏ trường chết `hasAccess` và suy diễn `allowDownload` theo bậc mật `<= 2` trong `O(1)`.
 */
export function mapReaderDocumentDto(d: ReaderDocumentApiDto): DiscoverableDoc {
  // CONFLICT-RESOLVED: Đọc trường phẳng classificationLevelCode/departmentName/description/businessCategoryName và suy diễn allowDownload theo bậc mật <= 2 (V-52, V-53).
  const clsCode = (d.classificationLevelCode ||
    d.classification?.code ||
    d.classificationCode ||
    deriveClassificationCodeFromName(d.classificationLevelName) ||
    'INTERNAL') as ClassificationCode;
  const clsRank = d.classification?.rank ?? rankFromCode(clsCode);

  return {
    id: d.id,
    title: d.title || 'Tài liệu chưa có tiêu đề',
    documentCode: d.documentCode || d.document_code,
    description: d.description ?? null,
    businessCategoryName: d.businessCategoryName ?? null,
    classificationCode: clsCode,
    classificationRank: clsRank,
    departmentName: d.departmentName || d.department?.name || '—',
    allowDownload: d.allowDownload ?? d.classification?.allowDownload ?? clsRank <= 2,
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
 * Làm phẳng DTO lồng của `GET /api/v1/documents/my-grants` kèm nguồn cấp quyền `USER`/`ROLE`, `validFrom`, `grantedAt` và chính sách tải trong `O(1)`.
 */
export function mapReaderGrantDto(g: ReaderGrantApiDto, index = 0): MyGrantedDoc {
  // CONFLICT-RESOLVED: Ánh xạ chuẩn grantId, principalType, roleName, validFrom, grantedAt và chính sách tải theo bậc mật <= 2 (V-43, V-53).
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
    principalType: g.principalType === 'ROLE' ? 'ROLE' : 'USER',
    roleName: g.roleName ?? null,
    validFrom: g.validFrom,
    validUntil: g.validUntil || '—',
    grantedAt: g.grantedAt,
    allowDownload: g.document?.allowDownload ?? g.allowDownload ?? clsRank <= 2,
  };
}

/**
 * Thuật toán: Hợp Nhất Nhãn Quyền Truy Cập Không Mâu Thuẫn Cho Bảng Quyền Người Đọc (`formatReaderGrantPermissionSummary`, V-27)
 * Trả duy nhất 1 nhãn thống nhất (`Xem & Tải về` khi và chỉ khi đồng thời thỏa grant `DOWNLOAD`, `allowDownload` và quyền RBAC `DOCUMENT:DOWNLOAD`; ngược lại `Chỉ xem`).
 */
export function formatReaderGrantPermissionSummary(
  permissions: readonly ('VIEW' | 'DOWNLOAD')[],
  allowDownload: boolean,
  canDownloadDocument: boolean,
): { label: 'Xem & Tải về' | 'Chỉ xem'; canDownload: boolean } {
  const canDownload = permissions.includes('DOWNLOAD') && allowDownload && canDownloadDocument;
  return {
    label: canDownload ? 'Xem & Tải về' : 'Chỉ xem',
    canDownload,
  };
}

/**
 * Thuật toán: Phân Loại Mức Độ Khẩn Cấp Hạn Hiệu Lực Giấy Phép (`resolveGrantExpiryUrgency`, V-31)
 * Trả về `danger` (< 24 giờ), `warning` (<= 3 ngày) hoặc `success` (> 3 ngày) thay vì luôn gắn chấm cam cảnh báo.
 */
export function resolveGrantExpiryUrgency(
  validUntil: string | null | undefined,
  nowMs: number = Date.now(),
): 'danger' | 'warning' | 'success' {
  if (!validUntil) return 'warning';
  const untilMs = Date.parse(validUntil);
  if (Number.isNaN(untilMs)) return 'warning';
  const remainingMs = untilMs - nowMs;
  if (remainingMs <= 86_400_000) return 'danger';
  if (remainingMs <= 3 * 86_400_000) return 'warning';
  return 'success';
}

/**
 * Thuật toán: Lọc Đa Tiêu chí Danh mục Tài liệu Khám phá Có Cắt Khoảng Trắng (`filterDiscoverableDocs`, V-38)
 * Kết hợp đối sánh chuỗi con không phân biệt hoa thường trên `title`, `documentCode`, `departmentName`, `description` với bộ lọc mức mật (đồng nhất `INTERNAL` & `RESTRICTED`) trong `O(N * M)`.
 */
export function filterDiscoverableDocs(
  docs: DiscoverableDoc[],
  searchQuery: string,
  selectedClassification: string,
): DiscoverableDoc[] {
  const q = searchQuery.trim().toLowerCase();
  const isInternalTier = (code: string) => code === 'INTERNAL' || code === 'RESTRICTED';

  return docs.filter((doc) => {
    const matchesSearch =
      !q ||
      doc.title.toLowerCase().includes(q) ||
      Boolean(doc.documentCode && doc.documentCode.toLowerCase().includes(q)) ||
      Boolean(doc.departmentName && doc.departmentName.toLowerCase().includes(q)) ||
      Boolean(doc.description && doc.description.toLowerCase().includes(q));
    // CONFLICT-RESOLVED: Coi INTERNAL và RESTRICTED tương đương khi lọc mức Nội bộ để khớp mã chuẩn CSDL.
    const matchesClass =
      selectedClassification === 'ALL' ||
      doc.classificationCode === selectedClassification ||
      (isInternalTier(selectedClassification) && isInternalTier(doc.classificationCode));
    return matchesSearch && matchesClass;
  });
}

/**
 * Thuật toán: Tính Số Ngày Sử dụng Yêu cầu An Toàn Chống `NaN` (`computeRequestSpanDays`, V-46)
 */
export function computeRequestSpanDays(requestedFrom: string, requestedUntil: string): number {
  const fromMs = Date.parse(requestedFrom);
  const untilMs = Date.parse(requestedUntil);
  if (Number.isNaN(fromMs) || Number.isNaN(untilMs) || untilMs <= fromMs) {
    return 0;
  }
  return Math.max(1, Math.round((untilMs - fromMs) / 86_400_000));
}

/**
 * Thuật toán: Định Dạng Thời Lượng Yêu Cầu Chi Tiết Theo Giờ Hoặc Ngày (`formatRequestDurationLabel`, V-46)
 * Hiển thị theo giờ nếu khoảng hiệu lực dưới 24 giờ và trả về chuỗi rỗng nếu mốc thời gian không hợp lệ.
 */
export function formatRequestDurationLabel(
  requestedFrom?: string | null,
  requestedUntil?: string | null,
): string | null {
  if (!requestedFrom || !requestedUntil) return null;
  const fromMs = Date.parse(requestedFrom);
  const untilMs = Date.parse(requestedUntil);
  if (Number.isNaN(fromMs) || Number.isNaN(untilMs) || untilMs <= fromMs) {
    return null;
  }
  const diffHours = (untilMs - fromMs) / 3_600_000;
  if (diffHours < 24) {
    return `${Math.max(1, Math.round(diffHours))} giờ`;
  }
  return `${Math.max(1, Math.round(diffHours / 24))} ngày`;
}

/**
 * Thuật toán: Kiểm Định Khoảng Thời Gian Tùy Chọn Trước Khi Gửi Yêu Cầu (`validateCustomRequestWindow`, V-39)
 */
export function validateCustomRequestWindow(
  isCustomDuration: boolean,
  customRequestedFrom: string,
  customRequestedUntil: string,
  nowMs: number = Date.now(),
): string | null {
  if (!isCustomDuration) return null;
  if (!customRequestedFrom.trim() || !customRequestedUntil.trim()) {
    return 'Vui lòng nhập đầy đủ cả thời điểm bắt đầu và thời điểm kết thúc khi chọn khoảng thời gian tùy chỉnh.';
  }
  const fromDate = new Date(customRequestedFrom);
  const untilDate = new Date(customRequestedUntil);
  if (Number.isNaN(fromDate.getTime()) || Number.isNaN(untilDate.getTime())) {
    return 'Định dạng thời gian tùy chọn không hợp lệ.';
  }
  const PAST_TOLERANCE_MS = 5 * 60_000;
  if (fromDate.getTime() < nowMs - PAST_TOLERANCE_MS) {
    return 'Thời điểm bắt đầu không được nằm trong quá khứ.';
  }
  if (untilDate.getTime() <= fromDate.getTime()) {
    return 'Thời điểm kết thúc phải lớn hơn thời điểm bắt đầu.';
  }
  if (untilDate.getTime() - fromDate.getTime() > 365 * 86_400_000) {
    return 'Khoảng thời gian đề nghị truy cập không được vượt quá 365 ngày.';
  }
  return null;
}

/**
 * Thuật toán: Dựng Khung Thời gian Hiệu lực ISO-8601 An Toàn Chống `RangeError` (`buildRequestWindowIso`, V-39)
 */
export function buildRequestWindowIso(
  isCustomDuration: boolean,
  customRequestedFrom: string,
  customRequestedUntil: string,
  requestDurationDays: number,
): { fromIso: string; untilIso: string } {
  if (isCustomDuration) {
    const validationErr = validateCustomRequestWindow(
      true,
      customRequestedFrom,
      customRequestedUntil,
    );
    if (validationErr) {
      throw new Error(validationErr);
    }
    return {
      fromIso: new Date(customRequestedFrom).toISOString(),
      untilIso: new Date(customRequestedUntil).toISOString(),
    };
  }
  const now = new Date();
  const safeDays = Math.min(365, Math.max(1, Math.round(requestDurationDays || 7)));
  return {
    fromIso: now.toISOString(),
    untilIso: new Date(now.getTime() + safeDays * 86_400_000).toISOString(),
  };
}

/**
 * Thuật toán: Định Dạng Mốc `datetime-local` Địa Phương Cho Thuộc Tính `min` (`formatLocalDateTimeMin`, V-39)
 */
export function formatLocalDateTimeMin(date: Date = new Date()): string {
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

const MIME_EXTENSION_MAP: Readonly<Record<string, string>> = {
  'application/pdf': '.pdf',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document': '.docx',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': '.xlsx',
  'application/vnd.openxmlformats-officedocument.presentationml.presentation': '.pptx',
  'application/msword': '.doc',
  'application/vnd.ms-excel': '.xls',
  'application/vnd.ms-powerpoint': '.ppt',
};

/**
 * Thuật toán: Xác Định Tên Tệp Tải Về Bảo Toàn Đúng Định Dạng Gốc (`resolveSafeDownloadFilename`, V-08)
 */
export function resolveSafeDownloadFilename(
  blob: DownloadBlob | Blob,
  documentCode?: string,
  explicitFilename?: string,
): string {
  const fromHeader = explicitFilename || ('filename' in blob ? blob.filename : undefined);
  if (fromHeader && fromHeader.trim()) {
    return fromHeader.trim().replace(/[\\/:*?"<>|]/g, '_');
  }
  const ext = MIME_EXTENSION_MAP[blob.type.toLowerCase()] ?? '.pdf';
  const base = (documentCode || 'TAI-LIEU').replace(/[\\/:*?"<>|]/g, '_');
  return ext === '.pdf' ? `${base}_bao-mat.pdf` : `${base}${ext}`;
}

/**
 * Thuật toán: Kích hoạt Tải Tệp Đúng Đuôi Định Dạng & Trì Hoãn Thu Hồi Object URL An Toàn Cho Safari/iOS (`triggerWatermarkedDownload`, V-08, V-42)
 */
export function triggerWatermarkedDownload(
  blob: DownloadBlob | Blob,
  documentCode?: string,
  explicitFilename?: string,
): void {
  const downloadUrl = window.URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = downloadUrl;
  link.download = resolveSafeDownloadFilename(blob, documentCode, explicitFilename);
  document.body.appendChild(link);
  link.click();
  link.remove();
  // Trì hoãn thu hồi Object URL 15 giây để Safari/iOS kịp hoàn tất đọc luồng blob mà không bị hủy tải
  window.setTimeout(() => {
    window.URL.revokeObjectURL(downloadUrl);
  }, 15_000);
}
