import {
  ClassificationRank,
  DEFAULT_GRANT_MAX_DURATION_DAYS,
  formatRetentionDateIso,
  isValidIsoCalendarDate,
  resolveClassificationDefaultViewDays,
  resolveClassificationRank,
} from '@sda/contracts';
import type { ClassificationCode } from '@/components/classification-badge';
import type {
  AccessGrantApiDto,
  AccessGrantItem,
  BusinessCategoryLookupItem,
  ClassificationLevelLookupItem,
  DepartmentLookupItem,
  DocumentApiDto,
  DocumentItem,
  GrantLookupMaps,
  RoleLookupItem,
  UserLookupItem,
} from './types';

export {
  DOCUMENT_CODE_REGEX,
  filterDepartmentsByUploadScope,
  MAX_UPLOAD_FILE_SIZE_BYTES,
  validateDocumentCodeInput,
  validateUploadFileInput,
} from './upload-validation';

/**
 * Thuật toán: Định dạng Mốc Thời gian Cục bộ Tương thích `datetime-local` (`toLocalISO`)
 */
export function toLocalISO(d: Date): string {
  const pad = (n: number) => n.toString().padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/**
 * Thuật toán: Chuẩn hóa Ngày Cục bộ `YYYY-MM-DD` Tương thích `<input type="date">` (`toLocalDateISO`)
 */
export function toLocalDateISO(d: Date = new Date()): string {
  const pad = (n: number) => n.toString().padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

/**
 * Thuật toán: Xác định Ngày Tối thiểu Hợp lệ cho Thời hạn Lưu trữ (`getMinRetentionDate`)
 * Lấy mốc lớn hơn giữa ngày cục bộ và ngày UTC hiện tại để vừa đồng bộ nút "Hôm nay" ở múi giờ dương,
 * vừa tránh lệch ngày bị máy chủ UTC từ chối ở múi giờ âm.
 */
export function getMinRetentionDate(referenceDate: Date = new Date()): string {
  const localToday = toLocalDateISO(referenceDate);
  const utcToday = referenceDate.toISOString().slice(0, 10);
  return localToday >= utcToday ? localToday : utcToday;
}

/**
 * Thuật toán: Định dạng Chuỗi Ngày ISO `YYYY-MM-DD` sang Hiển thị `DD/MM/YYYY` (`formatIsoDateDisplay`)
 */
export function formatIsoDateDisplay(isoDate: string): string {
  const trimmed = isoDate.trim();
  if (!/^\d{4}-\d{2}-\d{2}$/u.test(trimmed)) return trimmed;
  const [year, month, day] = trimmed.split('-');
  return `${day}/${month}/${year}`;
}

/**
 * Thuật toán: Kiểm định Ngày Thời hạn Lưu trữ Ở Biên Giao diện (`validateRetentionDateInput`)
 * Trả về `null` khi để trống hoặc hợp lệ (`>= getMinRetentionDate`); trả về thông báo tiếng Việt nếu không hợp lệ hoặc nằm trong quá khứ.
 */
export function validateRetentionDateInput(
  value: string,
  referenceDate: Date = new Date(),
): string | null {
  const trimmed = value.trim();
  if (!trimmed) return null;
  if (!isValidIsoCalendarDate(trimmed)) {
    return 'Thời hạn lưu trữ bảo mật không hợp lệ.';
  }
  const minDate = getMinRetentionDate(referenceDate);
  if (trimmed < minDate) {
    return `Thời hạn lưu trữ bảo mật không được là ngày trong quá khứ (tối thiểu từ ${formatIsoDateDisplay(minDate)}).`;
  }
  return null;
}

/**
 * Thuật toán: Ánh xạ Mã Mức Mật sang Thứ Bậc Bell-LaPadula Qua Hợp Đồng Chung `@sda/contracts` (`rankFromCode`)
 */
export function rankFromCode(code?: string | null): number {
  const upper = (code ?? '').trim().toUpperCase();
  if (upper === 'PUBLIC') return ClassificationRank.UNCLASSIFIED;
  if (upper === 'RESTRICTED') return ClassificationRank.INTERNAL;
  return resolveClassificationRank(upper) ?? ClassificationRank.CONFIDENTIAL;
}

const DOWNLOAD_PERMITTED_CLASSIFICATION_CODES = new Set([
  'UNCLASSIFIED',
  'PUBLIC',
  'INTERNAL',
  'RESTRICTED',
  'CONFIDENTIAL',
  'CFD',
]);

/**
 * Thuật toán: Suy diễn quyền cho phép tải xuống theo cơ chế Fail-Closed từ mã độ mật (`inferAllowDownloadFromClassificationCode`)
 * Trả về `false` mặc định khi thiếu mã phân loại hoặc thuộc cấp `SECRET` / `TOP_SECRET`.
 */
export function inferAllowDownloadFromClassificationCode(
  classificationCode?: string | null,
): boolean {
  if (!classificationCode) return false;
  return DOWNLOAD_PERMITTED_CLASSIFICATION_CODES.has(classificationCode.trim().toUpperCase());
}

function toOptionalPositiveInt(raw: string | number | null | undefined): number | undefined {
  if (raw === null || raw === undefined || raw === '') return undefined;
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : undefined;
}

function toOptionalNonNegativeInt(raw: string | number | null | undefined): number | undefined {
  if (raw === null || raw === undefined || raw === '') return undefined;
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed >= 0 ? Math.floor(parsed) : undefined;
}

/**
 * Thuật toán: Chuẩn hóa DTO Tài liệu Sở hữu Có Đối Chiếu Danh Mục Nghiệp Vụ & Mức Mật (`mapDocumentDtoToItem`)
 * Mục đích: Kết hợp các trường trực tiếp (`businessCategoryName`, `currentClassification`) với tra cứu chéo từ `businessCategories` và `classificationLevels` theo `id` hoặc `code` để không gán cứng nhãn danh mục giả.
 */
export function mapDocumentDtoToItem(
  d: DocumentApiDto,
  lookups?: {
    businessCategories?: ReadonlyArray<BusinessCategoryLookupItem>;
    classificationLevels?: ReadonlyArray<ClassificationLevelLookupItem>;
  },
): DocumentItem {
  const clsCode = (d.classificationLevelCode ||
    d.currentClassification?.classificationLevelCode ||
    d.classification?.code ||
    d.classificationCode ||
    'CONFIDENTIAL') as ClassificationCode;
  const rawLevelId =
    d.classificationLevelId ??
    d.currentClassification?.classificationLevelId ??
    d.classification?.id ??
    d.classification_level_id;
  const matchedLevel = lookups?.classificationLevels?.find(
    (lvl) => (rawLevelId != null && String(lvl.id) === String(rawLevelId)) || lvl.code === clsCode,
  );
  const clsRank =
    d.currentClassification?.rank ??
    d.classification?.rank ??
    matchedLevel?.rank ??
    rankFromCode(clsCode);
  const clsAllowDownload =
    d.classification?.allowDownload ??
    matchedLevel?.allowDownload ??
    clsRank <= ClassificationRank.CONFIDENTIAL;

  const rawCategoryId =
    d.businessCategoryId ??
    d.business_category_id ??
    d.currentClassification?.businessCategoryId ??
    d.businessCategory?.id ??
    d.business_categories?.id;
  const rawCategoryCode =
    d.businessCategoryCode ??
    d.business_category_code ??
    d.currentClassification?.businessCategoryCode ??
    d.businessCategory?.code ??
    d.business_categories?.code ??
    undefined;
  const matchedCategory = lookups?.businessCategories?.find(
    (cat) =>
      (rawCategoryId != null && String(cat.id) === String(rawCategoryId)) ||
      (rawCategoryCode !== undefined && cat.code === rawCategoryCode),
  );
  const catName =
    d.businessCategoryName ||
    d.business_category_name ||
    d.currentClassification?.businessCategoryName ||
    d.businessCategory?.name ||
    d.business_categories?.name ||
    matchedCategory?.name ||
    undefined;

  return {
    id: d.id,
    title: d.title || 'Tài liệu chưa có tiêu đề',
    description: d.description ?? null,
    documentCode: d.documentCode || d.document_code,
    classificationCode: clsCode,
    classificationRank: clsRank,
    classificationLevelId: toOptionalPositiveInt(rawLevelId ?? matchedLevel?.id),
    businessCategoryId: toOptionalPositiveInt(rawCategoryId ?? matchedCategory?.id),
    businessCategoryCode: rawCategoryCode ?? matchedCategory?.code,
    businessCategoryName: catName,
    status: d.status || 'ACTIVE',
    departmentId: toOptionalPositiveInt(
      d.departmentId ?? d.department_id ?? d.department?.id ?? d.departments?.id,
    ),
    departmentName: d.departmentName || d.department?.name || d.departments?.name || '—',
    allowDownload: d.allowDownload ?? clsAllowDownload,
    retentionUntil: formatRetentionDateIso(d.retentionUntil ?? d.retention_until),
    defaultViewDays: resolveClassificationDefaultViewDays(
      clsCode,
      d.defaultViewDays ?? matchedLevel?.defaultViewDays,
    ),
    currentVersionNo:
      toOptionalPositiveInt(d.currentVersionNo ?? d.currentVersion?.versionNo) ??
      toOptionalPositiveInt(d.versionCount) ??
      (Array.isArray(d.versions) && d.versions.length > 0 ? d.versions.length : 1),
    versionCount:
      toOptionalNonNegativeInt(d.versionCount) ??
      (Array.isArray(d.versions) ? d.versions.length : undefined) ??
      toOptionalPositiveInt(d.currentVersionNo ?? d.currentVersion?.versionNo) ??
      1,
    createdAt: d.createdAt || d.created_at || new Date().toISOString(),
  };
}

/**
 * Thuật toán: Xây dựng Bảng Băm Tra cứu Nhanh Tên Tài liệu & Đối tượng Cấp quyền (`buildGrantLookupMaps`)
 */
export function buildGrantLookupMaps(
  docs: ReadonlyArray<Pick<DocumentItem, 'id' | 'title'>>,
  users: ReadonlyArray<Pick<UserLookupItem, 'id' | 'fullName' | 'username'>>,
  roles: ReadonlyArray<Pick<RoleLookupItem, 'id' | 'name' | 'code'>>,
): GrantLookupMaps {
  return {
    docsById: new Map(docs.map((d) => [String(d.id), d])),
    usersById: new Map(users.map((u) => [String(u.id), u])),
    rolesById: new Map(roles.map((r) => [String(r.id), r])),
  };
}

/**
 * Thuật toán: Chuẩn hóa DTO Giấy phép Truy cập Có Đối chiếu Danh mục (`mapGrantDtoToItem`)
 */
export function mapGrantDtoToItem(
  g: AccessGrantApiDto,
  lookups?: GrantLookupMaps,
): AccessGrantItem {
  const matchedUser =
    g.principalUserId !== undefined && g.principalUserId !== null
      ? lookups?.usersById?.get(String(g.principalUserId))
      : undefined;
  const matchedRole =
    g.principalRoleId !== undefined && g.principalRoleId !== null
      ? lookups?.rolesById?.get(String(g.principalRoleId))
      : undefined;

  const principalName =
    g.principalUser?.fullName ||
    matchedUser?.fullName ||
    g.principalUser?.username ||
    matchedUser?.username ||
    g.principalRole?.name ||
    matchedRole?.name ||
    g.principalRole?.code ||
    matchedRole?.code ||
    (g.principalUserId
      ? 'Người dùng nội bộ'
      : g.principalRoleId
        ? 'Nhóm vai trò'
        : 'Đối tượng được cấp');

  const normalizedStatus =
    g.status === 'REVOKED' || g.status === 'EXPIRED' || g.status === 'SUSPENDED'
      ? g.status
      : ('ACTIVE' as const);

  return {
    id: g.id,
    documentId: g.documentId,
    documentTitle:
      g.document?.title || lookups?.docsById?.get(g.documentId)?.title || 'Tài liệu được cấp quyền',
    principalType: g.principalType === 'ROLE' ? 'ROLE' : 'USER',
    principalName,
    permissions: g.permissions && g.permissions.length > 0 ? g.permissions : ['VIEW'],
    validFrom: g.validFrom || new Date().toISOString(),
    validUntil: g.validUntil || new Date(Date.now() + 7 * 86400000).toISOString(),
    status: normalizedStatus,
    version: g.version || 0,
  };
}

/**
 * Thuật toán: Mở rộng Tập Quyền Cấp phát Bao hàm Quyền Xem (`expandGrantPermissions`)
 */
export function expandGrantPermissions(
  selected: ReadonlyArray<'VIEW' | 'DOWNLOAD'> | 'VIEW' | 'DOWNLOAD',
): Array<'VIEW' | 'DOWNLOAD'> {
  const list = Array.isArray(selected) ? selected : [selected];
  if (list.includes('DOWNLOAD')) return ['VIEW', 'DOWNLOAD'];
  if (list.includes('VIEW')) return ['VIEW'];
  return [];
}

/**
 * Thuật toán: Trích xuất Thông tin Phân trang Nhật ký Kiểm toán (`extractAuditPagination`)
 */
export function extractAuditPagination(res: {
  page?: number;
  totalPages?: number;
  total?: number;
  pagination?: { page?: number; totalPages?: number; total?: number };
}): { page: number; totalPages: number; total: number } {
  return {
    page: res.pagination?.page ?? res.page ?? 1,
    totalPages: res.pagination?.totalPages ?? res.totalPages ?? 1,
    total: res.pagination?.total ?? res.total ?? 0,
  };
}

/**
 * Thuật toán: Kiểm Định Mức Độ Sẵn Sàng Thuộc Tính Chủ Thể Trước Khi Tải Lên Tài Liệu (`evaluateUploadSubjectReadiness`)
 * Mục đích: Xác minh tài khoản chủ sở hữu đã có trạng thái hoạt động, phòng ban trực thuộc và cấp thẩm quyền bảo mật hợp lệ trước khi tải lên tài liệu mới.
 */
export interface UploadSubjectReadiness {
  ready: boolean;
  missingDepartment: boolean;
  missingClearance: boolean;
  inactiveAccount: boolean;
  blockingReason: string | null;
}

export function evaluateUploadSubjectReadiness(params: {
  departmentId?: string | number | null | undefined;
  clearanceRank?: number | null | undefined;
  status?: string | null | undefined;
}): UploadSubjectReadiness {
  const parsedDept =
    params.departmentId !== null && params.departmentId !== undefined && params.departmentId !== ''
      ? Number(params.departmentId)
      : NaN;
  const missingDepartment = !Number.isFinite(parsedDept) || parsedDept <= 0;
  const missingClearance =
    typeof params.clearanceRank !== 'number' ||
    !Number.isFinite(params.clearanceRank) ||
    params.clearanceRank <= 0;
  const normalizedStatus = (params.status ?? 'ACTIVE').trim().toUpperCase();
  const inactiveAccount = normalizedStatus !== 'ACTIVE';

  if (inactiveAccount) {
    return {
      ready: false,
      missingDepartment,
      missingClearance,
      inactiveAccount: true,
      blockingReason:
        'Tài khoản hiện không ở trạng thái hoạt động nên chưa thể tải lên tài liệu mới. Vui lòng liên hệ quản trị viên.',
    };
  }

  if (missingDepartment && missingClearance) {
    return {
      ready: false,
      missingDepartment: true,
      missingClearance: true,
      inactiveAccount: false,
      blockingReason:
        'Tài khoản chưa được gán phòng ban trực thuộc và cấp thẩm quyền bảo mật nên chưa thể tải lên tài liệu mới. Vui lòng liên hệ quản trị viên để cập nhật.',
    };
  }

  if (missingDepartment) {
    return {
      ready: false,
      missingDepartment: true,
      missingClearance: false,
      inactiveAccount: false,
      blockingReason:
        'Tài khoản chưa được gán phòng ban trực thuộc nên chưa thể tải lên tài liệu mới. Vui lòng liên hệ quản trị viên để cập nhật.',
    };
  }

  if (missingClearance) {
    return {
      ready: false,
      missingDepartment: false,
      missingClearance: true,
      inactiveAccount: false,
      blockingReason:
        'Tài khoản chưa được cấp thẩm quyền bảo mật nên chưa thể tải lên tài liệu mới. Vui lòng liên hệ quản trị viên để cập nhật.',
    };
  }

  return {
    ready: true,
    missingDepartment: false,
    missingClearance: false,
    inactiveAccount: false,
    blockingReason: null,
  };
}

/**
 * Thuật toán: Kiểm Định Nhanh Mức Mật Cho Phép Theo Trần Thẩm Tra Bell-LaPadula (`isClassificationAllowedForClearance`)
 * Mục đích: Xác định liệu bậc phân loại mật `levelRank` có nằm trong phạm vi `userClearanceRank` của tài khoản hay không (`levelRank <= userClearanceRank`).
 */
export function isClassificationAllowedForClearance(
  levelRank: number,
  userClearanceRank?: number | null,
): boolean {
  if (typeof userClearanceRank !== 'number' || !Number.isFinite(userClearanceRank)) {
    return true;
  }
  return levelRank <= userClearanceRank;
}

/**
 * Thuật toán: Khởi tạo Giá trị Mặc định Trình Tải lên Tài liệu 3 Bước (`resolveUploadWizardDefaults`)
 */
export function resolveUploadWizardDefaults(params: {
  userDepartmentId?: string | number | null | undefined;
  userClearanceRank?: number | null | undefined;
  departments: ReadonlyArray<DepartmentLookupItem>;
  businessCategories: ReadonlyArray<BusinessCategoryLookupItem>;
  classificationLevels: ReadonlyArray<ClassificationLevelLookupItem>;
}): { departmentId: number; categoryId: number; classificationId: number } {
  const {
    userDepartmentId,
    userClearanceRank,
    departments,
    businessCategories,
    classificationLevels,
  } = params;
  const parsedUserDept =
    userDepartmentId !== null && userDepartmentId !== undefined && userDepartmentId !== ''
      ? Number(userDepartmentId)
      : NaN;
  const hasValidUserDept = Number.isFinite(parsedUserDept) && parsedUserDept > 0;
  const matchedDept = hasValidUserDept
    ? departments.find((d) => String(d.id) === String(parsedUserDept))
    : undefined;
  const departmentId = Number(
    matchedDept?.id ??
      (hasValidUserDept && departments.length === 0 ? parsedUserDept : (departments[0]?.id ?? 1)),
  );

  const categoryId = Number(businessCategories[0]?.id ?? 1);
  const permittedLevels =
    typeof userClearanceRank === 'number' && Number.isFinite(userClearanceRank)
      ? classificationLevels.filter((l) => l.rank <= userClearanceRank)
      : classificationLevels;
  const highestPermitted = permittedLevels.reduce<ClassificationLevelLookupItem | undefined>(
    (best, lvl) => (!best || lvl.rank > best.rank ? lvl : best),
    undefined,
  );
  const defaultLevel =
    permittedLevels.find((l) => l.code === 'CONFIDENTIAL') ??
    highestPermitted ??
    classificationLevels.find((l) => l.code === 'CONFIDENTIAL') ??
    classificationLevels[0];
  const classificationId = Number(defaultLevel?.id ?? 3);

  return { departmentId, categoryId, classificationId };
}

/**
 * Thuật toán: Lọc Chuỗi Con Không Phân biệt Hoa thường Tài liệu Sở hữu (`filterOwnerDocuments`)
 */
export function filterOwnerDocuments(
  documents: DocumentItem[],
  searchQuery: string,
): DocumentItem[] {
  const q = searchQuery.trim().toLowerCase();
  if (!q) return documents;
  return documents.filter(
    (d) =>
      d.title.toLowerCase().includes(q) ||
      Boolean(d.documentCode && d.documentCode.toLowerCase().includes(q)),
  );
}

/**
 * Thuật toán: Tính Khoảng Ngày Hiệu lực Yêu cầu Truy cập Đồng Bộ Trần Tối Đa (`calculateRequestedDays`)
 */
export function calculateRequestedDays(
  requestedFrom?: string,
  requestedUntil?: string,
  maxDays: number = DEFAULT_GRANT_MAX_DURATION_DAYS,
): number {
  if (!requestedFrom || !requestedUntil) return Math.min(7, maxDays);
  const diffMs = new Date(requestedUntil).getTime() - new Date(requestedFrom).getTime();
  if (!Number.isFinite(diffMs) || diffMs <= 0) return 1;
  return Math.min(maxDays, Math.max(1, Math.round(diffMs / 86400000)));
}

/**
 * Thuật toán: Tải Xuống Luồng Blob Ngắn hạn & Giải phóng Bộ nhớ (`triggerBlobDownload`)
 */
export function triggerBlobDownload(blob: Blob, filename: string): void {
  const downloadUrl = window.URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = downloadUrl;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => {
    window.URL.revokeObjectURL(downloadUrl);
  }, 15_000);
}
