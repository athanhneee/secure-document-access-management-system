import { ClassificationRank, resolveClassificationRank } from '@sda/contracts';
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

/**
 * Thuật toán: Định dạng Mốc Thời gian Cục bộ Tương thích `datetime-local` (`toLocalISO`)
 */
export function toLocalISO(d: Date): string {
  const pad = (n: number) => n.toString().padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
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

/**
 * Thuật toán: Chuẩn hóa DTO Tài liệu Sở hữu (`mapDocumentDtoToItem`)
 */
export function mapDocumentDtoToItem(d: DocumentApiDto): DocumentItem {
  const clsCode = (d.classificationLevelCode ||
    d.classification?.code ||
    d.classificationCode ||
    'CONFIDENTIAL') as ClassificationCode;
  const clsRank = d.classification?.rank ?? rankFromCode(clsCode);
  const clsAllowDownload =
    d.classification?.allowDownload ?? clsRank <= ClassificationRank.CONFIDENTIAL;
  const deptName = d.departmentName || d.department?.name || d.departments?.name || '—';
  const catName =
    d.businessCategoryName || d.businessCategory?.name || d.business_categories?.name || undefined;

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
      ? `Người dùng #${g.principalUserId}`
      : g.principalRoleId
        ? `Vai trò #${g.principalRoleId}`
        : 'Đối tượng được cấp');

  const normalizedStatus =
    g.status === 'REVOKED' || g.status === 'EXPIRED' ? g.status : ('ACTIVE' as const);

  return {
    id: g.id,
    documentId: g.documentId,
    documentTitle:
      g.document?.title ||
      lookups?.docsById?.get(g.documentId)?.title ||
      'Tài liệu ' + g.documentId.slice(0, 8),
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
 * Thuật toán: Khởi tạo Giá trị Mặc định Trình Tải lên Tài liệu 3 Bước (`resolveUploadWizardDefaults`)
 */
export function resolveUploadWizardDefaults(params: {
  userDepartmentId?: string | number | null | undefined;
  departments: ReadonlyArray<DepartmentLookupItem>;
  businessCategories: ReadonlyArray<BusinessCategoryLookupItem>;
  classificationLevels: ReadonlyArray<ClassificationLevelLookupItem>;
}): { departmentId: number; categoryId: number; classificationId: number } {
  const { userDepartmentId, departments, businessCategories, classificationLevels } = params;
  const parsedUserDept =
    userDepartmentId !== null && userDepartmentId !== undefined && userDepartmentId !== ''
      ? Number(userDepartmentId)
      : NaN;
  const hasValidUserDept = Number.isFinite(parsedUserDept) && parsedUserDept > 0;
  const departmentId = hasValidUserDept
    ? departments.length > 0
      ? (departments.find((d) => d.id === parsedUserDept)?.id ?? departments[0]?.id ?? 1)
      : parsedUserDept
    : (departments[0]?.id ?? 1);

  const categoryId = businessCategories[0]?.id ?? 1;
  const classificationId =
    (classificationLevels.find((l) => l.code === 'CONFIDENTIAL') ?? classificationLevels[0])?.id ??
    3;

  return { departmentId, categoryId, classificationId };
}

/**
 * Thuật toán: Lọc Chuỗi Con Không Phân biệt Hoa thường Tài liệu Sở hữu (`filterOwnerDocuments`)
 */
export function filterOwnerDocuments(
  documents: DocumentItem[],
  searchQuery: string,
): DocumentItem[] {
  const q = searchQuery.toLowerCase();
  return documents.filter(
    (d) =>
      d.title.toLowerCase().includes(q) ||
      Boolean(d.documentCode && d.documentCode.toLowerCase().includes(q)),
  );
}

/**
 * Thuật toán: Tính Khoảng Ngày Hiệu lực Yêu cầu Truy cập (`calculateRequestedDays`)
 */
export function calculateRequestedDays(requestedFrom?: string, requestedUntil?: string): number {
  if (!requestedFrom || !requestedUntil) return 7;
  return Math.max(
    1,
    Math.round((new Date(requestedUntil).getTime() - new Date(requestedFrom).getTime()) / 86400000),
  );
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
  window.URL.revokeObjectURL(downloadUrl);
}
