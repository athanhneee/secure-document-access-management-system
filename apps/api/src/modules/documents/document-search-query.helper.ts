/**
 * @module DocumentSearchQueryHelper
 * Thuật toán: Xây dựng mệnh đề truy vấn tìm kiếm tài liệu tham số hóa 4 nhánh hiển thị (chủ sở hữu, quyền `DISCOVER`
 * phòng ban, cấp quyền `USER`, cấp quyền `ROLE`) kết hợp trần độ mật Bell-LaPadula, tìm kiếm lai FTS + Trigram
 * và phân trang nhìn trước `LIMIT pageSize + 1` chống lộ tổng số bản ghi ẩn.
 */
import { BadRequestException } from '@nestjs/common';
import { type getDatabaseClient, Prisma } from '@sda/database';
import { AppErrorCode, type SearchDocumentsInput } from '@sda/contracts';

export interface SearchResultItem {
  id: string;
  documentCode: string;
  title: string;
  description: string | null;
  status: string;
  departmentName: string;
  classificationLevelName: string | null;
  classificationLevelCode: string | null;
  businessCategoryId: string | null;
  businessCategoryCode: string | null;
  businessCategoryName: string | null;
  allowDownload: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface SearchResult {
  data: SearchResultItem[];
  page: number;
  pageSize: number;
  hasMore: boolean;
}

export interface GrantedDocumentItem {
  grantId: string;
  permissions: string[];
  grantStatus: string;
  validFrom: string;
  validUntil: string;
  grantedAt: string;
  document: {
    id: string;
    documentCode: string;
    title: string;
    status: string;
    classificationLevelName: string | null;
    classificationLevelCode: string | null;
    allowDownload: boolean;
  };
}

export interface GrantedDocumentsResult {
  data: GrantedDocumentItem[];
  page: number;
  pageSize: number;
  hasMore: boolean;
}

const FORBIDDEN_PATTERN = /[*?[\]{}\\^$|]/g;

/**
 * Thuật toán: Làm sạch từ khóa tìm kiếm, chặn vượt quá 200 ký tự và loại bỏ ký tự đại diện biểu thức chính quy.
 */
export function sanitizeSearchQuery(query: string | undefined): string | undefined {
  if (!query) return undefined;
  const trimmed = query.trim();
  if (trimmed.length === 0) return undefined;
  if (trimmed.length > 200) {
    throw new BadRequestException({
      errorCode: AppErrorCode.SEARCH_QUERY_TOO_LONG,
      message: 'Search query must not exceed 200 characters.',
    });
  }
  const cleaned = trimmed.replace(FORBIDDEN_PATTERN, '');
  if (cleaned.length === 0) {
    throw new BadRequestException({
      errorCode: AppErrorCode.SEARCH_QUERY_INVALID,
      message: 'Search query contains only invalid characters.',
    });
  }
  return cleaned;
}

export function resolveSortColumn(sort: string): Prisma.Sql {
  switch (sort) {
    case 'title':
      return Prisma.sql`d."title"`;
    case 'updated_at':
      return Prisma.sql`d."updated_at"`;
    case 'created_at':
    default:
      return Prisma.sql`d."created_at"`;
  }
}

export function resolveGrantSortColumn(sort: string): Prisma.Sql {
  switch (sort) {
    case 'valid_until':
      return Prisma.sql`ag."valid_until"`;
    case 'title':
      return Prisma.sql`d."title"`;
    case 'granted_at':
    default:
      return Prisma.sql`ag."granted_at"`;
  }
}

const DOWNLOAD_PERMITTED_CODES = new Set([
  'PUBLIC',
  'INTERNAL',
  'CONFIDENTIAL',
  'RESTRICTED',
  'CFD',
]);

/**
 * Thuật toán: Suy diễn quyền tải xuống Fail-Closed từ cấu hình phân loại tài liệu (HIGH-08).
 */
export function resolveFailClosedAllowDownload(
  allowDownload: boolean | null | undefined,
  classificationCode: string | null | undefined,
): boolean {
  if (typeof allowDownload === 'boolean') return allowDownload;
  if (!classificationCode) return false;
  return DOWNLOAD_PERMITTED_CODES.has(classificationCode.toUpperCase());
}

/**
 * Thuật toán: Truy vấn thứ bậc độ mật Bell-LaPadula (`CLEARANCE_LEVEL`) cao nhất còn hiệu lực của chủ thể (mặc định Fail-Closed bằng `0`).
 */
export async function queryUserClearanceRank(
  database: ReturnType<typeof getDatabaseClient>,
  userId: bigint,
): Promise<number> {
  if (typeof database?.userAttributeAssignment?.findFirst !== 'function') {
    return 0;
  }
  const now = new Date();
  const clearance = await database.userAttributeAssignment.findFirst({
    where: {
      user_id: userId,
      attribute_definitions: { code: 'CLEARANCE_LEVEL', is_active: true },
      attribute_options: { is_active: true },
      valid_from: { lte: now },
      OR: [{ valid_to: null }, { valid_to: { gt: now } }],
    },
    include: {
      attribute_definitions: { select: { is_active: true } },
      attribute_options: true,
    },
    orderBy: { attribute_options: { numeric_rank: 'desc' } },
  });
  if (
    (clearance as { attribute_definitions?: { is_active?: boolean } } | null)?.attribute_definitions
      ?.is_active === false ||
    clearance?.attribute_options?.is_active === false
  ) {
    return 0;
  }
  return clearance?.attribute_options?.numeric_rank ?? 0;
}

/**
 * Thuật toán: Tổng hợp mệnh đề `WHERE` hiển thị 4 nhánh (chủ sở hữu, quyền `DISCOVER` phòng ban, cấp quyền `USER`, cấp quyền `ROLE`)
 * kết hợp bộ lọc trần độ mật Bell-LaPadula và tìm kiếm lai FTS / Trigram.
 */
export function buildSearchWhereClause(params: {
  userId: bigint;
  hasGlobalDiscover: boolean;
  discoverableDeptIds: bigint[] | null;
  roleIds: bigint[];
  userClearanceRank: number | null;
  input: SearchDocumentsInput;
  sanitizedQuery: string | undefined;
}): Prisma.Sql {
  const {
    userId,
    hasGlobalDiscover,
    discoverableDeptIds,
    roleIds,
    userClearanceRank,
    input,
    sanitizedQuery,
  } = params;
  // CONFLICT-RESOLVED: Luôn áp dụng bộ lọc trần độ mật Bell-LaPadula (mặc định `0` khi thiếu thuộc tính) để chặn rò rỉ tiêu đề/trích đoạn 200 ký tự vượt thẩm quyền (HIGH-08).
  const effectiveClearanceRank = userClearanceRank ?? 0;
  const clearanceSql = Prisma.sql` AND (cl."rank" IS NULL OR cl."rank" <= ${effectiveClearanceRank})`;

  const visibility: Prisma.Sql[] = [Prisma.sql`(d."owner_id" = ${userId}${clearanceSql})`];
  if (hasGlobalDiscover) {
    visibility.push(Prisma.sql`(d."discoverable" = true AND d."status" = 'ACTIVE'${clearanceSql})`);
  } else if (discoverableDeptIds && discoverableDeptIds.length > 0) {
    visibility.push(
      Prisma.sql`(d."discoverable" = true AND d."status" = 'ACTIVE' AND d."department_id" = ANY(${discoverableDeptIds})${clearanceSql})`,
    );
  }

  visibility.push(
    Prisma.sql`(EXISTS (
      SELECT 1 FROM access_grants ag
      WHERE ag.document_id = d.id AND ag.principal_type = 'USER' AND ag.principal_user_id = ${userId}
        AND ag.status = 'ACTIVE' AND ag.valid_from <= now() AND ag.valid_until > now()
    )${clearanceSql})`,
  );

  if (roleIds.length > 0) {
    visibility.push(
      Prisma.sql`(EXISTS (
        SELECT 1 FROM access_grants ag
        WHERE ag.document_id = d.id AND ag.principal_type = 'ROLE' AND ag.principal_role_id = ANY(${roleIds})
          AND ag.status = 'ACTIVE' AND ag.valid_from <= now() AND ag.valid_until > now()
      )${clearanceSql})`,
    );
  }

  const conditions: Prisma.Sql[] = [
    Prisma.sql`(${Prisma.join(visibility, ' OR ')})`,
    Prisma.sql`d."status" != 'DELETED'`,
  ];

  if (input.status) conditions.push(Prisma.sql`d."status" = ${input.status}::document_status`);
  if (input.departmentId) conditions.push(Prisma.sql`d."department_id" = ${input.departmentId}`);
  if (input.classificationLevelId) {
    conditions.push(
      Prisma.sql`EXISTS (
        SELECT 1 FROM document_classification_history dch
        WHERE dch.document_id = d.id AND dch.effective_to IS NULL
          AND dch.classification_level_id = ${input.classificationLevelId}
      )`,
    );
  }
  if (sanitizedQuery && sanitizedQuery.length > 0) {
    conditions.push(
      Prisma.sql`(
        to_tsvector('simple', coalesce(d."title", '') || ' ' || coalesce(d."description", '') || ' ' || coalesce(d."document_code", ''))
        @@ plainto_tsquery('simple', ${sanitizedQuery})
        OR similarity(d."title", ${sanitizedQuery}) > 0.15
      )`,
    );
  }

  return Prisma.sql`WHERE ${Prisma.join(conditions, ' AND ')}`;
}
