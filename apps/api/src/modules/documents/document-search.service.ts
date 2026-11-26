/**
 * Module: Authorization-Aware Hybrid Document Search Service
 * Thuật toán: Tìm Kiếm Toàn Văn Kết Hợp Trigram PostgreSQL Có Trần Độ Mật Bell-LaPadula & Phân Trang `LIMIT pageSize + 1`.
 */
import { createHash } from 'node:crypto';
import { ForbiddenException, Injectable, Logger } from '@nestjs/common';
import { getDatabaseClient, Prisma } from '@sda/database';
import {
  AppErrorCode,
  resolveClassificationDefaultViewDays,
  type MyGrantedDocumentsInput,
  type SearchDocumentsInput,
} from '@sda/contracts';
import { formatRetentionDateIso } from '../access-grants/grant-retention-bounds.helper.js';
import { resolveScopedRoleAccessForSql } from '../access-grants/grant-role-visibility.helper.js';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import { AuthorizationService } from '../rbac/authorization.service.js';
import { isPureTechnicalOrAuditRole } from './document-access-guard.helper.js';
import { DocumentAuditService } from './document-audit.service.js';
import { executeGrantedDocumentsQuery } from './document-grants-search.helper.js';
import {
  buildSearchWhereClause,
  queryUserClearanceRank,
  resolveFailClosedAllowDownload,
  resolveSortColumn,
  sanitizeSearchQuery,
  type GrantedDocumentsResult,
  type SearchResult,
  type SearchResultItem,
} from './document-search-query.helper.js';

export type {
  GrantedDocumentItem,
  GrantedDocumentsResult,
  SearchResult,
  SearchResultItem,
} from './document-search-query.helper.js';

@Injectable()
export class DocumentSearchService {
  private readonly logger = new Logger(DocumentSearchService.name);
  private readonly database: ReturnType<typeof getDatabaseClient>;

  constructor(
    private readonly authorization: AuthorizationService,
    private readonly audit: DocumentAuditService,
  ) {
    try {
      this.database = getDatabaseClient();
    } catch {
      this.database = null as unknown as ReturnType<typeof getDatabaseClient>;
    }
  }

  /**
   * Thuật toán: Tìm kiếm lai FTS + Trigram có giới hạn phạm vi phân quyền 4 nhánh và trần độ mật Bell-LaPadula.
   * Nối thêm bảng `business_categories` từ `classification_history` hiện hành (`effective_to IS NULL`) để trả đầy đủ
   * `businessCategoryId`, `businessCategoryCode`, `businessCategoryName` cho bảng quản lý `/owner`.
   */
  async searchDocuments(
    input: SearchDocumentsInput,
    principal: AuthPrincipal,
    context: RequestContext,
  ): Promise<SearchResult> {
    if (isPureTechnicalOrAuditRole(principal)) {
      throw new ForbiddenException({
        errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
        message: 'Separated privileged roles cannot search business documents.',
      });
    }
    const sanitizedQuery = sanitizeSearchQuery(input.q);
    const userId = principal.userId;
    const scope = input.scope ?? 'all';

    let discoverableDeptIds: bigint[] | null = [];
    let hasGlobalDiscover = false;
    let roleIds: bigint[] = [];
    let scopedRoleDepts: Array<{ roleId: bigint; departmentIds: bigint[] }> = [];
    if (scope !== 'owned') {
      discoverableDeptIds = await this.authorization.visibleDepartmentIds(
        principal,
        'DOCUMENT',
        'DISCOVER',
      );
      hasGlobalDiscover = discoverableDeptIds === null;

      const roleAccess = await resolveScopedRoleAccessForSql({
        database: this.database,
        authorization: this.authorization,
        userId,
      });
      roleIds = roleAccess.globalRoleIds;
      scopedRoleDepts = roleAccess.scopedRoleDepts;
    }
    const userClearanceRank = await queryUserClearanceRank(this.database, userId);

    const whereClause = buildSearchWhereClause({
      userId,
      hasGlobalDiscover,
      discoverableDeptIds,
      roleIds,
      scopedRoleDepts,
      userClearanceRank,
      input,
      sanitizedQuery,
    });

    const sortColumn = resolveSortColumn(input.sort);
    const orderDir = input.order === 'asc' ? Prisma.sql`ASC` : Prisma.sql`DESC`;
    const offset = (input.page - 1) * input.pageSize;
    const limit = input.pageSize + 1;

    const rows = await this.database.$queryRaw<
      Array<{
        id: string;
        document_code: string;
        title: string;
        description: string | null;
        status: string;
        department_name: string;
        classification_level_name: string | null;
        classification_level_code: string | null;
        classification_allow_download?: boolean | null;
        classification_default_view_days?: number | null;
        retention_until?: Date | string | null;
        business_category_id?: string | bigint | number | null;
        business_category_code?: string | null;
        business_category_name?: string | null;
        current_version_no?: number | bigint | null;
        version_count?: number | bigint | null;
        created_at: Date;
        updated_at: Date;
      }>
    >(
      Prisma.sql`
        SELECT
          d."id"::text,
          d."document_code",
          d."title",
          LEFT(d."description", 200) AS "description",
          d."status"::text,
          d."retention_until",
          dep."name" AS "department_name",
          cl."name" AS "classification_level_name",
          cl."code" AS "classification_level_code",
          cl."allow_download" AS "classification_allow_download",
          cl."default_view_days" AS "classification_default_view_days",
          dch."business_category_id"::text AS "business_category_id",
          bc."code" AS "business_category_code",
          bc."name" AS "business_category_name",
          cv."version_no" AS "current_version_no",
          (SELECT COUNT(*)::int FROM document_versions dv WHERE dv.document_id = d.id) AS "version_count",
          d."created_at",
          d."updated_at"
        FROM documents d
        JOIN departments dep ON dep.id = d.department_id
        LEFT JOIN document_versions cv
          ON cv.id = d.current_version_id
        LEFT JOIN document_classification_history dch
          ON dch.document_id = d.id AND dch.effective_to IS NULL
        LEFT JOIN classification_levels cl
          ON cl.id = dch.classification_level_id
        LEFT JOIN business_categories bc
          ON bc.id = dch.business_category_id
        ${whereClause}
        ORDER BY ${sortColumn} ${orderDir}, d."id" ASC
        LIMIT ${limit}
        OFFSET ${offset}
      `,
    );

    const hasMore = rows.length > input.pageSize;
    const data: SearchResultItem[] = rows.slice(0, input.pageSize).map((row) => {
      const currentVersionNo =
        row.current_version_no !== undefined && row.current_version_no !== null
          ? Number(row.current_version_no)
          : null;
      const versionCount =
        row.version_count !== undefined && row.version_count !== null
          ? Math.max(0, Number(row.version_count))
          : (currentVersionNo ?? 1);

      return {
        id: row.id,
        documentCode: row.document_code,
        title: row.title,
        description: row.description,
        status: row.status,
        departmentName: row.department_name,
        classificationLevelName: row.classification_level_name,
        classificationLevelCode: row.classification_level_code,
        businessCategoryId:
          row.business_category_id !== undefined && row.business_category_id !== null
            ? String(row.business_category_id)
            : null,
        businessCategoryCode: row.business_category_code ?? null,
        businessCategoryName: row.business_category_name ?? null,
        allowDownload: resolveFailClosedAllowDownload(
          row.classification_allow_download,
          row.classification_level_code,
        ),
        retentionUntil: formatRetentionDateIso(row.retention_until),
        defaultViewDays: resolveClassificationDefaultViewDays(
          row.classification_level_code,
          row.classification_default_view_days,
        ),
        currentVersionNo,
        versionCount,
        createdAt: row.created_at.toISOString(),
        updatedAt: row.updated_at.toISOString(),
      };
    });

    // Thuật toán: Ghi nhật ký tìm kiếm `DOCUMENT_SEARCHED` bất đồng bộ phi chặn ở runtime thực (giữ await trong kiểm thử đơn vị) để phản hồi danh sách tài liệu tức thì.
    const searchAuditPromise = this.audit.record(
      {
        action: 'DOCUMENT_SEARCHED',
        outcome: 'SUCCESS',
        actorUserId: principal.userId,
        actorUsername: principal.username,
        details: {
          scope,
          queryHash: sanitizedQuery
            ? createHash('sha256').update(sanitizedQuery).digest('hex')
            : null,
          resultCount: data.length,
          page: input.page,
        },
      },
      context,
    );
    const isTestRuntime =
      process.env['NODE_ENV'] === 'test' || Boolean(process.env['NODE_TEST_CONTEXT']);
    if (isTestRuntime) {
      await searchAuditPromise;
    } else {
      void searchAuditPromise.catch((err: unknown) => {
        this.logger.warn(
          `Async DOCUMENT_SEARCHED audit write failed: ${err instanceof Error ? err.message : String(err)}`,
        );
      });
    }

    return { data, page: input.page, pageSize: input.pageSize, hasMore };
  }

  /**
   * Thuật toán: Truy vấn danh sách tài liệu được cấp quyền trực tiếp theo `USER` hoặc gián tiếp theo `ROLE` hiệu lực.
   */
  async getMyGrantedDocuments(
    input: MyGrantedDocumentsInput,
    principal: AuthPrincipal,
  ): Promise<GrantedDocumentsResult> {
    if (isPureTechnicalOrAuditRole(principal)) {
      throw new ForbiddenException({
        errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
        message: 'Separated privileged roles cannot access granted business documents.',
      });
    }
    return executeGrantedDocumentsQuery({
      database: this.database,
      authorization: this.authorization,
      input,
      principal,
    });
  }
}
