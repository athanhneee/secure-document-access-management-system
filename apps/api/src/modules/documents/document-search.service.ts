/**
 * Module: Authorization-Aware Hybrid Document Search Service
 * Algorithm: Executes parameterized SQL FTS + trigram search and granted-document listing with
 *   Bell-LaPadula clearance enforcement, `LIMIT pageSize + 1` pagination, and SHA-256 query-hash auditing.
 */
import { createHash } from 'node:crypto';
import { ForbiddenException, Injectable } from '@nestjs/common';
import { getDatabaseClient, Prisma } from '@sda/database';
import {
  AppErrorCode,
  type MyGrantedDocumentsInput,
  type SearchDocumentsInput,
} from '@sda/contracts';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import { AuthorizationService } from '../rbac/authorization.service.js';
import { isPureTechnicalOrAuditRole } from './document-access-guard.helper.js';
import { DocumentAuditService } from './document-audit.service.js';
import { executeGrantedDocumentsQuery } from './document-grants-search.helper.js';
import {
  buildSearchWhereClause,
  queryUserClearanceRank,
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
   * Algorithm: Authorization-Scoped Hybrid Document Search
   * Evaluates 4-branch visibility + clearance rank in SQL, fetches `pageSize + 1` rows, and audits SHA-256 query hash.
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

    const discoverableDeptIds = await this.authorization.visibleDepartmentIds(
      principal,
      'DOCUMENT',
      'DISCOVER',
    );
    const hasGlobalDiscover = discoverableDeptIds === null;

    const userRoles = await this.authorization.effectiveGrants(userId);
    const roleIds = [...new Set(userRoles.map((g) => g.roleId))];
    const userClearanceRank = await queryUserClearanceRank(this.database, userId);

    const whereClause = buildSearchWhereClause({
      userId,
      hasGlobalDiscover,
      discoverableDeptIds,
      roleIds,
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
          dep."name" AS "department_name",
          cl."name" AS "classification_level_name",
          cl."code" AS "classification_level_code",
          d."created_at",
          d."updated_at"
        FROM documents d
        JOIN departments dep ON dep.id = d.department_id
        LEFT JOIN document_classification_history dch
          ON dch.document_id = d.id AND dch.effective_to IS NULL
        LEFT JOIN classification_levels cl
          ON cl.id = dch.classification_level_id
        ${whereClause}
        ORDER BY ${sortColumn} ${orderDir}, d."id" ASC
        LIMIT ${limit}
        OFFSET ${offset}
      `,
    );

    const hasMore = rows.length > input.pageSize;
    const data: SearchResultItem[] = rows.slice(0, input.pageSize).map((row) => ({
      id: row.id,
      documentCode: row.document_code,
      title: row.title,
      description: row.description,
      status: row.status,
      departmentName: row.department_name,
      classificationLevelName: row.classification_level_name,
      classificationLevelCode: row.classification_level_code,
      createdAt: row.created_at.toISOString(),
      updatedAt: row.updated_at.toISOString(),
    }));

    await this.audit.record(
      {
        action: 'DOCUMENT_SEARCHED',
        outcome: 'SUCCESS',
        actorUserId: principal.userId,
        actorUsername: principal.username,
        details: {
          queryHash: sanitizedQuery
            ? createHash('sha256').update(sanitizedQuery).digest('hex')
            : null,
          resultCount: data.length,
          page: input.page,
        },
      },
      context,
    );

    return { data, page: input.page, pageSize: input.pageSize, hasMore };
  }

  /**
   * Algorithm: Hash-Joined User & Role Granted Documents Listing
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
