import { createHash } from 'node:crypto';
import { BadRequestException, Injectable } from '@nestjs/common';
import { getDatabaseClient, Prisma } from '@sda/database';
import {
  AppErrorCode,
  type SearchDocumentsInput,
  type MyGrantedDocumentsInput,
} from '@sda/contracts';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import { AuthorizationService } from '../rbac/authorization.service.js';
import { DocumentAuditService } from './document-audit.service.js';

/** Minimal document fields exposed by search — no sensitive internal data */
export interface SearchResultItem {
  id: string;
  documentCode: string;
  title: string;
  description: string | null;
  status: string;
  departmentName: string;
  classificationLevelName: string | null;
  classificationLevelCode: string | null;
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
  };
}

export interface GrantedDocumentsResult {
  data: GrantedDocumentItem[];
  page: number;
  pageSize: number;
  hasMore: boolean;
}

/** Pattern to strip from search queries — prevents regex/wildcard abuse */
const FORBIDDEN_PATTERN = /[*?[\]{}\\^$|]/g;

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
   * Authorization-aware document search.
   *
   * Visibility rules (D-BR11):
   * 1. User is document owner → always visible
   * 2. User has DISCOVER permission for document's department AND document is discoverable AND status is ACTIVE
   * 3. User has an active grant on the document (direct USER grant or via ROLE grant)
   *
   * Results never include: owner email, storage_key, encryption_key_ref, internal hashes, or total hidden count.
   */
  async searchDocuments(
    input: SearchDocumentsInput,
    principal: AuthPrincipal,
    context: RequestContext,
  ): Promise<SearchResult> {
    const sanitizedQuery = this.sanitizeSearchQuery(input.q);

    // Build the visibility filter using parameterized SQL
    const userId = principal.userId;

    // Determine which departments this user has DISCOVER permission for
    const discoverableDeptIds = await this.authorization.visibleDepartmentIds(
      principal,
      'DOCUMENT',
      'DISCOVER',
    );
    // null means global scope (all departments), [] means no DISCOVER at all
    const hasGlobalDiscover = discoverableDeptIds === null;

    // Get user's role IDs for role-based grant lookup
    const userRoles = await this.authorization.effectiveGrants(userId);
    const roleIds = [...new Set(userRoles.map((g) => g.roleId))];

    // Build WHERE conditions as parameterized fragments
    const conditions: Prisma.Sql[] = [];
    const visibilityConditions: Prisma.Sql[] = [];

    // 1. Owner always sees their documents
    visibilityConditions.push(Prisma.sql`d."owner_id" = ${userId}`);

    // 2. DISCOVER permission + discoverable + ACTIVE
    if (hasGlobalDiscover) {
      visibilityConditions.push(Prisma.sql`(d."discoverable" = true AND d."status" = 'ACTIVE')`);
    } else if (discoverableDeptIds && discoverableDeptIds.length > 0) {
      visibilityConditions.push(
        Prisma.sql`(d."discoverable" = true AND d."status" = 'ACTIVE' AND d."department_id" = ANY(${discoverableDeptIds}))`,
      );
    }

    // 3. Active grant (direct USER grant)
    visibilityConditions.push(
      Prisma.sql`EXISTS (
        SELECT 1 FROM access_grants ag
        WHERE ag.document_id = d.id
          AND ag.principal_type = 'USER'
          AND ag.principal_user_id = ${userId}
          AND ag.status = 'ACTIVE'
          AND ag.valid_from <= now()
          AND ag.valid_until > now()
      )`,
    );

    // 4. Active grant via ROLE
    if (roleIds.length > 0) {
      visibilityConditions.push(
        Prisma.sql`EXISTS (
          SELECT 1 FROM access_grants ag
          WHERE ag.document_id = d.id
            AND ag.principal_type = 'ROLE'
            AND ag.principal_role_id = ANY(${roleIds})
            AND ag.status = 'ACTIVE'
            AND ag.valid_from <= now()
            AND ag.valid_until > now()
        )`,
      );
    }

    // Combine visibility: user must satisfy at least one condition
    conditions.push(Prisma.sql`(${Prisma.join(visibilityConditions, ' OR ')})`);

    // Exclude DELETED documents
    conditions.push(Prisma.sql`d."status" != 'DELETED'`);

    // Optional filters
    if (input.status) {
      conditions.push(Prisma.sql`d."status" = ${input.status}::document_status`);
    }
    if (input.departmentId) {
      conditions.push(Prisma.sql`d."department_id" = ${input.departmentId}`);
    }
    if (input.classificationLevelId) {
      conditions.push(
        Prisma.sql`EXISTS (
          SELECT 1 FROM document_classification_history dch
          WHERE dch.document_id = d.id
            AND dch.effective_to IS NULL
            AND dch.classification_level_id = ${input.classificationLevelId}
        )`,
      );
    }

    // Text search with parameterized query
    if (sanitizedQuery && sanitizedQuery.length > 0) {
      conditions.push(
        Prisma.sql`(
          to_tsvector('simple', coalesce(d."title", '') || ' ' || coalesce(d."description", '') || ' ' || coalesce(d."document_code", ''))
          @@ plainto_tsquery('simple', ${sanitizedQuery})
          OR similarity(d."title", ${sanitizedQuery}) > 0.15
        )`,
      );
    }

    const whereClause = Prisma.sql`WHERE ${Prisma.join(conditions, ' AND ')}`;

    // Sort allowlist with stable tie-breaker
    const sortColumn = this.resolveSortColumn(input.sort);
    const orderDir = input.order === 'asc' ? Prisma.sql`ASC` : Prisma.sql`DESC`;

    const offset = (input.page - 1) * input.pageSize;
    // Fetch one extra to determine hasMore
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

    // Audit: hash search term for privacy
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
   * List documents the current user has been granted access to,
   * with grant status, permissions and validity period.
   */
  async getMyGrantedDocuments(
    input: MyGrantedDocumentsInput,
    principal: AuthPrincipal,
  ): Promise<GrantedDocumentsResult> {
    const userId = principal.userId;
    const offset = (input.page - 1) * input.pageSize;
    const limit = input.pageSize + 1;

    const sortColumn = this.resolveGrantSortColumn(input.sort);
    const orderDir = input.order === 'asc' ? Prisma.sql`ASC` : Prisma.sql`DESC`;

    // Get user's role IDs for role-based grant lookup
    const userRoles = await this.authorization.effectiveGrants(userId);
    const roleIds = [...new Set(userRoles.map((g) => g.roleId))];

    // Build grant visibility: direct USER grants OR grants via user's active roles
    const grantVisibility: Prisma.Sql[] = [
      Prisma.sql`(ag.principal_type = 'USER' AND ag.principal_user_id = ${userId})`,
    ];
    if (roleIds.length > 0) {
      grantVisibility.push(
        Prisma.sql`(ag.principal_type = 'ROLE' AND ag.principal_role_id = ANY(${roleIds}))`,
      );
    }

    const rows = await this.database.$queryRaw<
      Array<{
        grant_id: string;
        grant_status: string;
        valid_from: Date;
        valid_until: Date;
        granted_at: Date;
        doc_id: string;
        doc_code: string;
        doc_title: string;
        doc_status: string;
        cl_name: string | null;
      }>
    >(
      Prisma.sql`
        SELECT
          ag."id"::text AS "grant_id",
          ag."status"::text AS "grant_status",
          ag."valid_from",
          ag."valid_until",
          ag."granted_at",
          d."id"::text AS "doc_id",
          d."document_code" AS "doc_code",
          d."title" AS "doc_title",
          d."status"::text AS "doc_status",
          cl."name" AS "cl_name"
        FROM access_grants ag
        JOIN documents d ON d.id = ag.document_id
        LEFT JOIN document_classification_history dch
          ON dch.document_id = d.id AND dch.effective_to IS NULL
        LEFT JOIN classification_levels cl
          ON cl.id = dch.classification_level_id
        WHERE (${Prisma.join(grantVisibility, ' OR ')})
          AND d."status" != 'DELETED'
        ORDER BY ${sortColumn} ${orderDir}, ag."id" ASC
        LIMIT ${limit}
        OFFSET ${offset}
      `,
    );

    // Fetch permissions for each grant
    const grantIds = rows.slice(0, input.pageSize).map((r) => r.grant_id);
    let permissionsByGrant = new Map<string, string[]>();
    if (grantIds.length > 0) {
      const perms = await this.database.$queryRaw<
        Array<{ access_grant_id: string; permission: string }>
      >(
        Prisma.sql`
          SELECT "access_grant_id"::text, "permission"::text
          FROM access_grant_permissions
          WHERE "access_grant_id"::text = ANY(${grantIds})
        `,
      );
      permissionsByGrant = new Map<string, string[]>();
      for (const p of perms) {
        const existing = permissionsByGrant.get(p.access_grant_id) ?? [];
        existing.push(p.permission);
        permissionsByGrant.set(p.access_grant_id, existing);
      }
    }

    const hasMore = rows.length > input.pageSize;
    const data: GrantedDocumentItem[] = rows.slice(0, input.pageSize).map((row) => ({
      grantId: row.grant_id,
      permissions: permissionsByGrant.get(row.grant_id) ?? [],
      grantStatus: row.grant_status,
      validFrom: row.valid_from.toISOString(),
      validUntil: row.valid_until.toISOString(),
      grantedAt: row.granted_at.toISOString(),
      document: {
        id: row.doc_id,
        documentCode: row.doc_code,
        title: row.doc_title,
        status: row.doc_status,
        classificationLevelName: row.cl_name,
      },
    }));

    return { data, page: input.page, pageSize: input.pageSize, hasMore };
  }

  /**
   * Sanitize and validate search query input.
   * - Max 200 characters
   * - Strip forbidden regex/wildcard patterns
   * - Trim whitespace
   */
  private sanitizeSearchQuery(query: string | undefined): string | undefined {
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

  /** Map sort field to safe SQL column reference — sort allowlist */
  private resolveSortColumn(sort: string): Prisma.Sql {
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

  /** Map grant sort field to safe SQL column reference */
  private resolveGrantSortColumn(sort: string): Prisma.Sql {
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
}
