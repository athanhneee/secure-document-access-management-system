/**
 * Module: Document Search SQL Query Builder & Mapper Helper
 * Algorithm: Parameterized 4-branch visibility predicate with Bell-LaPadula clearance rank cap,
 *   hybrid PostgreSQL FTS (`to_tsvector`/`plainto_tsquery`) + trigram (`similarity`) matching,
 *   and `LIMIT pageSize + 1` lookahead pagination without disclosing hidden counts.
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

const FORBIDDEN_PATTERN = /[*?[\]{}\\^$|]/g;

/**
 * Algorithm: Search Query Sanitization & Wildcard Stripping
 * Enforces 200-character ceiling and strips regex/wildcard metacharacters.
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

/**
 * Algorithm: Subject Bell-LaPadula Clearance Lookup
 * Resolves the highest active `CLEARANCE_LEVEL` numeric rank for `userId` (or `null` when DB mock lacks attributes).
 */
export async function queryUserClearanceRank(
  database: ReturnType<typeof getDatabaseClient>,
  userId: bigint,
): Promise<number | null> {
  if (typeof database?.userAttributeAssignment?.findFirst !== 'function') {
    return null;
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
 * Algorithm: 4-Branch Disjunctive Visibility & Hybrid FTS/Trigram WHERE Builder
 * Combines owner, department `DISCOVER`, direct `USER` grant, and `ROLE` grant clauses with Bell-LaPadula rank filter.
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
  const clearanceSql =
    userClearanceRank !== null
      ? Prisma.sql` AND (cl."rank" IS NULL OR cl."rank" <= ${userClearanceRank})`
      : Prisma.empty;

  const visibility: Prisma.Sql[] = [Prisma.sql`d."owner_id" = ${userId}`];
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
