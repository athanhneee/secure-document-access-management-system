/**
 * Module: Granted Documents Listing SQL Query Helper
 * Algorithm: Queries `USER` and `ROLE` `access_grants` with Bell-LaPadula clearance rank cap (`LIMIT pageSize + 1`)
 *   and batch-loads `access_grant_permissions` in a single hash-joined lookup.
 */
import { type getDatabaseClient, Prisma } from '@sda/database';
import type { MyGrantedDocumentsInput } from '@sda/contracts';
import type { AuthPrincipal } from '../auth/auth.types.js';
import type { AuthorizationService } from '../rbac/authorization.service.js';
import {
  queryUserClearanceRank,
  resolveGrantSortColumn,
  type GrantedDocumentItem,
  type GrantedDocumentsResult,
} from './document-search-query.helper.js';

/**
 * Algorithm: Hash-Joined User & Role Granted Documents Listing
 * Queries visible grants with clearance filter (`LIMIT N+1`) and batch-loads grant permissions in one query.
 */
export async function executeGrantedDocumentsQuery(params: {
  database: ReturnType<typeof getDatabaseClient>;
  authorization: AuthorizationService;
  input: MyGrantedDocumentsInput;
  principal: AuthPrincipal;
}): Promise<GrantedDocumentsResult> {
  const { database, authorization, input, principal } = params;
  const userId = principal.userId;
  const offset = (input.page - 1) * input.pageSize;
  const limit = input.pageSize + 1;
  const sortColumn = resolveGrantSortColumn(input.sort);
  const orderDir = input.order === 'asc' ? Prisma.sql`ASC` : Prisma.sql`DESC`;

  const userRoles = await authorization.effectiveGrants(userId);
  const roleIds = [...new Set(userRoles.map((g) => g.roleId))];
  const userClearanceRank = await queryUserClearanceRank(database, userId);
  const grantClearanceFilter =
    userClearanceRank !== null
      ? Prisma.sql`AND (cl."rank" IS NULL OR cl."rank" <= ${userClearanceRank})`
      : Prisma.empty;

  const grantVisibility: Prisma.Sql[] = [
    Prisma.sql`(ag.principal_type = 'USER' AND ag.principal_user_id = ${userId})`,
  ];
  if (roleIds.length > 0) {
    grantVisibility.push(
      Prisma.sql`(ag.principal_type = 'ROLE' AND ag.principal_role_id = ANY(${roleIds}))`,
    );
  }

  const rows = await database.$queryRaw<
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
        ag."id"::text AS "grant_id", ag."status"::text AS "grant_status",
        ag."valid_from", ag."valid_until", ag."granted_at",
        d."id"::text AS "doc_id", d."document_code" AS "doc_code",
        d."title" AS "doc_title", d."status"::text AS "doc_status", cl."name" AS "cl_name"
      FROM access_grants ag
      JOIN documents d ON d.id = ag.document_id
      LEFT JOIN document_classification_history dch
        ON dch.document_id = d.id AND dch.effective_to IS NULL
      LEFT JOIN classification_levels cl ON cl.id = dch.classification_level_id
      WHERE (${Prisma.join(grantVisibility, ' OR ')})
        AND d."status" != 'DELETED'
        ${grantClearanceFilter}
      ORDER BY ${sortColumn} ${orderDir}, ag."id" ASC
      LIMIT ${limit}
      OFFSET ${offset}
    `,
  );

  const grantIds = rows.slice(0, input.pageSize).map((r) => r.grant_id);
  const permissionsByGrant = new Map<string, string[]>();
  if (grantIds.length > 0) {
    const perms = await database.$queryRaw<Array<{ access_grant_id: string; permission: string }>>(
      Prisma.sql`
        SELECT "access_grant_id"::text, "permission"::text
        FROM access_grant_permissions
        WHERE "access_grant_id"::text = ANY(${grantIds})
      `,
    );
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
