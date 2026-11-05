/**
 * Module: Document Scoped Mutation & Anti-Enumeration Read Access Guards
 * Algorithm: Enforces Separation of Duties (SoD), department-scoped business RBAC (`CLASSIFY`/`MANAGE`/`ARCHIVE`),
 *   and Bell-LaPadula clearance dominance (`userRank >= documentRank`) with 404 masking on unauthorized reads.
 */
import { ForbiddenException, NotFoundException } from '@nestjs/common';
import type { getDatabaseClient } from '@sda/database';
import { AppErrorCode } from '@sda/contracts';
import type { AuthPrincipal } from '../auth/auth.types.js';
import type { AuthorizationService } from '../rbac/authorization.service.js';
import { PRIVILEGED_SEPARATION_ROLES } from '../rbac/permission-matrix.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

/**
 * Algorithm / Thuật toán: Kiểm tra Phân tách nhiệm vụ (SoD) bất biến cho các vai trò đặc quyền (`SYSTEM_ADMIN`, `SECURITY_OFFICER`, `AUDITOR`).
 * Chặn tuyệt đối không cho phép chồng vai trò nghiệp vụ (`DOCUMENT_OWNER`/`DOCUMENT_READER`) để vượt rào truy cập nội dung tài liệu.
 */
export function isPureTechnicalOrAuditRole(principal?: AuthPrincipal): boolean {
  // CONFLICT-RESOLVED: Removed `!hasBusinessRole` bypass and included `SECURITY_OFFICER` via `PRIVILEGED_SEPARATION_ROLES`.
  const roles = principal?.roles ?? [];
  return roles.some((role) => PRIVILEGED_SEPARATION_ROLES.has(role));
}

/**
 * Algorithm / Thuật toán: Truy vấn thứ bậc độ mật `CLEARANCE_LEVEL` còn hiệu lực kèm lọc `is_active: true` trên cả định nghĩa và tùy chọn thuộc tính.
 */
export async function getUserClearanceRank(
  database: PrismaClient,
  userId: bigint,
  now: Date,
): Promise<number> {
  if (typeof database?.userAttributeAssignment?.findFirst !== 'function') {
    return 0;
  }
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
 * Algorithm: Department-Scoped Document Mutation Authorization
 * Permits the document owner or a caller holding `CLASSIFY`, `MANAGE`, or `ARCHIVE` in `document.department_id`.
 */
export async function assertDocumentMutationPermission(
  authorization: AuthorizationService,
  document: { id: string; owner_id: bigint; department_id: bigint },
  principal: AuthPrincipal,
): Promise<void> {
  if (document.owner_id === principal.userId) {
    return;
  }

  const hasClassify = await authorization.hasPermission(principal, 'DOCUMENT', 'CLASSIFY', {
    targetDepartmentId: document.department_id,
  });
  const hasManage = await authorization.hasPermission(principal, 'DOCUMENT', 'MANAGE', {
    targetDepartmentId: document.department_id,
  });
  const hasArchive = await authorization.hasPermission(principal, 'DOCUMENT', 'ARCHIVE', {
    targetDepartmentId: document.department_id,
  });

  if (hasClassify || hasManage || hasArchive) {
    return;
  }

  throw new ForbiddenException({
    errorCode: AppErrorCode.TECHNICAL_ADMIN_CANNOT_OWN,
    message:
      'Only the document owner or an authorized business administrator for this department may modify this document.',
  });
}

/**
 * Algorithm: Anti-Enumeration Document Metadata Read Guard
 * Verifies SoD, owner/department admin rights, or Bell-LaPadula clearance + active grant/`DISCOVER`; masks denials as 404.
 */
export async function assertDocumentReadAccess(
  database: PrismaClient,
  authorization: AuthorizationService,
  doc: {
    id: string;
    owner_id: bigint;
    department_id: bigint;
    status: string;
    discoverable: boolean;
    classification_history?: Array<{
      classification_levels?: { rank?: number } | null;
    }>;
  },
  principal?: AuthPrincipal,
  allowDiscoverable = false,
): Promise<void> {
  if (!principal) return;

  if (isPureTechnicalOrAuditRole(principal)) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
      message: 'Technical administrator and auditor accounts cannot access business documents.',
    });
  }

  if (doc.owner_id === principal.userId) {
    return;
  }

  const [hasClassify, hasManage, hasArchive] = await Promise.all([
    authorization.hasPermission(principal, 'DOCUMENT', 'CLASSIFY', {
      targetDepartmentId: doc.department_id,
    }),
    authorization.hasPermission(principal, 'DOCUMENT', 'MANAGE', {
      targetDepartmentId: doc.department_id,
    }),
    authorization.hasPermission(principal, 'DOCUMENT', 'ARCHIVE', {
      targetDepartmentId: doc.department_id,
    }),
  ]);
  if (hasClassify || hasManage || hasArchive) {
    return;
  }

  const now = new Date();
  const documentRank = doc.classification_history?.[0]?.classification_levels?.rank ?? 0;
  const userRank = await getUserClearanceRank(database, principal.userId, now);

  if (userRank >= documentRank && typeof database?.accessGrant?.findFirst === 'function') {
    const directGrant = await database.accessGrant.findFirst({
      where: {
        document_id: doc.id,
        principal_type: 'USER',
        principal_user_id: principal.userId,
        status: 'ACTIVE',
        valid_from: { lte: now },
        valid_until: { gt: now },
      },
    });
    if (directGrant) return;

    if (typeof database?.userRole?.findMany === 'function') {
      const activeRoles = await database.userRole.findMany({
        where: {
          user_id: principal.userId,
          valid_from: { lte: now },
          OR: [{ valid_to: null }, { valid_to: { gt: now } }],
          roles: { is_active: true },
        },
        select: { role_id: true },
      });
      const roleIds = activeRoles.map((r) => r.role_id);
      if (roleIds.length > 0) {
        const roleGrant = await database.accessGrant.findFirst({
          where: {
            document_id: doc.id,
            principal_type: 'ROLE',
            principal_role_id: { in: roleIds },
            status: 'ACTIVE',
            valid_from: { lte: now },
            valid_until: { gt: now },
          },
        });
        if (roleGrant) return;
      }
    }
  }

  if (
    allowDiscoverable &&
    doc.discoverable &&
    doc.status === 'ACTIVE' &&
    userRank >= documentRank
  ) {
    const hasDiscover = await authorization.hasPermission(principal, 'DOCUMENT', 'DISCOVER', {
      targetDepartmentId: doc.department_id,
    });
    if (hasDiscover) return;
  }

  throw new NotFoundException({
    errorCode: AppErrorCode.DOCUMENT_NOT_FOUND,
    message: 'Document not found.',
  });
}
