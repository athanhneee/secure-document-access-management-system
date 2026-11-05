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

export type DocumentMutationOperation =
  'METADATA' | 'ACTIVATE' | 'VERSION' | 'CLASSIFY' | 'ARCHIVE' | 'TRANSFER_OWNER';

/**
 * Thuật toán: Kiểm định thẩm quyền thay đổi tài liệu phân tách theo từng nghiệp vụ cụ thể (Operation-Specific Scoped RBAC).
 * Cơ chế hoạt động:
 *   - Chủ sở hữu tài liệu (`document.owner_id === principal.userId`) được phép thực thi các thao tác vòng đời trên tài liệu của mình.
 *   - Quản trị viên nghiệp vụ theo phòng ban chỉ được phép thực thi đúng hành động tương ứng:
 *     + `METADATA` / `ACTIVATE` / `CLASSIFY`: yêu cầu `DOCUMENT:MANAGE` hoặc `DOCUMENT:CLASSIFY` trong `document.department_id`.
 *     + `VERSION`: yêu cầu `DOCUMENT:MANAGE` hoặc `DOCUMENT_VERSION:CREATE` trong `document.department_id`.
 *     + `ARCHIVE`: yêu cầu `DOCUMENT:MANAGE` hoặc `DOCUMENT:ARCHIVE` trong `document.department_id`.
 *     + `TRANSFER_OWNER`: chỉ cho phép chủ sở hữu hoặc `DOCUMENT:MANAGE` (tuyệt đối chặn `ARCHIVE`/`CLASSIFY` tự ý chuyển quyền sở hữu).
 */
export async function assertDocumentMutationPermission(
  authorization: AuthorizationService,
  document: { id: string; owner_id: bigint; department_id: bigint },
  principal: AuthPrincipal,
  operation: DocumentMutationOperation = 'METADATA',
): Promise<void> {
  if (isPureTechnicalOrAuditRole(principal)) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.TECHNICAL_ADMIN_CANNOT_OWN,
      message:
        'Only the document owner or an authorized business administrator for this department may modify this document.',
    });
  }

  if (document.owner_id === principal.userId) {
    return;
  }

  // CONFLICT-RESOLVED: Tách bạch kiểm tra quyền RBAC theo từng thao tác thay vì gộp chung DOCUMENT:ARCHIVE/CLASSIFY/MANAGE cho mọi đột biến.
  const scope = { targetDepartmentId: document.department_id };
  const hasManage = await authorization.hasPermission(principal, 'DOCUMENT', 'MANAGE', scope);
  if (hasManage) {
    return;
  }

  let hasSpecificPermission = false;
  switch (operation) {
    case 'METADATA':
    case 'ACTIVATE':
    case 'CLASSIFY':
      hasSpecificPermission = await authorization.hasPermission(
        principal,
        'DOCUMENT',
        'CLASSIFY',
        scope,
      );
      break;
    case 'VERSION':
      hasSpecificPermission = await authorization.hasPermission(
        principal,
        'DOCUMENT_VERSION',
        'CREATE',
        scope,
      );
      break;
    case 'ARCHIVE':
      hasSpecificPermission = await authorization.hasPermission(
        principal,
        'DOCUMENT',
        'ARCHIVE',
        scope,
      );
      break;
    case 'TRANSFER_OWNER':
      hasSpecificPermission = false;
      break;
  }

  if (hasSpecificPermission) {
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
