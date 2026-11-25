/**
 * Module: Document Scoped Mutation & Anti-Enumeration Read Access Guards
 * Thuật toán: Kiểm Soát Phân Tách Nhiệm Vụ (SoD), Quyền RBAC Theo Phòng Ban & Thống Trị Độ Mật Bell-LaPadula.
 *   1. Chặn tuyệt đối các vai trò đặc quyền (`SYSTEM_ADMIN`, `SECURITY_OFFICER`, `AUDITOR`) truy cập hoặc sở hữu tài liệu nghiệp vụ.
 *   2. Cưỡng chế bất biến "No Read/Write Above Clearance" (`actorClearanceRank >= documentRank`) cho CẢ chủ sở hữu tài liệu (`owner_id`)
 *      lẫn quản trị viên nghiệp vụ phòng ban để ngăn vượt rào khi chủ sở hữu bị hạ bậc độ mật sau khi tài liệu được nâng lên `SECRET`/`TOP_SECRET`.
 *   3. Che giấu sự tồn tại của tài liệu bằng mã lỗi `404 DOCUMENT_NOT_FOUND` đối với người dùng thường không đủ thẩm quyền đọc.
 */
import { ForbiddenException, NotFoundException } from '@nestjs/common';
import type { getDatabaseClient } from '@sda/database';
import { AppErrorCode } from '@sda/contracts';
import type { AuthPrincipal } from '../auth/auth.types.js';
import type { AuthorizationService } from '../rbac/authorization.service.js';
import { PRIVILEGED_SEPARATION_ROLES } from '../rbac/permission-matrix.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

/**
 * Thuật toán: Kiểm tra Phân tách nhiệm vụ (SoD) bất biến cho các vai trò đặc quyền (`SYSTEM_ADMIN`, `SECURITY_OFFICER`, `AUDITOR`).
 */
export function isPureTechnicalOrAuditRole(principal?: AuthPrincipal): boolean {
  const roles = principal?.roles ?? [];
  return roles.some((role) => PRIVILEGED_SEPARATION_ROLES.has(role));
}

/**
 * Thuật toán: Truy vấn thứ bậc độ mật `CLEARANCE_LEVEL` còn hiệu lực kèm lọc `is_active: true` trên cả định nghĩa và tùy chọn thuộc tính.
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
 * Thuật toán: Cưỡng chế bất biến thống trị độ mật Bell-LaPadula (`actorClearanceRank >= documentRank`) cho chủ sở hữu và quản trị viên.
 */
export async function assertActorClearanceDominatesDocument(
  database: PrismaClient | undefined,
  userId: bigint,
  documentRank: number,
  now = new Date(),
): Promise<void> {
  if (
    documentRank <= 0 ||
    !database ||
    typeof database?.userAttributeAssignment?.findFirst !== 'function'
  ) {
    return;
  }
  const actorRank = await getUserClearanceRank(database, userId, now);
  if (actorRank < documentRank) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.BELL_LAPADULA_CLEARANCE_INSUFFICIENT,
      message: `Insufficient security clearance (${actorRank}) for document at classification rank ${documentRank}.`,
    });
  }
}

async function resolveActiveDocumentClassificationRank(
  database: PrismaClient | undefined,
  doc: {
    id: string;
    classification_history?: Array<{ classification_levels?: { rank?: number } | null }>;
  },
): Promise<number> {
  const inlineRank = doc.classification_history?.[0]?.classification_levels?.rank;
  if (typeof inlineRank === 'number') {
    return inlineRank;
  }
  if (
    !Array.isArray(doc.classification_history) &&
    typeof database?.documentClassificationHistory?.findFirst === 'function'
  ) {
    const active = await database.documentClassificationHistory.findFirst({
      where: { document_id: doc.id, effective_to: null },
      include: { classification_levels: true },
    });
    return active?.classification_levels?.rank ?? 0;
  }
  return 0;
}

export type DocumentMutationOperation =
  'METADATA' | 'ACTIVATE' | 'VERSION' | 'CLASSIFY' | 'ARCHIVE' | 'TRANSFER_OWNER';

/**
 * Thuật toán: Kiểm định thẩm quyền thay đổi tài liệu theo nguyên tắc sở hữu nghiêm ngặt (chống BOLA liên chủ sở hữu),
 * phân tách nhiệm vụ (SoD) và bất biến độ mật Bell-LaPadula (`actorClearanceRank >= documentRank`).
 */
export async function assertDocumentMutationPermission(
  _authorization: AuthorizationService,
  document: {
    id: string;
    owner_id: bigint;
    department_id: bigint;
    classification_history?: Array<{ classification_levels?: { rank?: number } | null }>;
  },
  principal: AuthPrincipal,
  _operation: DocumentMutationOperation = 'METADATA',
  options?: {
    database?: PrismaClient | undefined;
    documentRank?: number | undefined;
    now?: Date | undefined;
  },
): Promise<void> {
  if (isPureTechnicalOrAuditRole(principal)) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.TECHNICAL_ADMIN_CANNOT_OWN,
      message:
        'Technical administrator, security officer, and auditor accounts cannot modify business documents.',
    });
  }

  if (document.owner_id !== principal.userId) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
      message: 'Only the document owner may modify this document.',
    });
  }

  const effectiveRank =
    typeof options?.documentRank === 'number'
      ? options.documentRank
      : await resolveActiveDocumentClassificationRank(options?.database, document);
  await assertActorClearanceDominatesDocument(
    options?.database,
    principal.userId,
    effectiveRank,
    options?.now,
  );
}

/**
 * Thuật toán: Cổng kiểm định quyền đọc siêu dữ liệu chống dò quét (Anti-Enumeration) và chống BOLA liên chủ sở hữu.
 *   1. Chặn tuyệt đối tài khoản quản trị/SOC/kiểm toán (SoD) và tài liệu đã xóa (`DELETED`).
 *   2. Chủ sở hữu tài liệu (`doc.owner_id === principal.userId`) được phép đọc khi thỏa độ mật Bell-LaPadula.
 *   3. Khi `allowActiveGrant === true` (dành cho chi tiết tài liệu `ACTIVE`), chỉ người có `AccessGrant` (`USER` hoặc `ROLE`)
 *      còn hiệu lực và đủ độ mật Bell-LaPadula mới được phép truy cập; từ chối mọi chủ sở hữu ngang hàng hoặc tra cứu theo UUID trần bằng `404`.
 */
export async function assertDocumentReadAccess(
  database: PrismaClient,
  _authorization: AuthorizationService,
  doc: {
    id: string;
    owner_id: bigint;
    department_id: bigint;
    status: string;
    discoverable: boolean;
    classification_history?: Array<{ classification_levels?: { rank?: number } | null }>;
  },
  principal?: AuthPrincipal,
  allowActiveGrant = false,
  options?: { internalTrustedRead?: boolean },
): Promise<void> {
  if (!principal) {
    if (options?.internalTrustedRead) return;
    throw new ForbiddenException({
      errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
      message: 'Authenticated principal is required to access document metadata.',
    });
  }

  if (isPureTechnicalOrAuditRole(principal)) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
      message: 'Technical administrator and auditor accounts cannot access business documents.',
    });
  }

  if (doc.status === 'DELETED') {
    throw new NotFoundException({
      errorCode: AppErrorCode.DOCUMENT_NOT_FOUND,
      message: 'Document not found.',
    });
  }

  const now = new Date();
  const documentRank = await resolveActiveDocumentClassificationRank(database, doc);

  if (doc.owner_id === principal.userId) {
    await assertActorClearanceDominatesDocument(database, principal.userId, documentRank, now);
    return;
  }

  if (allowActiveGrant && doc.status === 'ACTIVE') {
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
  }

  throw new NotFoundException({
    errorCode: AppErrorCode.DOCUMENT_NOT_FOUND,
    message: 'Document not found.',
  });
}
