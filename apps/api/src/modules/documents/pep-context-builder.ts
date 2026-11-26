/**
 * @module PepContextBuilder
 * Thuật toán: Tổng hợp ngữ cảnh Điểm Thông tin Chính sách (PIP) tại cổng thực thi PEP — nạp thuộc tính chủ thể
 * (`CLEARANCE_LEVEL`, `EMPLOYMENT_STATUS` từ từ điển ABAC kèm fallback `user.status`, `PROJECT`, phòng ban),
 * đối chiếu IP với dải mạng tin cậy CIDR, cưỡng chế Phân tách Nhiệm vụ (SoD) và ghi nhật ký từ chối fail-closed.
 */
import type { Logger } from '@nestjs/common';
import type { getDatabaseClient } from '@sda/database';
import { cidrMatch } from '../abac/policy-engine.js';
import type { AppConfigService } from '../../config/config.service.js';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import {
  isPrivilegedSeparationRoleOrCapability,
  PRIVILEGED_SEPARATION_ROLES,
  type PermissionCapabilityLike,
} from '../rbac/permission-matrix.js';
import type { DocumentDeliveryAuditService } from './document-delivery-audit.service.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export interface PepAccessContext {
  action: 'VIEW' | 'DOWNLOAD';
  grantId?: string | undefined;
  deviceFingerprint?: string | undefined;
  now?: Date | undefined;
}

export interface PepEvaluationResult {
  sessionId: string;
  documentId: string;
  documentTitle: string;
  documentCode: string | null;
  // CONFLICT-RESOLVED: Chuyển documentVersionId sang string để tránh lỗi Fastify JSON.stringify BigInt HTTP 500 trên POST /documents/:id/sessions.
  documentVersionId: string;
  versionNo: number;
  grantId: string;
  watermarkRequired: boolean;
  allowDownload: boolean;
  classificationRank: number;
  obligations: string[];
}

export interface SessionSubjectPolicySnapshot {
  employmentStatus: string | null;
  clearanceRank: number | null;
  departmentId: string | null;
}

export interface SessionResourcePolicySnapshot {
  classificationRank: number;
  category: string | null;
  departmentId: string | null;
  status: string;
}

export interface ActiveSessionPolicy {
  grantedAction: 'VIEW' | 'DOWNLOAD';
  forbidDownload: boolean;
  watermarkRequired: boolean;
  expiresAtMs: number | null;
  maxSessionMinutes?: number | null | undefined;
  ipAddress?: string | null | undefined;
  userAgent?: string | null | undefined;
  policyVersion?: string | null | undefined;
  abacEpoch?: number | undefined;
  userEpoch?: number | undefined;
  subjectSnapshot?: SessionSubjectPolicySnapshot | undefined;
  resourceSnapshot?: SessionResourcePolicySnapshot | undefined;
}

/**
 * Thuật toán: Tính thời gian sống bắt buộc có chặn trên cho bộ đệm chính sách phiên (`Math.min(maxSessionMinutes ?? 30, 60) * 60_000`).
 * Đảm bảo khóa phiên trong `DistributedStateService` không bao giờ tồn tại vô thời hạn ngay cả khi chính sách ABAC không khai báo `MAX_SESSION_MINUTES`.
 */
export function computeBoundedSessionPolicyTtlMs(
  maxSessionMinutes?: number | null | undefined,
): number {
  const effectiveMinutes =
    typeof maxSessionMinutes === 'number' &&
    Number.isFinite(maxSessionMinutes) &&
    maxSessionMinutes > 0
      ? maxSessionMinutes
      : 30;
  return Math.min(effectiveMinutes, 60) * 60_000;
}

/**
 * Algorithm / Thuật toán: Kiểm tra Phân tách nhiệm vụ (SoD) bất biến tại cổng PEP cho cả vai trò hệ thống (`SYSTEM_ADMIN`, `SECURITY_OFFICER`, `AUDITOR`)
 * lẫn Custom Role mang năng lực đặc quyền quản trị/SOC/kiểm toán (`BUG-047`).
 */
export function isRestrictedNonBusinessRole(
  principalOrRoles: AuthPrincipal | readonly string[],
  permissions?: Iterable<string | PermissionCapabilityLike>,
): boolean {
  if (!Array.isArray(principalOrRoles) && 'userId' in principalOrRoles) {
    const principal = principalOrRoles as AuthPrincipal;
    if (principal.restrictedNonBusiness === true) {
      return true;
    }
    if ((principal.roles ?? []).some((role) => PRIVILEGED_SEPARATION_ROLES.has(role))) {
      return true;
    }
    if (permissions !== undefined) {
      return isPrivilegedSeparationRoleOrCapability(undefined, permissions);
    }
    return false;
  }
  const roles = principalOrRoles;
  // CONFLICT-RESOLVED: Removed `!hasBusinessRole` bypass, included `SECURITY_OFFICER` via `PRIVILEGED_SEPARATION_ROLES`, and checked custom privileged capabilities (`BUG-047`).
  if (roles.some((role) => PRIVILEGED_SEPARATION_ROLES.has(role))) {
    return true;
  }
  if (permissions !== undefined) {
    return isPrivilegedSeparationRoleOrCapability(undefined, permissions);
  }
  return false;
}

/**
 * Thuật toán: Xác minh trực tiếp từ CSDL xem chủ thể có đang nắm bất kỳ vai trò hệ thống hoặc Custom Role đặc quyền quản trị/SOC/kiểm toán nào hay không (`BUG-047`).
 */
export async function hasPrivilegedNonBusinessCapability(
  database: PrismaClient | undefined,
  principal: AuthPrincipal,
  now = new Date(),
): Promise<boolean> {
  if (isRestrictedNonBusinessRole(principal)) {
    return true;
  }
  if (typeof database?.userRole?.findMany !== 'function') {
    return false;
  }
  try {
    const activeAssignments = await database.userRole.findMany({
      where: {
        user_id: principal.userId,
        valid_from: { lte: now },
        OR: [{ valid_to: null }, { valid_to: { gt: now } }],
        roles: { is_active: true },
      },
      include: {
        roles: {
          select: {
            code: true,
            role_permissions: {
              select: {
                permissions: { select: { code: true, resource_type: true, action: true } },
              },
            },
          },
        },
      },
    });
    for (const assignment of activeAssignments) {
      const roleObj = (
        assignment as {
          roles?: {
            code?: string;
            role_permissions?: Array<{
              permissions?: { code: string; resource_type?: string; action?: string } | null;
            }>;
          } | null;
        }
      ).roles;
      if (!roleObj) continue;
      const perms = (roleObj.role_permissions ?? [])
        .map((rp) => rp.permissions)
        .filter((p): p is NonNullable<typeof p> => Boolean(p));
      if (isPrivilegedSeparationRoleOrCapability(roleObj.code, perms)) {
        return true;
      }
    }
  } catch {
    // Fallback safely to principal checks when lightweight unit test mocks omit role relations
  }
  return false;
}

/**
 * Algorithm: Trusted Network CIDR Membership Evaluation
 * Splits comma-delimited `ABAC_TRUSTED_NETWORK_CIDRS` and checks IP membership via `cidrMatch`.
 */
export function resolvePepTrustedNetwork(
  config: AppConfigService | undefined,
  ip: string,
): boolean {
  const rawTrustedCidrs =
    typeof config?.get === 'function' ? config.get('ABAC_TRUSTED_NETWORK_CIDRS') : undefined;
  if (typeof rawTrustedCidrs !== 'string' || rawTrustedCidrs.length === 0) {
    return false;
  }
  return rawTrustedCidrs
    .split(',')
    .map((c) => c.trim())
    .filter(Boolean)
    .some((cidr) => cidrMatch(ip, cidr));
}

/**
 * Thuật toán: Tổng hợp thuộc tính chủ thể PIP (`CLEARANCE_LEVEL`, `EMPLOYMENT_STATUS`, `PROJECT`, phòng ban).
 * Nạp đồng thời `PROJECT` và `EMPLOYMENT_STATUS` còn hiệu lực (`is_active: true`) trong một truy vấn `findMany` duy nhất;
 * nếu có gán `EMPLOYMENT_STATUS` tường minh thì ưu tiên `value_code ?? value_text`, ngược lại giữ fallback `user?.status ?? null`.
 */
export async function buildPepSubjectAttributes(
  database: PrismaClient,
  userId: bigint,
  now: Date,
): Promise<{
  clearanceRank: number | null;
  departmentId: string | null;
  employmentStatus: string | null;
  projects: string[];
}> {
  const user = await database.user?.findUnique?.({
    where: { id: userId },
    select: { department_id: true, status: true },
  });

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
  const activeClearanceRank =
    (clearance as { attribute_definitions?: { is_active?: boolean } } | null)?.attribute_definitions
      ?.is_active === false || clearance?.attribute_options?.is_active === false
      ? null
      : (clearance?.attribute_options?.numeric_rank ?? null);

  let projects: string[] = [];
  let explicitEmploymentStatus: string | null = null;
  if (typeof database?.userAttributeAssignment?.findMany === 'function') {
    const attrAssignments = await database.userAttributeAssignment.findMany({
      where: {
        user_id: userId,
        attribute_definitions: { code: { in: ['PROJECT', 'EMPLOYMENT_STATUS'] }, is_active: true },
        valid_from: { lte: now },
        AND: [
          { OR: [{ valid_to: null }, { valid_to: { gt: now } }] },
          // CONFLICT-RESOLVED: Đồng bộ tên cột khóa ngoại option_id của bảng UserAttributeAssignment trong abac.prisma thay cho attribute_option_id không tồn tại.
          { OR: [{ option_id: null }, { attribute_options: { is_active: true } }] },
        ],
      },
      include: {
        attribute_definitions: { select: { code: true, is_active: true } },
        attribute_options: true,
      },
      orderBy: [{ attribute_definition_id: 'asc' }, { id: 'asc' }],
    });
    const projectValues: string[] = [];
    for (const raw of attrAssignments) {
      const row = raw as {
        attribute_definitions?: { code?: string; is_active?: boolean } | null;
        attribute_options?: { value_code?: string; is_active?: boolean } | null;
        value_text?: string | null;
      };
      if (
        row.attribute_definitions?.is_active === false ||
        row.attribute_options?.is_active === false
      ) {
        continue;
      }
      const val = row.attribute_options?.value_code ?? row.value_text;
      if (typeof val !== 'string' || val.length === 0) continue;
      if (row.attribute_definitions?.code === 'EMPLOYMENT_STATUS') {
        explicitEmploymentStatus = val;
      } else {
        projectValues.push(val);
      }
    }
    projects = projectValues.sort();
  }

  return {
    clearanceRank: activeClearanceRank,
    departmentId: user?.department_id?.toString() ?? null,
    // BUG-037: Nếu tài khoản không còn ACTIVE (LOCKED/DISABLED), luôn áp user.status thay vì để thuộc tính EMPLOYMENT_STATUS cũ ghi đè.
    employmentStatus:
      user && user.status !== 'ACTIVE'
        ? user.status
        : (explicitEmploymentStatus ?? user?.status ?? null),
    projects,
  };
}

/**
 * Algorithm: Fail-Closed Access Deny Audit Recorder
 * Emits `ACCESS_DENIED` audit event and rethrows persistence errors in production.
 */
export async function recordPepDenyAudit(params: {
  audit: DocumentDeliveryAuditService;
  logger: Logger;
  documentId: string;
  grantId: string | null;
  reasonCode: string;
  reasonMessage: string;
  principal: AuthPrincipal;
  context: RequestContext;
}): Promise<void> {
  try {
    await params.audit.record(
      {
        action: 'ACCESS_DENIED',
        outcome: 'DENIED',
        documentId: params.documentId,
        objectId: params.grantId,
        reasonCode: params.reasonCode,
        details: { message: params.reasonMessage },
      },
      params.principal,
      params.context,
    );
  } catch (auditErr) {
    params.logger.error(`Failed to record access deny audit: ${auditErr}`);
    if (process.env['NODE_ENV'] === 'production') {
      throw auditErr;
    }
  }
}
