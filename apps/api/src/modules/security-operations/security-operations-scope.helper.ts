/**
 * @module SecurityOperationsScopeHelper
 * Algorithm: Department-Subtree Visibility Scoping for SOC Alerts & Incident Reports (HIGH-13).
 */
import { NotFoundException } from '@nestjs/common';
import type { Prisma, getDatabaseClient } from '@sda/database';
import { AppErrorCode } from '@sda/contracts';
import type { AuthPrincipal } from '../auth/auth.types.js';
import type { AuthorizationService } from '../rbac/authorization.service.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

/**
 * Thuật toán: Phân giải danh sách phòng ban được phép truy cập cảnh báo an ninh (`null` = toàn cục).
 */
export async function resolveAlertDepartmentScope(
  authorization: AuthorizationService | undefined,
  actor: AuthPrincipal | undefined,
  action: 'VIEW' | 'MANAGE',
): Promise<bigint[] | null> {
  // CONFLICT-RESOLVED: Chặn Fail-Open thành phạm vi toàn cục (`null`) khi thiếu `actor` hoặc dịch vụ phân quyền trong môi trường chạy thật (HIGH-08).
  if (!actor) return [];
  if (!authorization) {
    if (process.env['NODE_ENV'] === 'production') return [];
    const roles = actor.roles ?? [];
    return roles.includes('SECURITY_OFFICER') ||
      roles.includes('SYSTEM_ADMIN') ||
      (action === 'VIEW' && roles.includes('AUDITOR'))
      ? null
      : [];
  }
  if (action === 'MANAGE') {
    return authorization.visibleDepartmentIds(actor, 'SECURITY_ALERT', 'MANAGE');
  }
  const [viewScope, manageScope] = await Promise.all([
    authorization.visibleDepartmentIds(actor, 'SECURITY_ALERT', 'VIEW'),
    authorization.visibleDepartmentIds(actor, 'SECURITY_ALERT', 'MANAGE'),
  ]);
  if (viewScope === null || manageScope === null) return null;
  return [...new Map([...viewScope, ...manageScope].map((id) => [id.toString(), id])).values()];
}

/**
 * Thuật toán: Giao điều kiện lọc cảnh báo với phạm vi phòng ban của người dùng bị phát hiện hoặc tài liệu liên quan.
 */
export function applyAlertScopeToWhere(
  baseWhere: Prisma.SecurityAlertWhereInput,
  allowedDepartmentIds: bigint[] | null,
): Prisma.SecurityAlertWhereInput {
  if (allowedDepartmentIds === null) return baseWhere;
  // CONFLICT-RESOLVED: Giới hạn danh sách và chi tiết cảnh báo theo bao đóng phòng ban được cấp quyền (HIGH-13)
  return {
    AND: [
      baseWhere,
      {
        OR: [
          {
            users_security_alerts_detected_user_idTousers: {
              department_id: { in: allowedDepartmentIds },
            },
          },
          { documents: { department_id: { in: allowedDepartmentIds } } },
        ],
      },
    ],
  };
}

/**
 * Thuật toán: Chặn truy cập hoặc cập nhật cảnh báo nằm ngoài phạm vi phòng ban bằng phản hồi chống dò quét `404 ALERT_NOT_FOUND`.
 */
export async function assertAlertInDepartmentScope(
  database: PrismaClient,
  authorization: AuthorizationService | undefined,
  actor: AuthPrincipal | undefined,
  alertId: string,
  action: 'VIEW' | 'MANAGE',
): Promise<void> {
  const allowedDepartmentIds = await resolveAlertDepartmentScope(authorization, actor, action);
  if (allowedDepartmentIds === null || typeof database?.securityAlert?.findFirst !== 'function') {
    return;
  }
  const scoped = await database.securityAlert.findFirst({
    where: applyAlertScopeToWhere({ id: alertId }, allowedDepartmentIds),
    select: { id: true },
  });
  if (!scoped) {
    throw new NotFoundException({
      errorCode: AppErrorCode.ALERT_NOT_FOUND,
      message: `Security alert ${alertId} was not found.`,
    });
  }
}

/**
 * Thuật toán: Phân giải phạm vi phòng ban cho báo cáo sự cố an ninh (`null` = toàn cục).
 */
export async function resolveIncidentDepartmentScope(
  authorization: AuthorizationService | undefined,
  actor: AuthPrincipal | undefined,
  mode: 'VIEW' | 'MANAGE',
): Promise<bigint[] | null> {
  if (!actor) return [];
  if (!authorization) {
    if (process.env['NODE_ENV'] === 'production') return [];
    const roles = actor.roles ?? [];
    return roles.includes('SECURITY_OFFICER') ||
      roles.includes('SYSTEM_ADMIN') ||
      (mode === 'VIEW' && roles.includes('AUDITOR'))
      ? null
      : [];
  }
  if (mode === 'MANAGE') {
    return authorization.visibleDepartmentIds(actor, 'INCIDENT_REPORT', 'MANAGE');
  }
  const [viewScope, manageScope] = await Promise.all([
    authorization.visibleDepartmentIds(actor, 'SECURITY_ALERT', 'VIEW'),
    authorization.visibleDepartmentIds(actor, 'INCIDENT_REPORT', 'MANAGE'),
  ]);
  if (viewScope === null || manageScope === null) return null;
  return [...new Map([...viewScope, ...manageScope].map((id) => [id.toString(), id])).values()];
}

/**
 * Thuật toán: Giao điều kiện lọc báo cáo sự cố với phạm vi phòng ban của người lập báo cáo hoặc cảnh báo gốc.
 */
export function applyIncidentScopeToWhere(
  baseWhere: Prisma.IncidentReportWhereInput,
  allowedDepartmentIds: bigint[] | null,
): Prisma.IncidentReportWhereInput {
  if (allowedDepartmentIds === null) return baseWhere;
  return {
    AND: [
      baseWhere,
      {
        OR: [
          {
            users_incident_reports_prepared_byTousers: {
              department_id: { in: allowedDepartmentIds },
            },
          },
          {
            security_alerts: {
              OR: [
                { documents: { department_id: { in: allowedDepartmentIds } } },
                {
                  users_security_alerts_detected_user_idTousers: {
                    department_id: { in: allowedDepartmentIds },
                  },
                },
              ],
            },
          },
        ],
      },
    ],
  };
}

/**
 * Thuật toán: Chặn xem hoặc thao tác hồ sơ sự cố nằm ngoài phạm vi phòng ban bằng `404 INCIDENT_NOT_FOUND`.
 */
export async function assertIncidentInDepartmentScope(
  database: PrismaClient,
  authorization: AuthorizationService | undefined,
  actor: AuthPrincipal | undefined,
  incidentId: string,
  mode: 'VIEW' | 'MANAGE',
): Promise<void> {
  const allowedDepartmentIds = await resolveIncidentDepartmentScope(authorization, actor, mode);
  if (allowedDepartmentIds === null || typeof database?.incidentReport?.findFirst !== 'function') {
    return;
  }
  const scoped = await database.incidentReport.findFirst({
    where: applyIncidentScopeToWhere({ id: incidentId }, allowedDepartmentIds),
    select: { id: true },
  });
  if (!scoped) {
    throw new NotFoundException({
      errorCode: AppErrorCode.INCIDENT_NOT_FOUND,
      message: `Incident report ${incidentId} was not found.`,
    });
  }
}
