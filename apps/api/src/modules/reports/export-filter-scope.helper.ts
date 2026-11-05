/**
 * Module: Export RBAC Scope Resolver & Parameterized Compliance Filter Normalizer
 * Algorithm / Thuật toán: Phân Giải Quyền RBAC Theo Miền Báo Cáo & Chuẩn Hóa Bộ Lọc Có Phạm Vi Phòng Ban (Scoped Compliance Export Filter)
 *   1. Đối chiếu từng `exportType` với đúng quyền RBAC miền dữ liệu tương ứng để ngăn chặn lệch quyền chéo miền.
 *   2. Thu thập bao đóng phân cấp phòng ban (`allowedDepartmentIds`) và chuẩn hóa `filterParams` an toàn kiểu.
 */
import { BadRequestException, ForbiddenException } from '@nestjs/common';
import { AppErrorCode, type ExportType } from '@sda/contracts';
import type { AuthPrincipal } from '../auth/auth.types.js';
import type { AuthorizationService } from '../rbac/authorization.service.js';

export {
  buildAuditLogExportWhere,
  buildIncidentReportExportWhere,
  buildSecurityAlertExportWhere,
  buildSystemHealthExportWhere,
} from './export-where-builders.helper.js';

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ISO_DATE_ONLY_REGEX = /^\d{4}-\d{2}-\d{2}$/;

export interface NormalizedExportFilters {
  fromDate: Date | null;
  toDate: Date | null;
  effectiveDepartmentIds: bigint[] | null;
  actorUserId: bigint | null;
  actorUsername: string | null;
  documentId: string | null;
  action: string | null;
  outcome: string | null;
  chainPartition: string | null;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | null;
  status: string | null;
  alertType: string | null;
  incidentCode: string | null;
  serviceName: string | null;
  limit: number | null;
}

function parseOptionalBigInt(raw: unknown, fieldName: string): bigint | null {
  if (raw === undefined || raw === null || raw === '') return null;
  if (typeof raw === 'bigint') return raw > 0n ? raw : null;
  const str = String(raw).trim();
  if (!/^\d+$/.test(str)) {
    throw new BadRequestException(`Invalid numeric identifier in filterParams.${fieldName}.`);
  }
  const value = BigInt(str);
  if (value <= 0n) {
    throw new BadRequestException(`filterParams.${fieldName} must be a positive integer.`);
  }
  return value;
}

function parseOptionalDate(raw: unknown, fieldName: string, endOfDay = false): Date | null {
  if (raw === undefined || raw === null || raw === '') return null;
  if (raw instanceof Date) {
    if (!Number.isFinite(raw.getTime())) {
      throw new BadRequestException(`Invalid date in filterParams.${fieldName}.`);
    }
    return raw;
  }
  if (typeof raw !== 'string') {
    throw new BadRequestException(`Invalid date string in filterParams.${fieldName}.`);
  }
  const trimmed = raw.trim();
  const normalized = ISO_DATE_ONLY_REGEX.test(trimmed)
    ? `${trimmed}${endOfDay ? 'T23:59:59.999Z' : 'T00:00:00.000Z'}`
    : trimmed;
  const ts = Date.parse(normalized);
  if (!Number.isFinite(ts)) {
    throw new BadRequestException(`Malformed date in filterParams.${fieldName}.`);
  }
  return new Date(ts);
}

function parseOptionalString(raw: unknown, maxLength = 100): string | null {
  if (raw === undefined || raw === null) return null;
  const trimmed = String(raw).trim();
  return trimmed ? trimmed.slice(0, maxLength) : null;
}

/**
 * Algorithm / Thuật toán: Thẩm Định Quyền Xuất Báo Cáo Theo Miền & Trích Xuất Phạm Vi Phòng Ban Cho Phép
 */
export async function resolveExportAuthorizationScope(
  authorization: AuthorizationService | undefined,
  actor: AuthPrincipal,
  exportType: ExportType,
): Promise<bigint[] | null> {
  if (!authorization) return null;

  switch (exportType) {
    case 'AUDIT_LOGS': {
      const allowed = await authorization.hasPermission(actor, 'AUDIT_LOG', 'EXPORT', {
        anyScope: true,
      });
      if (!allowed) {
        throw new ForbiddenException({
          errorCode: AppErrorCode.EXPORT_UNAUTHORIZED,
          message: 'AUDIT_LOG:EXPORT permission is required to export audit logs.',
        });
      }
      return authorization.visibleDepartmentIds(actor, 'AUDIT_LOG', 'EXPORT');
    }

    case 'SECURITY_ALERTS': {
      const canManageAlerts = await authorization.hasPermission(actor, 'SECURITY_ALERT', 'MANAGE', {
        anyScope: true,
      });
      const canViewAlerts = await authorization.hasPermission(actor, 'SECURITY_ALERT', 'VIEW', {
        anyScope: true,
      });
      const canExportSystemReports = await authorization.hasPermission(
        actor,
        'SYSTEM_REPORT',
        'EXPORT',
        { anyScope: true },
      );

      if (!canManageAlerts && !(canViewAlerts && canExportSystemReports)) {
        throw new ForbiddenException({
          errorCode: AppErrorCode.EXPORT_UNAUTHORIZED,
          message:
            'SECURITY_ALERT:MANAGE or (SECURITY_ALERT:VIEW + SYSTEM_REPORT:EXPORT) permission is required to export security alerts.',
        });
      }
      return canManageAlerts
        ? authorization.visibleDepartmentIds(actor, 'SECURITY_ALERT', 'MANAGE')
        : authorization.visibleDepartmentIds(actor, 'SECURITY_ALERT', 'VIEW');
    }

    case 'INCIDENT_REPORTS': {
      const canManageIncidents = await authorization.hasPermission(
        actor,
        'INCIDENT_REPORT',
        'MANAGE',
        { anyScope: true },
      );
      if (!canManageIncidents) {
        throw new ForbiddenException({
          errorCode: AppErrorCode.EXPORT_UNAUTHORIZED,
          message: 'INCIDENT_REPORT:MANAGE permission is required to export incident reports.',
        });
      }
      return authorization.visibleDepartmentIds(actor, 'INCIDENT_REPORT', 'MANAGE');
    }

    case 'SYSTEM_REPORT': {
      const canExportSystemReport = await authorization.hasPermission(
        actor,
        'SYSTEM_REPORT',
        'EXPORT',
        { requireGlobal: true },
      );
      const canViewSystemHealth = await authorization.hasPermission(
        actor,
        'SYSTEM_HEALTH',
        'VIEW',
        { requireGlobal: true },
      );
      if (!canExportSystemReport && !canViewSystemHealth) {
        throw new ForbiddenException({
          errorCode: AppErrorCode.EXPORT_UNAUTHORIZED,
          message:
            'Global SYSTEM_REPORT:EXPORT or SYSTEM_HEALTH:VIEW permission is required to export system health reports.',
        });
      }
      return null;
    }
  }
}

/**
 * Algorithm / Thuật toán: Chuẩn Hóa Tham Số Lọc & Giao Với Bao Đóng Phòng Ban Được Cấp Quyền
 */
export function normalizeExportFilters(
  rawFilterParams: unknown,
  allowedDepartmentIds: bigint[] | null = null,
): NormalizedExportFilters {
  const params =
    rawFilterParams && typeof rawFilterParams === 'object' && !Array.isArray(rawFilterParams)
      ? (rawFilterParams as Record<string, unknown>)
      : {};

  const fromDate = parseOptionalDate(params['from'] ?? params['startDate'], 'from', false);
  const toDate = parseOptionalDate(params['to'] ?? params['endDate'], 'to', true);
  if (fromDate && toDate && fromDate.getTime() > toDate.getTime()) {
    throw new BadRequestException('filterParams.from must not be later than filterParams.to.');
  }

  const requestedDepartmentId = parseOptionalBigInt(params['departmentId'], 'departmentId');
  let effectiveDepartmentIds: bigint[] | null = allowedDepartmentIds;

  if (requestedDepartmentId !== null) {
    if (allowedDepartmentIds !== null && !allowedDepartmentIds.includes(requestedDepartmentId)) {
      throw new ForbiddenException({
        errorCode: AppErrorCode.EXPORT_UNAUTHORIZED,
        message: 'Requested departmentId is outside your authorized export scope.',
      });
    }
    effectiveDepartmentIds = [requestedDepartmentId];
  }

  const actorUserId = parseOptionalBigInt(
    params['actorUserId'] ?? params['userId'] ?? params['detectedUserId'] ?? params['preparedBy'],
    'actorUserId',
  );
  const actorUsername = parseOptionalString(params['actorUsername'], 80);

  const rawDocId = parseOptionalString(params['documentId'], 64);
  if (rawDocId && !UUID_REGEX.test(rawDocId)) {
    throw new BadRequestException('filterParams.documentId must be a valid UUID.');
  }

  const rawSeverity = parseOptionalString(params['severity'], 20)?.toUpperCase() ?? null;
  const severity =
    rawSeverity === 'LOW' ||
    rawSeverity === 'MEDIUM' ||
    rawSeverity === 'HIGH' ||
    rawSeverity === 'CRITICAL'
      ? rawSeverity
      : null;

  let limit: number | null = null;
  if (params['limit'] !== undefined && params['limit'] !== null && params['limit'] !== '') {
    const parsedLimit = Number(params['limit']);
    if (!Number.isInteger(parsedLimit) || parsedLimit < 1) {
      throw new BadRequestException('filterParams.limit must be a positive integer.');
    }
    limit = Math.min(parsedLimit, 1000);
  }

  return {
    fromDate,
    toDate,
    effectiveDepartmentIds,
    actorUserId,
    actorUsername,
    documentId: rawDocId,
    action: parseOptionalString(params['action'], 100),
    outcome: parseOptionalString(params['outcome'], 20)?.toUpperCase() ?? null,
    chainPartition: parseOptionalString(params['chainPartition'], 80),
    severity,
    status: parseOptionalString(params['status'], 30)?.toUpperCase() ?? null,
    alertType: parseOptionalString(params['alertType'] ?? params['ruleCode'], 80),
    incidentCode: parseOptionalString(params['incidentCode'], 50),
    serviceName: parseOptionalString(params['serviceName'], 100),
    limit,
  };
}
