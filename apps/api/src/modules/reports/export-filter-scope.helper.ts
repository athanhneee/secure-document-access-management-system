/**
 * Module: Export RBAC Scope Resolver & Parameterized Compliance Filter Normalizer
 * Algorithm / Thuật toán: Phân Giải Quyền RBAC Theo Miền Báo Cáo & Chuẩn Hóa Bộ Lọc Có Phạm Vi Phòng Ban (Scoped Compliance Export Filter)
 *   1. Đối chiếu từng `exportType` với đúng quyền RBAC miền dữ liệu tương ứng để ngăn chặn lệch quyền chéo miền.
 *   2. Thu thập bao đóng phân cấp phòng ban (`allowedDepartmentIds`) và chuẩn hóa `filterParams` an toàn kiểu.
 */
import { BadRequestException, ForbiddenException } from '@nestjs/common';
import {
  AppErrorCode,
  ExportFilterValidationError,
  normalizeExportFilters as normalizeSharedExportFilters,
  type ExportType,
  type NormalizedExportFilters,
} from '@sda/contracts';
import type { AuthPrincipal } from '../auth/auth.types.js';
import type { AuthorizationService } from '../rbac/authorization.service.js';

export type { NormalizedExportFilters };

export {
  buildAuditLogExportWhere,
  buildIncidentReportExportWhere,
  buildSecurityAlertExportWhere,
  buildSystemHealthExportWhere,
} from './export-where-builders.helper.js';

/**
 * Algorithm / Thuật toán: Thẩm Định Quyền Xuất Báo Cáo Theo Miền & Trích Xuất Phạm Vi Phòng Ban Cho Phép
 */
export async function resolveExportAuthorizationScope(
  authorization: AuthorizationService | undefined,
  actor: AuthPrincipal,
  exportType: ExportType,
): Promise<bigint[] | null> {
  // CONFLICT-RESOLVED: Áp dụng cơ chế đóng an toàn (fail-closed) khi thiếu dịch vụ phân quyền thay vì trả về null (MED-06)
  if (!authorization) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.EXPORT_UNAUTHORIZED,
      message: 'Authorization service is required to evaluate export scope.',
    });
  }

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
 * Ủy quyền hoàn toàn cho bộ chuẩn hóa dùng chung `@sda/contracts` để đảm bảo đồng nhất 100% giữa API và Worker.
 */
export function normalizeExportFilters(
  rawFilterParams: unknown,
  allowedDepartmentIds: bigint[] | null = null,
  exportType?: ExportType,
): NormalizedExportFilters {
  try {
    return normalizeSharedExportFilters(rawFilterParams, allowedDepartmentIds, exportType);
  } catch (err) {
    if (err instanceof ExportFilterValidationError) {
      if (err.status === 403) {
        throw new ForbiddenException({
          errorCode: err.errorCode,
          message: err.message,
        });
      }
      throw new BadRequestException({
        errorCode: err.errorCode,
        message: err.message,
      });
    }
    throw err;
  }
}
