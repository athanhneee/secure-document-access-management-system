/**
 * Module: Bounded Compliance Export Dataset Query & Tabular Row Builder
 * Thuật toán: Truy Vấn Tập Dữ Liệu Xuất Tuân Thủ Có Giới Hạn Bản Ghi & Chuẩn Hóa Dòng Bảng Theo Bộ Hợp Nhất `@sda/contracts`.
 */
import type { getDatabaseClient } from '@sda/database';
import {
  DEFAULT_SYSTEM_HEALTH_EXPORT_LIMIT,
  EXPORT_REPORT_SPECS,
  MAX_EXPORT_LIMIT,
  MAX_SYSTEM_HEALTH_EXPORT_LIMIT,
  projectExportRows,
  type ExportType,
} from '@sda/contracts';
import type { ExportDatasetPayload } from './export-artifact.helper.js';
import {
  buildAuditLogExportWhere,
  buildIncidentReportExportWhere,
  buildSecurityAlertExportWhere,
  buildSystemHealthExportWhere,
  normalizeExportFilters,
} from './export-filter-scope.helper.js';

export {
  mapExportJobToDetail,
  renderExportBuffer,
  resolveExportDownloadMeta,
  type ExportDatasetPayload,
  type ExportJobDetail,
} from './export-artifact.helper.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

/**
 * Algorithm: Bounded Compliance Dataset Query & Tabular Row Projection
 */
export async function buildExportDataset(
  database: PrismaClient,
  exportType: ExportType,
  filterParams: unknown = {},
  allowedDepartmentIds: bigint[] | null = null,
): Promise<ExportDatasetPayload> {
  const filters = normalizeExportFilters(filterParams, allowedDepartmentIds, exportType);
  const scopeEmpty =
    filters.effectiveDepartmentIds !== null && filters.effectiveDepartmentIds.length === 0;
  const spec = EXPORT_REPORT_SPECS[exportType];

  switch (exportType) {
    case 'AUDIT_LOGS': {
      const logs = scopeEmpty
        ? []
        : await database.auditLog.findMany({
            where: buildAuditLogExportWhere(filters),
            take: filters.limit ?? MAX_EXPORT_LIMIT,
            orderBy: { occurred_at: 'desc' },
          });
      return {
        exportType,
        reportTitle: spec.reportTitle,
        rawRecords: logs,
        columns: [...spec.columns],
        rows: projectExportRows('AUDIT_LOGS', logs as unknown as Record<string, unknown>[]),
      };
    }

    case 'SECURITY_ALERTS': {
      const alerts = scopeEmpty
        ? []
        : await database.securityAlert.findMany({
            where: buildSecurityAlertExportWhere(filters),
            take: filters.limit ?? MAX_EXPORT_LIMIT,
            orderBy: { detected_at: 'desc' },
          });
      return {
        exportType,
        reportTitle: spec.reportTitle,
        rawRecords: alerts,
        columns: [...spec.columns],
        rows: projectExportRows('SECURITY_ALERTS', alerts as unknown as Record<string, unknown>[]),
      };
    }

    case 'INCIDENT_REPORTS': {
      const incidents = scopeEmpty
        ? []
        : await database.incidentReport.findMany({
            where: buildIncidentReportExportWhere(filters),
            take: filters.limit ?? MAX_EXPORT_LIMIT,
            orderBy: { created_at: 'desc' },
          });
      return {
        exportType,
        reportTitle: spec.reportTitle,
        rawRecords: incidents,
        columns: [...spec.columns],
        rows: projectExportRows(
          'INCIDENT_REPORTS',
          incidents as unknown as Record<string, unknown>[],
        ),
      };
    }

    case 'SYSTEM_REPORT': {
      const snapshots = scopeEmpty
        ? []
        : await database.systemHealthSnapshot.findMany({
            where: buildSystemHealthExportWhere(filters),
            take: Math.min(
              filters.limit ?? DEFAULT_SYSTEM_HEALTH_EXPORT_LIMIT,
              MAX_SYSTEM_HEALTH_EXPORT_LIMIT,
            ),
            orderBy: { captured_at: 'desc' },
          });
      return {
        exportType,
        reportTitle: spec.reportTitle,
        rawRecords: snapshots,
        columns: [...spec.columns],
        rows: projectExportRows('SYSTEM_REPORT', snapshots as unknown as Record<string, unknown>[]),
      };
    }
  }
}
