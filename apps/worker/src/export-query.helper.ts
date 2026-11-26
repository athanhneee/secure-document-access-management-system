import { type getDatabaseClient } from '@sda/database';
import {
  DEFAULT_SYSTEM_HEALTH_EXPORT_LIMIT,
  MAX_EXPORT_LIMIT,
  MAX_SYSTEM_HEALTH_EXPORT_LIMIT,
  buildAuditLogExportWhere,
  buildIncidentReportExportWhere,
  buildSecurityAlertExportWhere,
  buildSystemHealthExportWhere,
  extractPersistedExportScope,
  normalizeExportFilters,
  parseExportDateBound,
  parseRawFilterParamsObject,
  projectExportRows,
  type ExportType,
} from '@sda/contracts';

/**
 * Thuật toán / Tổng quan module:
 * Bộ truy vấn dữ liệu kết xuất bất đồng bộ dùng chung 100% logic chuẩn hóa bộ lọc, mệnh đề `where` Prisma
 * và chiếu dòng bảng từ `@sda/contracts` với `@sda/api` (triệt tiêu hoàn toàn phân kỳ API vs Worker).
 */

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export function parseFilterParams(raw: unknown): Record<string, unknown> {
  return parseRawFilterParamsObject(raw);
}

/**
 * Thuật toán: Phân tích mốc thời gian đầu/cuối ngày cho chuỗi ngày thuần `YYYY-MM-DD` (Inclusive End-of-Day Bound)
 * ủy quyền trực tiếp cho bộ chuẩn hóa dùng chung `@sda/contracts`.
 */
export function parseDateBound(raw: unknown, endOfDay = false): Date | undefined {
  return parseExportDateBound(raw, endOfDay);
}

/**
 * Thuật toán: Truy vấn tập bản ghi báo cáo theo `exportType` áp dụng đúng bộ chuẩn hóa,
 * phạm vi phòng ban (`__allowedDepartmentIds` giao với `departmentId`), khớp UUID `correlation_id`
 * bằng `equals`, hỗ trợ `IN_REVIEW` và giới hạn trần đồng nhất với `@sda/api`.
 */
export async function queryExportDataset(
  database: PrismaClient,
  exportType: string,
  filterParams: Record<string, unknown>,
): Promise<Record<string, unknown>[]> {
  if (
    exportType !== 'AUDIT_LOGS' &&
    exportType !== 'SECURITY_ALERTS' &&
    exportType !== 'INCIDENT_REPORTS' &&
    exportType !== 'SYSTEM_REPORT'
  ) {
    throw new Error(`Unsupported export_type: ${exportType}`);
  }

  const typedExportType = exportType as ExportType;
  const { cleanFilterParams, allowedDepartmentIds } = extractPersistedExportScope(filterParams);
  const filters = normalizeExportFilters(cleanFilterParams, allowedDepartmentIds, typedExportType);
  const scopeEmpty =
    filters.effectiveDepartmentIds !== null && filters.effectiveDepartmentIds.length === 0;

  if (scopeEmpty) {
    return [];
  }

  if (typedExportType === 'AUDIT_LOGS') {
    const logs = (await database.auditLog.findMany({
      where: buildAuditLogExportWhere(filters) as never,
      orderBy: { occurred_at: 'desc' },
      take: filters.limit ?? MAX_EXPORT_LIMIT,
    })) as unknown as Record<string, unknown>[];
    return projectExportRows('AUDIT_LOGS', logs);
  }

  if (typedExportType === 'SECURITY_ALERTS') {
    const alerts = (await database.securityAlert.findMany({
      where: buildSecurityAlertExportWhere(filters) as never,
      orderBy: { detected_at: 'desc' },
      take: filters.limit ?? MAX_EXPORT_LIMIT,
    })) as unknown as Record<string, unknown>[];
    return projectExportRows('SECURITY_ALERTS', alerts);
  }

  if (typedExportType === 'INCIDENT_REPORTS') {
    const incidents = (await database.incidentReport.findMany({
      where: buildIncidentReportExportWhere(filters) as never,
      orderBy: { created_at: 'desc' },
      take: filters.limit ?? MAX_EXPORT_LIMIT,
    })) as unknown as Record<string, unknown>[];
    return projectExportRows('INCIDENT_REPORTS', incidents);
  }

  const snapshots = (await database.systemHealthSnapshot.findMany({
    where: buildSystemHealthExportWhere(filters) as never,
    orderBy: { captured_at: 'desc' },
    take: Math.min(
      filters.limit ?? DEFAULT_SYSTEM_HEALTH_EXPORT_LIMIT,
      MAX_SYSTEM_HEALTH_EXPORT_LIMIT,
    ),
  })) as unknown as Record<string, unknown>[];
  return projectExportRows('SYSTEM_REPORT', snapshots);
}
