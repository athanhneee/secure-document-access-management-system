/**
 * Module: Scoped Prisma Export `where` Clause Builders
 * Thuật toán: Ủy quyền trực tiếp sang bộ biên dịch `where` dùng chung `@sda/contracts`
 * bảo đảm 100% đồng nhất truy vấn giữa `@sda/api` và `@sda/worker`.
 */
import type { Prisma } from '@sda/database';
import {
  buildAuditLogExportWhere as buildSharedAuditLogExportWhere,
  buildIncidentReportExportWhere as buildSharedIncidentReportExportWhere,
  buildSecurityAlertExportWhere as buildSharedSecurityAlertExportWhere,
  buildSystemHealthExportWhere as buildSharedSystemHealthExportWhere,
  type NormalizedExportFilters,
} from '@sda/contracts';

/**
 * Algorithm: Department-Scoped Audit Log Export Filter Builder
 */
export function buildAuditLogExportWhere(
  filters: NormalizedExportFilters,
): Prisma.AuditLogWhereInput {
  return buildSharedAuditLogExportWhere(filters) as Prisma.AuditLogWhereInput;
}

/**
 * Algorithm: Department-Scoped Security Alert Export Filter Builder
 */
export function buildSecurityAlertExportWhere(
  filters: NormalizedExportFilters,
): Prisma.SecurityAlertWhereInput {
  return buildSharedSecurityAlertExportWhere(filters) as Prisma.SecurityAlertWhereInput;
}

/**
 * Algorithm: Department-Scoped Incident Report Export Filter Builder
 */
export function buildIncidentReportExportWhere(
  filters: NormalizedExportFilters,
): Prisma.IncidentReportWhereInput {
  return buildSharedIncidentReportExportWhere(filters) as Prisma.IncidentReportWhereInput;
}

/**
 * Algorithm: System Health Snapshot Export Filter Builder
 */
export function buildSystemHealthExportWhere(
  filters: NormalizedExportFilters,
): Prisma.SystemHealthSnapshotWhereInput {
  return buildSharedSystemHealthExportWhere(filters) as Prisma.SystemHealthSnapshotWhereInput;
}
