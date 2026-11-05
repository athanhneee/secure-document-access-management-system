/**
 * Module: Scoped Prisma Export `where` Clause Builders
 * Algorithm: Translates normalized export filters and department subtree scopes (`effectiveDepartmentIds`)
 *   into type-safe Prisma `where` inputs for `AuditLog`, `SecurityAlert`, `IncidentReport`, and `SystemHealthSnapshot`.
 */
import type { Prisma } from '@sda/database';
import type { NormalizedExportFilters } from './export-filter-scope.helper.js';

/**
 * Algorithm: Department-Scoped Audit Log Export Filter Builder
 */
export function buildAuditLogExportWhere(
  filters: NormalizedExportFilters,
): Prisma.AuditLogWhereInput {
  const where: Prisma.AuditLogWhereInput = {};
  if (filters.fromDate || filters.toDate) {
    where.occurred_at = {
      ...(filters.fromDate ? { gte: filters.fromDate } : {}),
      ...(filters.toDate ? { lte: filters.toDate } : {}),
    };
  }
  if (filters.actorUserId !== null) where.actor_user_id = filters.actorUserId;
  if (filters.actorUsername) where.actor_username = filters.actorUsername;
  if (filters.documentId) where.document_id = filters.documentId;
  if (filters.action) where.action = filters.action;
  if (filters.outcome) where.outcome = filters.outcome;
  if (filters.chainPartition) where.chain_partition = filters.chainPartition;
  if (filters.effectiveDepartmentIds !== null) {
    where.OR = [
      { users: { department_id: { in: filters.effectiveDepartmentIds } } },
      { documents: { department_id: { in: filters.effectiveDepartmentIds } } },
    ];
  }
  return where;
}

/**
 * Algorithm: Department-Scoped Security Alert Export Filter Builder
 */
export function buildSecurityAlertExportWhere(
  filters: NormalizedExportFilters,
): Prisma.SecurityAlertWhereInput {
  const where: Prisma.SecurityAlertWhereInput = {};
  if (filters.fromDate || filters.toDate) {
    where.detected_at = {
      ...(filters.fromDate ? { gte: filters.fromDate } : {}),
      ...(filters.toDate ? { lte: filters.toDate } : {}),
    };
  }
  if (filters.actorUserId !== null) where.detected_user_id = filters.actorUserId;
  if (filters.documentId) where.document_id = filters.documentId;
  if (filters.severity) where.severity = filters.severity;
  if (
    filters.status === 'OPEN' ||
    filters.status === 'INVESTIGATING' ||
    filters.status === 'RESOLVED' ||
    filters.status === 'FALSE_POSITIVE'
  ) {
    where.status = filters.status;
  }
  if (filters.alertType) where.alert_type = filters.alertType;
  if (filters.effectiveDepartmentIds !== null) {
    where.OR = [
      {
        users_security_alerts_detected_user_idTousers: {
          department_id: { in: filters.effectiveDepartmentIds },
        },
      },
      { documents: { department_id: { in: filters.effectiveDepartmentIds } } },
    ];
  }
  return where;
}

/**
 * Algorithm: Department-Scoped Incident Report Export Filter Builder
 */
export function buildIncidentReportExportWhere(
  filters: NormalizedExportFilters,
): Prisma.IncidentReportWhereInput {
  const where: Prisma.IncidentReportWhereInput = {};
  if (filters.fromDate || filters.toDate) {
    where.created_at = {
      ...(filters.fromDate ? { gte: filters.fromDate } : {}),
      ...(filters.toDate ? { lte: filters.toDate } : {}),
    };
  }
  if (filters.actorUserId !== null) where.prepared_by = filters.actorUserId;
  if (filters.incidentCode) where.incident_code = filters.incidentCode;
  if (filters.status === 'DRAFT' || filters.status === 'SUBMITTED' || filters.status === 'CLOSED') {
    where.status = filters.status;
  }
  if (filters.effectiveDepartmentIds !== null) {
    where.OR = [
      {
        users_incident_reports_prepared_byTousers: {
          department_id: { in: filters.effectiveDepartmentIds },
        },
      },
      {
        security_alerts: {
          OR: [
            { documents: { department_id: { in: filters.effectiveDepartmentIds } } },
            {
              users_security_alerts_detected_user_idTousers: {
                department_id: { in: filters.effectiveDepartmentIds },
              },
            },
          ],
        },
      },
    ];
  }
  return where;
}

/**
 * Algorithm: System Health Snapshot Export Filter Builder
 */
export function buildSystemHealthExportWhere(
  filters: NormalizedExportFilters,
): Prisma.SystemHealthSnapshotWhereInput {
  const where: Prisma.SystemHealthSnapshotWhereInput = {};
  if (filters.fromDate || filters.toDate) {
    where.captured_at = {
      ...(filters.fromDate ? { gte: filters.fromDate } : {}),
      ...(filters.toDate ? { lte: filters.toDate } : {}),
    };
  }
  if (filters.serviceName) where.service_name = filters.serviceName;
  if (filters.status) where.status = filters.status;
  return where;
}
