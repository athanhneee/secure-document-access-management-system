/**
 * Module: Bounded Compliance Export Dataset Query & Tabular Row Builder
 * Algorithm: Dispatches bounded queries (`take: 1000` / `50`) by `exportType` (`AUDIT_LOGS`,
 *   `SECURITY_ALERTS`, `INCIDENT_REPORTS`, `SYSTEM_REPORT`) and normalizes records into string-keyed rows.
 */
import type { getDatabaseClient } from '@sda/database';
import type { ExportType } from '@sda/contracts';
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
  const filters = normalizeExportFilters(filterParams, allowedDepartmentIds);
  const scopeEmpty =
    filters.effectiveDepartmentIds !== null && filters.effectiveDepartmentIds.length === 0;

  switch (exportType) {
    case 'AUDIT_LOGS': {
      const logs = scopeEmpty
        ? []
        : await database.auditLog.findMany({
            where: buildAuditLogExportWhere(filters),
            take: filters.limit ?? 1000,
            orderBy: { occurred_at: 'desc' },
          });
      return {
        reportTitle: 'Secure Document Access - Audit Trail Report',
        rawRecords: logs,
        columns: [
          { key: 'id', header: 'Log ID' },
          { key: 'occurred_at', header: 'Timestamp (UTC)' },
          { key: 'actor_username', header: 'Actor' },
          { key: 'action', header: 'Action' },
          { key: 'object_type', header: 'Resource Type' },
          { key: 'object_id', header: 'Resource ID' },
          { key: 'outcome', header: 'Outcome' },
          { key: 'ip_address', header: 'IP Address' },
          { key: 'chain_partition', header: 'Partition' },
          { key: 'chain_sequence', header: 'Sequence' },
          { key: 'entry_hash', header: 'HMAC Hash' },
        ],
        rows: logs.map((l) => ({
          id: l.id.toString(),
          occurred_at: l.occurred_at.toISOString(),
          actor_username: l.actor_username ?? '',
          action: l.action,
          object_type: l.object_type,
          object_id: l.object_id ?? '',
          outcome: l.outcome,
          ip_address: l.ip_address ?? '',
          chain_partition: l.chain_partition,
          chain_sequence: l.chain_sequence.toString(),
          entry_hash: l.entry_hash,
        })),
      };
    }

    case 'SECURITY_ALERTS': {
      const alerts = scopeEmpty
        ? []
        : await database.securityAlert.findMany({
            where: buildSecurityAlertExportWhere(filters),
            take: filters.limit ?? 1000,
            orderBy: { detected_at: 'desc' },
          });
      return {
        reportTitle: 'Security Operations - Alert Incident Report',
        rawRecords: alerts,
        columns: [
          { key: 'id', header: 'Alert ID' },
          { key: 'alert_type', header: 'Alert Type' },
          { key: 'severity', header: 'Severity' },
          { key: 'status', header: 'Status' },
          { key: 'title', header: 'Title' },
          { key: 'description', header: 'Description' },
          { key: 'detected_at', header: 'Detected At (UTC)' },
          { key: 'resolved_at', header: 'Resolved At' },
          { key: 'resolution_note', header: 'Resolution Note' },
        ],
        rows: alerts.map((a) => ({
          id: a.id,
          alert_type: a.alert_type,
          severity: a.severity,
          status: a.status,
          title: a.title,
          description: a.description,
          detected_at: a.detected_at.toISOString(),
          resolved_at: a.resolved_at?.toISOString() ?? '',
          resolution_note: a.resolution_note ?? '',
        })),
      };
    }

    case 'INCIDENT_REPORTS': {
      const incidents = scopeEmpty
        ? []
        : await database.incidentReport.findMany({
            where: buildIncidentReportExportWhere(filters),
            take: filters.limit ?? 1000,
            orderBy: { created_at: 'desc' },
          });
      return {
        reportTitle: 'Security Operations - Incident Summary Report',
        rawRecords: incidents,
        columns: [
          { key: 'id', header: 'ID' },
          { key: 'incident_code', header: 'Incident Code' },
          { key: 'status', header: 'Status' },
          { key: 'title', header: 'Title' },
          { key: 'summary', header: 'Summary' },
          { key: 'created_at', header: 'Created At' },
          { key: 'submitted_at', header: 'Submitted At' },
          { key: 'closed_at', header: 'Closed At' },
        ],
        rows: incidents.map((i) => ({
          id: i.id,
          incident_code: i.incident_code,
          status: i.status,
          title: i.title,
          summary: i.summary,
          created_at: i.created_at.toISOString(),
          submitted_at: i.submitted_at?.toISOString() ?? '',
          closed_at: i.closed_at?.toISOString() ?? '',
        })),
      };
    }

    default: {
      const snapshots = await database.systemHealthSnapshot.findMany({
        where: buildSystemHealthExportWhere(filters),
        take: Math.min(filters.limit ?? 50, 200),
        orderBy: { captured_at: 'desc' },
      });
      return {
        reportTitle: 'System Health Diagnostic Snapshot Report',
        rawRecords: snapshots,
        columns: [
          { key: 'id', header: 'ID' },
          { key: 'service_name', header: 'Service' },
          { key: 'status', header: 'Status' },
          { key: 'response_time_ms', header: 'Latency (ms)' },
          { key: 'error_count', header: 'Errors' },
          { key: 'captured_at', header: 'Captured At' },
        ],
        rows: snapshots.map((s) => ({
          id: s.id.toString(),
          service_name: s.service_name,
          status: s.status,
          response_time_ms: s.response_time_ms !== null ? s.response_time_ms.toString() : '0',
          error_count: s.error_count.toString(),
          captured_at: s.captured_at.toISOString(),
        })),
      };
    }
  }
}
