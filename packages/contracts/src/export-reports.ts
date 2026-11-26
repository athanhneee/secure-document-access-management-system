import { AppErrorCode } from './error-codes.js';
import type { ExportType } from './dto/audit-reports.dto.js';
import { MAX_PG_BIGINT, isValidIsoCalendarDate } from './dto/validation-primitives.js';

/**
 * Module: Unified Compliance Report Export Filter Normalizer, Prisma Where Builders & Payload Formatter (`@sda/contracts`)
 * Thuật toán: Một nguồn chân lý duy nhất dùng chung giữa `@sda/api` và `@sda/worker` cho:
 *   1. Chuẩn hóa & thẩm định bộ lọc xuất báo cáo (`normalizeExportFilters`) có trần `limit <= 1000`, đối khớp `UUID` và giao phạm vi phòng ban.
 *   2. Đóng gói/khôi phục bộ lọc đã chuẩn hóa vào `async_export_jobs.filter_params` (`serializePersistedExportFilters` / `extractPersistedExportScope`).
 *   3. Biên dịch mệnh đề Prisma `where` thống nhất cho 4 loại báo cáo (`AUDIT_LOGS`, `SECURITY_ALERTS`, `INCIDENT_REPORTS`, `SYSTEM_REPORT`).
 *   4. Chiếu dòng bảng và định dạng JSON hợp nhất (`{ exportType, generatedAt, rowCount, items }`).
 */

export const MAX_EXPORT_LIMIT = 1000;
export const DEFAULT_SYSTEM_HEALTH_EXPORT_LIMIT = 50;
export const MAX_SYSTEM_HEALTH_EXPORT_LIMIT = 200;

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const ISO_DATE_ONLY_REGEX = /^\d{4}-\d{2}-\d{2}$/u;

export const VALID_EXPORT_AUDIT_OUTCOMES = ['SUCCESS', 'DENIED', 'FAILED'] as const;
export type ExportAuditOutcome = (typeof VALID_EXPORT_AUDIT_OUTCOMES)[number];

export const VALID_EXPORT_SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;
export type ExportSeverity = (typeof VALID_EXPORT_SEVERITIES)[number];

export const VALID_EXPORT_ALERT_STATUSES = [
  'OPEN',
  'INVESTIGATING',
  'RESOLVED',
  'FALSE_POSITIVE',
] as const;
export type ExportAlertStatus = (typeof VALID_EXPORT_ALERT_STATUSES)[number];

export const VALID_EXPORT_INCIDENT_STATUSES = [
  'DRAFT',
  'SUBMITTED',
  'IN_REVIEW',
  'CLOSED',
] as const;
export type ExportIncidentStatus = (typeof VALID_EXPORT_INCIDENT_STATUSES)[number];

export const VALID_EXPORT_SYSTEM_HEALTH_STATUSES = ['HEALTHY', 'DEGRADED', 'DOWN'] as const;
export type ExportSystemHealthStatus = (typeof VALID_EXPORT_SYSTEM_HEALTH_STATUSES)[number];

export interface ExportColumnSpec {
  key: string;
  header: string;
  width?: number;
}

export interface ExportReportSpec {
  reportTitle: string;
  columns: readonly ExportColumnSpec[];
}

export interface NormalizedExportFilters {
  fromDate: Date | null;
  toDate: Date | null;
  effectiveDepartmentIds: bigint[] | null;
  requestedDepartmentId: bigint | null;
  actorUserId: bigint | null;
  actorUsername: string | null;
  documentId: string | null;
  correlationId: string | null;
  alertId: string | null;
  action: string | null;
  outcome: ExportAuditOutcome | null;
  chainPartition: string | null;
  severity: ExportSeverity | null;
  status: string | null;
  alertType: string | null;
  incidentCode: string | null;
  serviceName: string | null;
  limit: number | null;
}

export class ExportFilterValidationError extends Error {
  constructor(
    public readonly status: 400 | 403,
    public readonly errorCode: AppErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'ExportFilterValidationError';
  }
}

export const EXPORT_REPORT_SPECS: Readonly<Record<ExportType, ExportReportSpec>> = {
  AUDIT_LOGS: {
    reportTitle: 'Secure Document Access - Audit Trail Report',
    columns: [
      { key: 'id', header: 'Log ID' },
      { key: 'occurred_at', header: 'Timestamp (UTC)' },
      { key: 'actor_username', header: 'Actor' },
      { key: 'action', header: 'Action' },
      { key: 'object_type', header: 'Resource Type' },
      { key: 'object_id', header: 'Resource ID' },
      { key: 'document_id', header: 'Document ID' },
      { key: 'outcome', header: 'Outcome' },
      { key: 'reason_code', header: 'Reason Code' },
      { key: 'ip_address', header: 'IP Address' },
      { key: 'correlation_id', header: 'Correlation ID' },
      { key: 'chain_partition', header: 'Partition' },
      { key: 'chain_sequence', header: 'Sequence' },
      { key: 'entry_hash', header: 'HMAC Hash' },
    ],
  },
  SECURITY_ALERTS: {
    reportTitle: 'Security Operations - Alert Incident Report',
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
  },
  INCIDENT_REPORTS: {
    reportTitle: 'Security Operations - Incident Summary Report',
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
  },
  SYSTEM_REPORT: {
    reportTitle: 'System Health Diagnostic Snapshot Report',
    columns: [
      { key: 'id', header: 'ID' },
      { key: 'service_name', header: 'Service' },
      { key: 'status', header: 'Status' },
      { key: 'response_time_ms', header: 'Latency (ms)' },
      { key: 'error_count', header: 'Errors' },
      { key: 'captured_at', header: 'Captured At' },
    ],
  },
};

export function parseRawFilterParamsObject(raw: unknown): Record<string, unknown> {
  if (typeof raw === 'string') {
    try {
      const parsed = JSON.parse(raw) as unknown;
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        return parsed as Record<string, unknown>;
      }
    } catch {
      return {};
    }
  }
  if (raw && typeof raw === 'object' && !Array.isArray(raw)) {
    return raw as Record<string, unknown>;
  }
  return {};
}

export function parseExportDateBound(raw: unknown, endOfDay = false): Date | undefined {
  if (raw instanceof Date && Number.isFinite(raw.getTime())) return raw;
  if (typeof raw === 'string' && raw.trim().length > 0) {
    const trimmed = raw.trim();
    if (ISO_DATE_ONLY_REGEX.test(trimmed) && !isValidIsoCalendarDate(trimmed)) {
      return undefined;
    }
    const normalized = ISO_DATE_ONLY_REGEX.test(trimmed)
      ? `${trimmed}${endOfDay ? 'T23:59:59.999Z' : 'T00:00:00.000Z'}`
      : trimmed;
    const ts = Date.parse(normalized);
    if (Number.isFinite(ts)) return new Date(ts);
  }
  return undefined;
}

function parseOptionalBigInt(raw: unknown, fieldName: string): bigint | null {
  if (raw === undefined || raw === null || raw === '') return null;
  if (typeof raw === 'bigint') {
    if (raw <= 0n || raw > MAX_PG_BIGINT) {
      throw new ExportFilterValidationError(
        400,
        AppErrorCode.VALIDATION_FAILED,
        `filterParams.${fieldName} exceeds 64-bit BIGINT bounds.`,
      );
    }
    return raw;
  }
  const str = String(raw).trim();
  if (!/^\d+$/u.test(str)) {
    throw new ExportFilterValidationError(
      400,
      AppErrorCode.VALIDATION_FAILED,
      `Invalid numeric identifier in filterParams.${fieldName}.`,
    );
  }
  const value = BigInt(str);
  if (value <= 0n || value > MAX_PG_BIGINT) {
    throw new ExportFilterValidationError(
      400,
      AppErrorCode.VALIDATION_FAILED,
      `filterParams.${fieldName} must be a positive 64-bit integer within PostgreSQL BIGINT range.`,
    );
  }
  return value;
}

function parseOptionalStrictDate(raw: unknown, fieldName: string, endOfDay = false): Date | null {
  if (raw === undefined || raw === null || raw === '') return null;
  if (raw instanceof Date) {
    if (!Number.isFinite(raw.getTime())) {
      throw new ExportFilterValidationError(
        400,
        AppErrorCode.VALIDATION_FAILED,
        `Invalid date in filterParams.${fieldName}.`,
      );
    }
    return raw;
  }
  if (typeof raw !== 'string') {
    throw new ExportFilterValidationError(
      400,
      AppErrorCode.VALIDATION_FAILED,
      `Invalid date string in filterParams.${fieldName}.`,
    );
  }
  const trimmed = raw.trim();
  if (ISO_DATE_ONLY_REGEX.test(trimmed) && !isValidIsoCalendarDate(trimmed)) {
    throw new ExportFilterValidationError(
      400,
      AppErrorCode.VALIDATION_FAILED,
      `Invalid calendar date in filterParams.${fieldName}.`,
    );
  }
  const normalized = ISO_DATE_ONLY_REGEX.test(trimmed)
    ? `${trimmed}${endOfDay ? 'T23:59:59.999Z' : 'T00:00:00.000Z'}`
    : trimmed;
  const ts = Date.parse(normalized);
  if (!Number.isFinite(ts)) {
    throw new ExportFilterValidationError(
      400,
      AppErrorCode.VALIDATION_FAILED,
      `Malformed date in filterParams.${fieldName}.`,
    );
  }
  return new Date(ts);
}

function parseOptionalString(raw: unknown, maxLength = 100): string | null {
  if (raw === undefined || raw === null) return null;
  const trimmed = String(raw).trim();
  return trimmed ? trimmed.slice(0, maxLength) : null;
}

function parseOptionalUuid(raw: unknown, fieldName: string): string | null {
  const value = parseOptionalString(raw, 64);
  if (!value) return null;
  if (!UUID_REGEX.test(value)) {
    throw new ExportFilterValidationError(
      400,
      AppErrorCode.VALIDATION_FAILED,
      `filterParams.${fieldName} must be a valid UUID.`,
    );
  }
  return value;
}

/**
 * Thuật toán: Chuẩn Hóa Tham Số Lọc & Giao Với Bao Đóng Phòng Ban Được Cấp Quyền (`normalizeExportFilters`).
 * Chuẩn hóa chữ hoa cho các enum (`outcome`, `severity`, `status`), kiểm định UUID cho `documentId`/`correlationId`/`alertId`,
 * chặn `from > to`, áp trần `limit <= 1000` và kiểm định `departmentId` nằm trong `allowedDepartmentIds`.
 */
export function normalizeExportFilters(
  rawFilterParams: unknown,
  allowedDepartmentIds: bigint[] | null = null,
  exportType?: ExportType,
): NormalizedExportFilters {
  const params = parseRawFilterParamsObject(rawFilterParams);

  const fromDate = parseOptionalStrictDate(params['from'] ?? params['startDate'], 'from', false);
  const toDate = parseOptionalStrictDate(params['to'] ?? params['endDate'], 'to', true);
  if (fromDate && toDate && fromDate.getTime() > toDate.getTime()) {
    throw new ExportFilterValidationError(
      400,
      AppErrorCode.VALIDATION_FAILED,
      'filterParams.from must not be later than filterParams.to.',
    );
  }

  const requestedDepartmentId = parseOptionalBigInt(params['departmentId'], 'departmentId');
  let effectiveDepartmentIds: bigint[] | null = allowedDepartmentIds;

  if (requestedDepartmentId !== null) {
    if (allowedDepartmentIds !== null && !allowedDepartmentIds.includes(requestedDepartmentId)) {
      throw new ExportFilterValidationError(
        403,
        AppErrorCode.EXPORT_UNAUTHORIZED,
        'Requested departmentId is outside your authorized export scope.',
      );
    }
    effectiveDepartmentIds = [requestedDepartmentId];
  }

  const actorUserId = parseOptionalBigInt(
    params['actorUserId'] ?? params['userId'] ?? params['detectedUserId'] ?? params['preparedBy'],
    'actorUserId',
  );
  const actorUsername = parseOptionalString(params['actorUsername'], 80);
  const documentId = parseOptionalUuid(params['documentId'], 'documentId');
  const correlationId = parseOptionalUuid(params['correlationId'], 'correlationId');
  const alertId = parseOptionalUuid(params['alertId'], 'alertId');

  const rawOutcome = parseOptionalString(params['outcome'], 20)?.toUpperCase() ?? null;
  let outcome: ExportAuditOutcome | null = null;
  if (rawOutcome !== null) {
    if ((VALID_EXPORT_AUDIT_OUTCOMES as readonly string[]).includes(rawOutcome)) {
      outcome = rawOutcome as ExportAuditOutcome;
    } else if (exportType === 'AUDIT_LOGS') {
      throw new ExportFilterValidationError(
        400,
        AppErrorCode.VALIDATION_FAILED,
        `Invalid filterParams.outcome "${rawOutcome}". Allowed: ${VALID_EXPORT_AUDIT_OUTCOMES.join(', ')}.`,
      );
    }
  }

  const rawSeverity = parseOptionalString(params['severity'], 20)?.toUpperCase() ?? null;
  let severity: ExportSeverity | null = null;
  if (rawSeverity !== null) {
    if ((VALID_EXPORT_SEVERITIES as readonly string[]).includes(rawSeverity)) {
      severity = rawSeverity as ExportSeverity;
    } else if (exportType === 'SECURITY_ALERTS') {
      throw new ExportFilterValidationError(
        400,
        AppErrorCode.VALIDATION_FAILED,
        `Invalid filterParams.severity "${rawSeverity}". Allowed: ${VALID_EXPORT_SEVERITIES.join(', ')}.`,
      );
    }
  }

  const normalizedStatus = parseOptionalString(params['status'], 30)?.toUpperCase() ?? null;
  if (normalizedStatus !== null) {
    if (
      exportType === 'SECURITY_ALERTS' &&
      !(VALID_EXPORT_ALERT_STATUSES as readonly string[]).includes(normalizedStatus)
    ) {
      throw new ExportFilterValidationError(
        400,
        AppErrorCode.VALIDATION_FAILED,
        `Invalid filterParams.status "${normalizedStatus}" for SECURITY_ALERTS. Allowed: ${VALID_EXPORT_ALERT_STATUSES.join(', ')}.`,
      );
    }
    if (
      exportType === 'INCIDENT_REPORTS' &&
      !(VALID_EXPORT_INCIDENT_STATUSES as readonly string[]).includes(normalizedStatus)
    ) {
      throw new ExportFilterValidationError(
        400,
        AppErrorCode.VALIDATION_FAILED,
        `Invalid filterParams.status "${normalizedStatus}" for INCIDENT_REPORTS. Allowed: ${VALID_EXPORT_INCIDENT_STATUSES.join(', ')}.`,
      );
    }
    if (
      exportType === 'SYSTEM_REPORT' &&
      !(VALID_EXPORT_SYSTEM_HEALTH_STATUSES as readonly string[]).includes(normalizedStatus)
    ) {
      throw new ExportFilterValidationError(
        400,
        AppErrorCode.VALIDATION_FAILED,
        `Invalid filterParams.status "${normalizedStatus}" for SYSTEM_REPORT. Allowed: ${VALID_EXPORT_SYSTEM_HEALTH_STATUSES.join(', ')}.`,
      );
    }
  }

  let limit: number | null = null;
  if (params['limit'] !== undefined && params['limit'] !== null && params['limit'] !== '') {
    const parsedLimit = Number(params['limit']);
    if (!Number.isInteger(parsedLimit) || parsedLimit < 1) {
      throw new ExportFilterValidationError(
        400,
        AppErrorCode.VALIDATION_FAILED,
        'filterParams.limit must be a positive integer.',
      );
    }
    limit = Math.min(parsedLimit, MAX_EXPORT_LIMIT);
  }

  return {
    fromDate,
    toDate,
    effectiveDepartmentIds,
    requestedDepartmentId,
    actorUserId,
    actorUsername,
    documentId,
    correlationId,
    alertId,
    action: parseOptionalString(params['action'], 100),
    outcome,
    chainPartition: parseOptionalString(params['chainPartition'], 80),
    severity,
    status: normalizedStatus,
    alertType: parseOptionalString(params['alertType'] ?? params['ruleCode'], 80),
    incidentCode: parseOptionalString(params['incidentCode'], 50),
    serviceName: parseOptionalString(params['serviceName'], 100),
    limit,
  };
}

/**
 * Thuật toán: Tuần tự hóa bộ lọc đã chuẩn hóa cùng `__allowedDepartmentIds` để lưu bền vững vào cột JSON `filter_params`.
 */
export function serializePersistedExportFilters(
  normalized: NormalizedExportFilters,
  allowedDepartmentIds: bigint[] | null,
): Record<string, unknown> {
  const effectiveAllowed = normalized.effectiveDepartmentIds ?? allowedDepartmentIds;
  return {
    ...(normalized.fromDate ? { from: normalized.fromDate.toISOString() } : {}),
    ...(normalized.toDate ? { to: normalized.toDate.toISOString() } : {}),
    ...(normalized.requestedDepartmentId !== null
      ? { departmentId: normalized.requestedDepartmentId.toString() }
      : {}),
    ...(normalized.actorUserId !== null ? { actorUserId: normalized.actorUserId.toString() } : {}),
    ...(normalized.actorUsername ? { actorUsername: normalized.actorUsername } : {}),
    ...(normalized.documentId ? { documentId: normalized.documentId } : {}),
    ...(normalized.correlationId ? { correlationId: normalized.correlationId } : {}),
    ...(normalized.alertId ? { alertId: normalized.alertId } : {}),
    ...(normalized.action ? { action: normalized.action } : {}),
    ...(normalized.outcome ? { outcome: normalized.outcome } : {}),
    ...(normalized.chainPartition ? { chainPartition: normalized.chainPartition } : {}),
    ...(normalized.severity ? { severity: normalized.severity } : {}),
    ...(normalized.status ? { status: normalized.status } : {}),
    ...(normalized.alertType ? { alertType: normalized.alertType } : {}),
    ...(normalized.incidentCode ? { incidentCode: normalized.incidentCode } : {}),
    ...(normalized.serviceName ? { serviceName: normalized.serviceName } : {}),
    ...(normalized.limit !== null ? { limit: normalized.limit } : {}),
    __allowedDepartmentIds: effectiveAllowed ? effectiveAllowed.map(String) : null,
  };
}

/**
 * Thuật toán: Tách và khôi phục mảng `bigint[] | null` của `__allowedDepartmentIds` từ `filter_params` trong PostgreSQL.
 */
export function extractPersistedExportScope(persistedFilterParams: unknown): {
  cleanFilterParams: Record<string, unknown>;
  allowedDepartmentIds: bigint[] | null;
} {
  const copy = { ...parseRawFilterParamsObject(persistedFilterParams) };
  const rawAllowed = copy['__allowedDepartmentIds'];
  delete copy['__allowedDepartmentIds'];
  delete copy['__leaseExpiresAt'];
  delete copy['__processingLeaseUntil'];
  const allowedDepartmentIds = Array.isArray(rawAllowed)
    ? rawAllowed
        .map((item) => {
          if (typeof item === 'bigint') return item;
          if (typeof item === 'number' && Number.isInteger(item) && item > 0) return BigInt(item);
          if (typeof item === 'string' && /^\d+$/u.test(item.trim())) return BigInt(item.trim());
          return null;
        })
        .filter((item): item is bigint => item !== null)
    : null;
  return { cleanFilterParams: copy, allowedDepartmentIds };
}

/**
 * Thuật toán: Biên dịch mệnh đề Prisma `where` cho xuất `AUDIT_LOGS` (dùng chung API & Worker, so khớp UUID `correlation_id` bằng `equals`).
 */
export function buildAuditLogExportWhere(
  filters: NormalizedExportFilters,
): Record<string, unknown> {
  const where: Record<string, unknown> = {};
  if (filters.fromDate || filters.toDate) {
    where['occurred_at'] = {
      ...(filters.fromDate ? { gte: filters.fromDate } : {}),
      ...(filters.toDate ? { lte: filters.toDate } : {}),
    };
  }
  if (filters.actorUserId !== null) where['actor_user_id'] = filters.actorUserId;
  if (filters.actorUsername) {
    where['actor_username'] = { contains: filters.actorUsername, mode: 'insensitive' };
  }
  if (filters.documentId) where['document_id'] = filters.documentId;
  if (filters.correlationId) {
    where['correlation_id'] = { equals: filters.correlationId };
  }
  if (filters.action) {
    where['action'] = { contains: filters.action, mode: 'insensitive' };
  }
  if (filters.outcome) where['outcome'] = filters.outcome;
  if (filters.chainPartition) where['chain_partition'] = filters.chainPartition;
  if (filters.effectiveDepartmentIds !== null) {
    where['OR'] = [
      { users: { department_id: { in: filters.effectiveDepartmentIds } } },
      { documents: { department_id: { in: filters.effectiveDepartmentIds } } },
    ];
  }
  return where;
}

/**
 * Thuật toán: Biên dịch mệnh đề Prisma `where` cho xuất `SECURITY_ALERTS` (dùng chung API & Worker).
 */
export function buildSecurityAlertExportWhere(
  filters: NormalizedExportFilters,
): Record<string, unknown> {
  const where: Record<string, unknown> = {};
  if (filters.fromDate || filters.toDate) {
    where['detected_at'] = {
      ...(filters.fromDate ? { gte: filters.fromDate } : {}),
      ...(filters.toDate ? { lte: filters.toDate } : {}),
    };
  }
  if (filters.actorUserId !== null) where['detected_user_id'] = filters.actorUserId;
  if (filters.documentId) where['document_id'] = filters.documentId;
  if (filters.severity) where['severity'] = filters.severity;
  if (
    filters.status !== null &&
    (VALID_EXPORT_ALERT_STATUSES as readonly string[]).includes(filters.status)
  ) {
    where['status'] = filters.status;
  }
  if (filters.alertType) where['alert_type'] = filters.alertType;
  if (filters.effectiveDepartmentIds !== null) {
    where['OR'] = [
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
 * Thuật toán: Biên dịch mệnh đề Prisma `where` cho xuất `INCIDENT_REPORTS` (hỗ trợ đầy đủ `IN_REVIEW`, `incidentCode`, `alertId`, `documentId`, `ruleCode`/`alertType` và phạm vi cảnh báo phòng ban).
 */
export function buildIncidentReportExportWhere(
  filters: NormalizedExportFilters,
): Record<string, unknown> {
  const where: Record<string, unknown> = {};
  if (filters.fromDate || filters.toDate) {
    where['created_at'] = {
      ...(filters.fromDate ? { gte: filters.fromDate } : {}),
      ...(filters.toDate ? { lte: filters.toDate } : {}),
    };
  }
  if (filters.actorUserId !== null) where['prepared_by'] = filters.actorUserId;
  if (filters.alertId) where['alert_id'] = filters.alertId;
  if (filters.incidentCode) where['incident_code'] = filters.incidentCode;
  if (
    filters.status !== null &&
    (VALID_EXPORT_INCIDENT_STATUSES as readonly string[]).includes(filters.status)
  ) {
    where['status'] = filters.status;
  }
  if (filters.documentId || filters.alertType) {
    where['security_alerts'] = {
      ...(filters.documentId ? { document_id: filters.documentId } : {}),
      ...(filters.alertType ? { alert_type: filters.alertType } : {}),
    };
  }
  if (filters.effectiveDepartmentIds !== null) {
    where['OR'] = [
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
 * Thuật toán: Biên dịch mệnh đề Prisma `where` cho xuất `SYSTEM_REPORT` (`system_health_snapshots`).
 */
export function buildSystemHealthExportWhere(
  filters: NormalizedExportFilters,
): Record<string, unknown> {
  const where: Record<string, unknown> = {};
  if (filters.fromDate || filters.toDate) {
    where['captured_at'] = {
      ...(filters.fromDate ? { gte: filters.fromDate } : {}),
      ...(filters.toDate ? { lte: filters.toDate } : {}),
    };
  }
  if (filters.serviceName) where['service_name'] = filters.serviceName;
  if (filters.status) where['status'] = filters.status;
  return where;
}

function toIsoCell(val: unknown): string {
  if (val instanceof Date && Number.isFinite(val.getTime())) return val.toISOString();
  if (typeof val === 'string') return val;
  return '';
}

function toStringCell(val: unknown): string {
  if (val === null || val === undefined) return '';
  if (typeof val === 'bigint') return val.toString();
  if (val instanceof Date && Number.isFinite(val.getTime())) return val.toISOString();
  return String(val);
}

/**
 * Thuật toán: Chiếu tập bản ghi CSDL thành mảng dòng bảng đồng nhất 100% giữa `@sda/api` và `@sda/worker`.
 */
export function projectExportRows(
  exportType: ExportType,
  records: ReadonlyArray<Record<string, unknown>>,
): Record<string, string>[] {
  switch (exportType) {
    case 'AUDIT_LOGS':
      return records.map((l) => ({
        id: toStringCell(l['id']),
        occurred_at: toIsoCell(l['occurred_at']),
        actor_username: toStringCell(l['actor_username']),
        action: toStringCell(l['action']),
        object_type: toStringCell(l['object_type']),
        object_id: toStringCell(l['object_id']),
        document_id: toStringCell(l['document_id']),
        outcome: toStringCell(l['outcome']),
        reason_code: toStringCell(l['reason_code']),
        ip_address: toStringCell(l['ip_address']),
        correlation_id: toStringCell(l['correlation_id']),
        chain_partition: toStringCell(l['chain_partition']),
        chain_sequence: toStringCell(l['chain_sequence']),
        entry_hash: toStringCell(l['entry_hash']),
      }));

    case 'SECURITY_ALERTS':
      return records.map((a) => ({
        id: toStringCell(a['id']),
        alert_type: toStringCell(a['alert_type']),
        severity: toStringCell(a['severity']),
        status: toStringCell(a['status']),
        title: toStringCell(a['title']),
        description: toStringCell(a['description']),
        detected_at: toIsoCell(a['detected_at']),
        resolved_at: toIsoCell(a['resolved_at']),
        resolution_note: toStringCell(a['resolution_note']),
      }));

    case 'INCIDENT_REPORTS':
      return records.map((i) => ({
        id: toStringCell(i['id']),
        incident_code: toStringCell(i['incident_code']),
        status: toStringCell(i['status']),
        title: toStringCell(i['title']),
        summary: toStringCell(i['summary']),
        created_at: toIsoCell(i['created_at']),
        submitted_at: toIsoCell(i['submitted_at']),
        closed_at: toIsoCell(i['closed_at']),
      }));

    case 'SYSTEM_REPORT':
      return records.map((s) => ({
        id: toStringCell(s['id']),
        service_name: toStringCell(s['service_name']),
        status: toStringCell(s['status']),
        response_time_ms:
          s['response_time_ms'] !== null && s['response_time_ms'] !== undefined
            ? toStringCell(s['response_time_ms'])
            : '0',
        error_count: toStringCell(s['error_count'] ?? 0),
        captured_at: toIsoCell(s['captured_at']),
      }));
  }
}

/**
 * Thuật toán: Định dạng JSON kết xuất báo cáo đồng nhất 100% giữa `@sda/api` và `@sda/worker`
 * theo cấu trúc phong bì `{ exportType, generatedAt, rowCount, items }`.
 */
export function formatUnifiedExportJson(
  exportType: string,
  items: ReadonlyArray<unknown>,
  generatedAt: Date = new Date(),
): string {
  return JSON.stringify(
    {
      exportType,
      generatedAt: generatedAt.toISOString(),
      rowCount: items.length,
      items,
    },
    (_k, v: unknown) => (typeof v === 'bigint' ? v.toString() : v),
    2,
  );
}
