/**
 * @module AuditExportHelper
 * Algorithm: Allowlist Audit Filter Builder & Formula-Injection-Safe CSV/JSON Export Serializer.
 */
import type { Prisma } from '@sda/database';
import { formatCsvRow } from '../reports/csv-formula-sanitizer.js';

export interface AuditLogFilterParams {
  actorUserId?: bigint | undefined;
  action?: string | undefined;
  outcome?: 'SUCCESS' | 'DENIED' | 'FAILED' | undefined;
  chainPartition?: string | undefined;
  from?: string | undefined;
  to?: string | undefined;
}

export interface RawAuditLogRow {
  id: bigint;
  occurred_at: Date;
  actor_user_id: bigint | null;
  actor_username: string | null;
  action: string;
  object_type: string;
  object_id: string | null;
  document_id: string | null;
  access_session_id: string | null;
  outcome: string;
  reason_code: string | null;
  ip_address: string | null;
  user_agent: string | null;
  correlation_id: string;
  details: unknown;
  chain_partition: string;
  chain_sequence: bigint;
  entry_hash: string;
  previous_hash: string | null;
  hmac_key_version: number;
  chain_algorithm: string;
}

const CSV_EXPORT_HEADERS = [
  'id',
  'occurred_at',
  'actor_user_id',
  'actor_username',
  'action',
  'object_type',
  'object_id',
  'document_id',
  'access_session_id',
  'outcome',
  'reason_code',
  'ip_address',
  'correlation_id',
  'chain_partition',
  'chain_sequence',
  'entry_hash',
];

/**
 * Algorithm / Thuật toán: Áp bộ lọc danh sách trắng cho truy vấn nhật ký kiểm toán (Strict Allowlist Filter Builder).
 */
export function applyAuditFilterAllowlist(
  where: Prisma.AuditLogWhereInput,
  filter: AuditLogFilterParams,
): void {
  // CONFLICT-RESOLVED: Unified duplicate allowlist filter construction across queryAuditLogs and exportAuditLogs
  if (filter.actorUserId !== undefined) where.actor_user_id = filter.actorUserId;
  if (filter.action) where.action = filter.action;
  if (filter.outcome) where.outcome = filter.outcome;
  if (filter.chainPartition) where.chain_partition = filter.chainPartition;
  if (filter.from || filter.to) {
    where.occurred_at = {};
    if (filter.from) where.occurred_at.gte = new Date(filter.from);
    if (filter.to) where.occurred_at.lte = new Date(filter.to);
  }
}

/**
 * Algorithm / Thuật toán: Tuần tự hóa bản ghi kiểm toán an toàn số nguyên lớn 64-bit (`BigInt` -> `string`).
 */
export function serializeAuditLogRow(log: RawAuditLogRow): Record<string, unknown> {
  // CONFLICT-RESOLVED: Unified duplicate 21-field BigInt-safe audit log serializer across query and JSON export
  return {
    id: log.id.toString(),
    occurredAt: log.occurred_at.toISOString(),
    actorUserId: log.actor_user_id?.toString() ?? null,
    actorUsername: log.actor_username,
    action: log.action,
    objectType: log.object_type,
    objectId: log.object_id,
    documentId: log.document_id,
    accessSessionId: log.access_session_id,
    outcome: log.outcome,
    reasonCode: log.reason_code,
    ipAddress: log.ip_address,
    userAgent: log.user_agent,
    correlationId: log.correlation_id,
    details: log.details,
    chainPartition: log.chain_partition,
    chainSequence: log.chain_sequence.toString(),
    entryHash: log.entry_hash,
    previousHash: log.previous_hash,
    hmacKeyVersion: log.hmac_key_version,
    chainAlgorithm: log.chain_algorithm,
  };
}

/**
 * Algorithm / Thuật toán: Kết xuất dữ liệu kiểm toán ra CSV chống Formula Injection (RFC 4180) hoặc JSON định dạng chuẩn.
 */
export function formatAuditExportPayload(
  logs: RawAuditLogRow[],
  format: 'CSV' | 'JSON',
): { format: 'CSV' | 'JSON'; data: string; count: number } {
  if (format === 'CSV') {
    const rows = [formatCsvRow(CSV_EXPORT_HEADERS)];
    for (const log of logs) {
      rows.push(
        formatCsvRow([
          log.id.toString(),
          log.occurred_at.toISOString(),
          log.actor_user_id?.toString() ?? '',
          log.actor_username ?? '',
          log.action,
          log.object_type,
          log.object_id ?? '',
          log.document_id ?? '',
          log.access_session_id ?? '',
          log.outcome,
          log.reason_code ?? '',
          log.ip_address ?? '',
          log.correlation_id,
          log.chain_partition,
          log.chain_sequence.toString(),
          log.entry_hash,
        ]),
      );
    }
    return { format: 'CSV', data: rows.join('\r\n'), count: logs.length };
  }

  return {
    format: 'JSON',
    data: JSON.stringify(logs.map(serializeAuditLogRow), null, 2),
    count: logs.length,
  };
}
