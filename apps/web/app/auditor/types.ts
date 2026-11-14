import type { SharedExportJobSummary, SharedPaginationMeta } from '@sda/contracts';

export interface AuditLogItem {
  id: string;
  occurredAt: string;
  actorUserId?: string | null | undefined;
  actorUsername: string;
  action: string;
  objectType: string;
  objectId?: string | null | undefined;
  documentId?: string | null | undefined;
  accessSessionId?: string | null | undefined;
  outcome: 'SUCCESS' | 'DENIED' | 'FAILED';
  reasonCode?: string | null | undefined;
  ipAddress?: string | undefined;
  userAgent?: string | null | undefined;
  correlationId: string;
  chainPartition?: string | undefined;
  chainSequence?: number | string | undefined;
  previousHash?: string | null | undefined;
  entryHash?: string | undefined;
  details?: Record<string, unknown> | null | undefined;
}

export interface AuditorPaginationInfo {
  page: number;
  pageSize: number;
  total: number;
  totalPages: number;
}

export interface AuditLogsPaginatedResponse {
  data: AuditLogApiDto[];
  pagination?: Partial<AuditorPaginationInfo> | undefined;
  meta?: SharedPaginationMeta | undefined;
}

export interface AuditLogApiDto {
  id?: string;
  occurredAt?: string;
  occurred_at?: string;
  actorUserId?: string | null;
  actor_user_id?: string | null;
  actorUsername?: string;
  actor_username?: string;
  action?: string;
  objectType?: string;
  object_type?: string;
  objectId?: string | null;
  object_id?: string | null;
  documentId?: string | null;
  document_id?: string | null;
  accessSessionId?: string | null;
  access_session_id?: string | null;
  outcome?: 'SUCCESS' | 'DENIED' | 'FAILED';
  reasonCode?: string | null;
  reason_code?: string | null;
  ipAddress?: string;
  ip_address?: string;
  userAgent?: string | null;
  user_agent?: string | null;
  correlationId?: string;
  correlation_id?: string;
  chainPartition?: string;
  chain_partition?: string;
  chainSequence?: number | string;
  chain_sequence?: number | string;
  previousHash?: string | null;
  previous_hash?: string | null;
  entryHash?: string;
  entry_hash?: string;
  details?: Record<string, unknown> | null;
}

export interface PartitionVerificationResult {
  partition: string;
  valid: boolean;
  totalChecked: number;
  anchorsChecked: number;
  violations: { code: string; message: string }[];
}

export type VerifyHashChainResponse =
  | Record<string, PartitionVerificationResult>
  | {
      partitions?: PartitionVerificationResult[];
      tamperedCount?: number;
      valid?: boolean;
    };

export interface ChainVerificationReport {
  isChainValid: boolean;
  totalEntriesChecked: number;
  tamperingDetected: boolean;
  brokenSequences: (number | string)[];
  verifiedAt: string;
  chainPartition: string;
}

export type ExportFormat = 'CSV' | 'JSON' | 'PDF' | 'EXCEL';

export interface ExportJobItem extends Pick<
  SharedExportJobSummary,
  'id' | 'exportType' | 'status' | 'createdAt'
> {
  format: ExportFormat;
  completedAt?: string | null | undefined;
  expiresAt?: string | null | undefined;
  isExpired?: boolean | undefined;
  rowCount?: number | null | undefined;
}

export interface AuditTrailFilters {
  outcomeFilter: string;
  actionFilter: string;
  fromDate: string;
  toDate: string;
}
