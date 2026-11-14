import type { SharedExportJobSummary, SharedPaginationMeta } from '@sda/contracts';

export interface AuditLogItem {
  id: string;
  occurredAt: string;
  actorUsername: string;
  action: string;
  objectType: string;
  objectId?: string | undefined;
  outcome: 'SUCCESS' | 'DENIED' | 'FAILED';
  ipAddress?: string | undefined;
  correlationId: string;
  chainSequence?: number | undefined;
  entryHash?: string | undefined;
}

export interface AuditLogsPaginatedResponse {
  data: AuditLogApiDto[];
  meta?: SharedPaginationMeta | undefined;
}

export interface AuditLogApiDto {
  id?: string;
  occurredAt?: string;
  occurred_at?: string;
  actorUsername?: string;
  actor_username?: string;
  action?: string;
  objectType?: string;
  object_type?: string;
  objectId?: string;
  object_id?: string;
  outcome?: 'SUCCESS' | 'DENIED' | 'FAILED';
  ipAddress?: string;
  ip_address?: string;
  correlationId?: string;
  correlation_id?: string;
  chainSequence?: number;
  chain_sequence?: number;
  entryHash?: string;
  entry_hash?: string;
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
