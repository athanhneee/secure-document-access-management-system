import type { SharedExportJobSummary, SharedPaginationMeta } from '@sda/contracts';

export type AuditOutcome = 'SUCCESS' | 'DENIED' | 'FAILED';

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
  outcome: AuditOutcome;
  reasonCode?: string | null | undefined;
  ipAddress?: string | undefined;
  userAgent?: string | null | undefined;
  correlationId: string;
  chainPartition?: string | undefined;
  chainSequence?: number | string | undefined;
  previousHash?: string | null | undefined;
  entryHash?: string | undefined;
  hmacKeyVersion?: number | undefined;
  chainAlgorithm?: string | undefined;
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
  actorUserId?: string | null;
  actorUsername?: string;
  action?: string;
  objectType?: string;
  objectId?: string | null;
  documentId?: string | null;
  accessSessionId?: string | null;
  outcome?: AuditOutcome;
  reasonCode?: string | null;
  ipAddress?: string;
  userAgent?: string | null;
  correlationId?: string;
  chainPartition?: string;
  chainSequence?: number | string;
  previousHash?: string | null;
  entryHash?: string;
  hmacKeyVersion?: number;
  chainAlgorithm?: string;
  details?: Record<string, unknown> | null;
}

export interface AuditViolationDto {
  code: string;
  partition?: string | undefined;
  sequence?: string | number | undefined;
  logId?: string | undefined;
  message: string;
}

export interface PartitionVerificationResult {
  partition: string;
  valid: boolean;
  totalChecked: number;
  anchorsChecked: number;
  resumedFromAnchorSequence?: string | undefined;
  violations: AuditViolationDto[];
}

export type VerifyHashChainResponse =
  | PartitionVerificationResult
  | Record<string, PartitionVerificationResult>
  | {
      partitions?: PartitionVerificationResult[];
      tamperedCount?: number;
      valid?: boolean;
    };

export interface ChainVerificationReport {
  isChainValid: boolean;
  totalEntriesChecked: number;
  totalAnchorsChecked: number;
  resumedFromAnchors: boolean;
  partitions: PartitionVerificationResult[];
  brokenSequences: string[];
  verifiedAt: string;
  chainPartition: string;
}

export interface AuditAnchorItem {
  id: string;
  chainPartition: string;
  anchorSequence: string;
  entryHash: string;
  signature: string;
  signerKeyId?: string | undefined;
  status?: string | undefined;
  anchoredAt: string;
}

export type ExportFormat = 'CSV' | 'JSON' | 'PDF' | 'EXCEL';
export type ExportReportType =
  'AUDIT_LOGS' | 'SYSTEM_REPORT' | 'SECURITY_ALERTS' | 'INCIDENT_REPORTS';

export interface ExportJobItem extends Pick<
  SharedExportJobSummary,
  'id' | 'exportType' | 'status' | 'createdAt'
> {
  format: ExportFormat;
  completedAt?: string | null | undefined;
  expiresAt?: string | null | undefined;
  isExpired?: boolean | undefined;
  rowCount?: number | null | undefined;
  fileSizeBytes?: string | null | undefined;
  sha256Hash?: string | null | undefined;
  errorMessage?: string | null | undefined;
  mimeType?: string | null | undefined;
}

export interface AuditTrailFilters {
  outcomeFilter: string;
  actionFilter: string;
  partitionFilter: string;
  actorFilter: string;
  fromDate: string;
  toDate: string;
  sortOrder: 'desc' | 'asc';
}

export type AuditorErrorSource =
  'logs' | 'exports' | 'verify' | 'download' | 'alerts' | 'watermark' | 'general';

export interface AuditorAlertNoteItem {
  id?: string | undefined;
  note: string;
  authorName: string;
  createdAt: string;
}

export interface AuditorLinkedAuditLog {
  id: string;
  action: string;
  occurredAt: string;
  outcome: string;
  ipAddress: string | null;
}

export interface AuditorAlertApiDto {
  id?: string;
  alertType?: string;
  ruleCode?: string;
  title?: string;
  description?: string;
  severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  status?: 'OPEN' | 'INVESTIGATING' | 'RESOLVED' | 'FALSE_POSITIVE';
  detectedUserId?: string | null;
  detectedUser?: { fullName?: string; username?: string } | null;
  ipAddress?: string | null;
  detectedAt?: string;
  resolutionNote?: string | null;
  linkedAuditLogs?: AuditorLinkedAuditLog[];
  notes?: Array<{
    id?: string;
    note?: string;
    content?: string;
    authorName?: string;
    author?: { fullName?: string; username?: string };
    createdAt?: string;
  }>;
}

export interface AuditorAlertItem {
  id: string;
  ruleCode: string;
  title: string;
  description: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  status: 'OPEN' | 'INVESTIGATING' | 'RESOLVED' | 'FALSE_POSITIVE';
  detectedUserName: string;
  ipAddress: string;
  detectedAt: string;
  resolutionNote?: string | null | undefined;
  linkedAuditLogs?: AuditorLinkedAuditLog[] | undefined;
  notes?: AuditorAlertNoteItem[] | undefined;
}

export interface AuditorAlertPaginatedResponse {
  data: AuditorAlertApiDto[];
  total?: number | undefined;
  meta?: SharedPaginationMeta | undefined;
}

export interface AuditorWatermarkVerifyDto {
  verified?: boolean;
  watermarkToken?: string;
  renderedText?: string;
  outputSha256Hash?: string | null;
  documentTitle?: string;
  documentCode?: string | null;
  recipientName?: string;
  employeeCode?: string | null;
  sessionId?: string;
  ipAddress?: string;
  generatedAtUtc?: string;
  generatedAt?: string;
  classificationName?: string | null;
  document?: {
    title?: string;
    documentCode?: string | null;
    classificationName?: string | null;
    versionNo?: number;
    originalSha256Hash?: string;
  };
  user?: {
    username?: string;
    fullName?: string | null;
    employeeCode?: string | null;
    email?: string;
  };
  session?: { id?: string; ipAddress?: string; userAgent?: string | null };
  config?: { name?: string; opacityPercent?: number; includeQrCode?: boolean };
}

export interface AuditorWatermarkProvenance {
  verified: boolean;
  watermarkToken: string;
  renderedText: string;
  outputSha256Hash: string;
  originalSha256Hash: string;
  documentTitle: string;
  documentCode: string;
  versionNo: number | null;
  recipientName: string;
  recipientEmail: string;
  employeeCode: string;
  sessionId: string;
  ipAddress: string;
  userAgent: string;
  generatedAtUtc: string;
  classificationName: string;
  configSummary: string;
}
