import type { SharedPaginationMeta } from '@sda/contracts';

export type AlertLifecycleStatus =
  'OPEN' | 'INVESTIGATING' | 'ESCALATED' | 'RESOLVED' | 'FALSE_POSITIVE';

export type GatewayHealthStatus = 'ONLINE' | 'DEGRADED' | 'OFFLINE';
export type DlpEnforcementMode = 'BLOCK' | 'AUDIT_ONLY' | 'DISABLED' | 'OFFLINE';

export interface NetworkDlpStatus {
  gatewayHealth: GatewayHealthStatus;
  workerReachable: boolean;
  icapEnabled: boolean;
  icapListening: boolean;
  enforcementMode: DlpEnforcementMode;
  totalDlpAlerts: number;
  openDlpAlerts: number;
  checkedAt: string;
}

export interface AlertNoteItem {
  id?: string | undefined;
  note: string;
  authorName: string;
  createdAt: string;
}

export interface LinkedAuditLogSummary {
  id: string;
  action: string;
  occurredAt: string;
  outcome: string;
  ipAddress: string | null;
}

export interface LinkedIncidentSummary {
  id: string;
  incidentCode: string;
  title: string;
  status: string;
  createdAt: string;
}

export interface SecurityAlertItem {
  id: string;
  ruleCode: string;
  title: string;
  description: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  status: AlertLifecycleStatus;
  detectedUserId?: string | undefined;
  detectedUserName?: string | undefined;
  documentId?: string | undefined;
  ipAddress: string;
  detectedAt: string;
  resolutionNote?: string | null | undefined;
  linkedAuditLogsCount?: number | undefined;
  linkedAuditLogs?: LinkedAuditLogSummary[] | undefined;
  incidentReports?: LinkedIncidentSummary[] | undefined;
  details?: Record<string, unknown> | undefined;
  notes?: AlertNoteItem[] | undefined;
}

export interface SecurityPaginatedResponse<T> {
  data: T[];
  total?: number | undefined;
  activeCount?: number | undefined;
  page?: number | undefined;
  pageSize?: number | undefined;
  hasMore?: boolean | undefined;
  meta?: SharedPaginationMeta | undefined;
}

export interface IncidentActionItem {
  id: string;
  actionType: string;
  recommendation: string;
  dueAt?: string | null | undefined;
  isCompleted?: boolean | undefined;
  completedAt?: string | null | undefined;
  completionNote?: string | null | undefined;
  createdAt?: string | undefined;
}

export interface IncidentItem {
  id: string;
  incidentCode?: string | undefined;
  alertId?: string | null | undefined;
  title: string;
  summary: string;
  closingNote?: string | null | undefined;
  findings?: string | null | undefined;
  impactAssessment?: string | null | undefined;
  status: 'DRAFT' | 'SUBMITTED' | 'IN_REVIEW' | 'CLOSED';
  severity?: string | undefined;
  submittedToOwner?: string | null | undefined;
  submittedToAdmin?: string | null | undefined;
  createdAt: string;
  submittedAt?: string | null | undefined;
  closedAt?: string | null | undefined;
  actions?: IncidentActionItem[] | undefined;
}

export interface DetectionRuleItem {
  code?: string | undefined;
  ruleCode?: string | undefined;
  name: string;
  description?: string | undefined;
  severity: string;
  threshold: number;
  thresholdCount?: number | undefined;
  windowMinutes: number;
  cooldownMinutes?: number | undefined;
  isEnabled?: boolean | undefined;
  parameters?: Record<string, unknown> | undefined;
}

export interface AlertApiNoteDto {
  id?: string;
  note?: string;
  content?: string;
  authorName?: string;
  author?: { fullName?: string; username?: string };
  createdAt?: string;
}

export interface AlertApiDto {
  id?: string;
  alertType?: string;
  ruleCode?: string;
  alert_type?: string;
  title?: string;
  description?: string;
  severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  status?: AlertLifecycleStatus;
  detectedUserId?: string | null;
  detectedUser?: { fullName?: string; username?: string } | null;
  documentId?: string | null;
  ipAddress?: string | null;
  detectedAt?: string;
  resolutionNote?: string | null;
  resolution_note?: string | null;
  linkedAuditLogsCount?: number;
  linkedAuditLogs?: LinkedAuditLogSummary[];
  incidentReports?: LinkedIncidentSummary[];
  details?: Record<string, unknown>;
  notes?: AlertApiNoteDto[];
}

export interface IncidentApiDto {
  id?: string;
  incidentCode?: string;
  alertId?: string | null;
  title?: string;
  summary?: string;
  closingNote?: string | null;
  findings?: string | null;
  impactAssessment?: string | null;
  status?: 'DRAFT' | 'SUBMITTED' | 'IN_REVIEW' | 'CLOSED';
  severity?: string;
  submittedToOwner?: string | null;
  submittedToAdmin?: string | null;
  createdAt?: string;
  submittedAt?: string | null;
  closedAt?: string | null;
  actions?: IncidentActionItem[];
}

export interface WatermarkVerifyDto {
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
    id?: string;
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
  session?: { id?: string; ipAddress?: string; userAgent?: string | null; startedAt?: string };
  config?: { name?: string; opacityPercent?: number; fontSize?: number; includeQrCode?: boolean };
}

export interface WatermarkProvenance {
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

export interface DocumentSessionItem {
  id: string;
  accessGrantId: string;
  username: string;
  fullName: string;
  documentTitle: string;
  documentCode: string;
  versionNo: number;
  ipAddress: string;
  userAgent?: string | null | undefined;
  status: string;
  startedAt: string;
  lastActivityAt: string;
  endedAt?: string | null | undefined;
  terminatedReason?: string | null | undefined;
}

export interface SecurityTabErrors {
  alerts: string | null;
  incidents: string | null;
  sessions: string | null;
  rules: string | null;
  dlp: string | null;
}

export interface IncidentDraftPrefill {
  alertId?: string | undefined;
  title?: string | undefined;
  summary?: string | undefined;
}
