import type { SharedPaginationMeta } from '@sda/contracts';

export type AlertLifecycleStatus =
  'OPEN' | 'INVESTIGATING' | 'ESCALATED' | 'RESOLVED' | 'FALSE_POSITIVE';

export type GatewayHealthStatus = 'ONLINE' | 'DEGRADED' | 'OFFLINE';

export interface AlertNoteItem {
  id?: string | undefined;
  note: string;
  authorName: string;
  createdAt: string;
}

export interface SecurityAlertItem {
  id: string;
  ruleCode: string;
  title: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  status: AlertLifecycleStatus;
  detectedUserId?: string | undefined;
  detectedUserName?: string | undefined;
  documentId?: string | undefined;
  ipAddress?: string | undefined;
  detectedAt: string;
  resolutionNote?: string | null | undefined;
  details?: Record<string, unknown> | undefined;
  notes?: AlertNoteItem[] | undefined;
}

export interface SecurityPaginatedResponse<T> {
  data: T[];
  meta?: SharedPaginationMeta | undefined;
}

export interface IncidentActionItem {
  id: string;
  actionType: string;
  recommendation: string;
  isCompleted?: boolean | undefined;
  completedAt?: string | null | undefined;
}

export interface IncidentItem {
  id: string;
  title: string;
  summary: string;
  status: 'DRAFT' | 'SUBMITTED' | 'IN_REVIEW' | 'CLOSED';
  severity?: string | undefined;
  createdAt: string;
  actions?: IncidentActionItem[] | undefined;
}

export interface DetectionRuleItem {
  code?: string | undefined;
  ruleCode?: string | undefined;
  name: string;
  severity: string;
  threshold: number;
  windowMinutes: number;
  isEnabled?: boolean | undefined;
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
  severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  status?: AlertLifecycleStatus;
  detectedUserId?: string;
  detectedUser?: { fullName?: string };
  documentId?: string;
  ipAddress?: string;
  detectedAt?: string;
  resolutionNote?: string | null;
  resolution_note?: string | null;
  details?: Record<string, unknown>;
  notes?: AlertApiNoteDto[];
}

export interface IncidentApiDto {
  id?: string;
  title?: string;
  summary?: string;
  status?: 'DRAFT' | 'SUBMITTED' | 'IN_REVIEW' | 'CLOSED';
  severity?: string;
  createdAt?: string;
  actions?: IncidentActionItem[];
}

export interface WatermarkVerifyDto {
  verified?: boolean;
  watermarkToken?: string;
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
  };
  user?: { username?: string; fullName?: string | null; employeeCode?: string | null };
  session?: { id?: string; ipAddress?: string };
}

export interface WatermarkProvenance {
  verified: boolean;
  documentTitle: string;
  documentCode: string;
  recipientName: string;
  employeeCode: string;
  sessionId: string;
  ipAddress: string;
  generatedAtUtc: string;
  classificationName: string;
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
  status: string;
  startedAt: string;
  lastActivityAt: string;
}
