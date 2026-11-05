export interface SecurityAlertItem {
  id: string;
  ruleCode: string;
  title: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  status: 'OPEN' | 'INVESTIGATING' | 'RESOLVED' | 'FALSE_POSITIVE';
  detectedUserId?: string | undefined;
  detectedUserName?: string | undefined;
  documentId?: string | undefined;
  ipAddress?: string | undefined;
  detectedAt: string;
  details?: Record<string, unknown> | undefined;
  notes?: Array<{ note: string; authorName: string; createdAt: string }> | undefined;
}

export interface IncidentItem {
  id: string;
  title: string;
  summary: string;
  status: 'DRAFT' | 'SUBMITTED' | 'IN_REVIEW' | 'CLOSED';
  severity?: string | undefined;
  createdAt: string;
  actions?:
    | Array<{
        id: string;
        actionType: string;
        recommendation: string;
        isCompleted: boolean;
      }>
    | undefined;
}

export interface DetectionRuleItem {
  code: string;
  name: string;
  severity: string;
  threshold: number;
  windowMinutes: number;
  isEnabled?: boolean | undefined;
}

export interface AlertApiDto {
  id?: string;
  ruleCode?: string;
  alert_type?: string;
  title?: string;
  severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  status?: 'OPEN' | 'INVESTIGATING' | 'RESOLVED' | 'FALSE_POSITIVE';
  detectedUserId?: string;
  detectedUser?: { fullName?: string };
  documentId?: string;
  ipAddress?: string;
  detectedAt?: string;
  details?: Record<string, unknown>;
}

export interface IncidentApiDto {
  id?: string;
  title?: string;
  summary?: string;
  status?: 'DRAFT' | 'SUBMITTED' | 'IN_REVIEW' | 'CLOSED';
  severity?: string;
  createdAt?: string;
  actions?: Array<{
    id: string;
    actionType: string;
    recommendation: string;
    isCompleted: boolean;
  }>;
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
