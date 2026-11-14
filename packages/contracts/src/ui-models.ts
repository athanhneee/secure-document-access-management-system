import type { ClassificationCode } from './classifications.js';
import type { ExportFormat, ExportType } from './dto/audit-reports.dto.js';
import type { AlertStatus, IncidentStatus, SeverityLevel } from './dto/security-operations.dto.js';

/**
 * Mô hình dữ liệu chuẩn dùng chung giữa `@sda/api` và `@sda/web` giúp loại bỏ định nghĩa DTO rời rạc trên 5 không gian làm việc giao diện.
 */
export interface SharedPaginationMeta {
  page: number;
  pageSize?: number;
  total: number;
  totalPages: number;
}

export interface SharedPaginatedEnvelope<T> {
  data: T[];
  pagination?: SharedPaginationMeta;
  meta?: SharedPaginationMeta;
}

export interface SharedDepartmentOption {
  id: string | number;
  code: string;
  name: string;
  parentId?: string | number | null;
  isActive?: boolean;
}

export interface SharedClassificationOption {
  id: string | number;
  code: ClassificationCode | string;
  name: string;
  rank: number;
  allowDownload: boolean;
  requireWatermark: boolean;
  isActive?: boolean;
}

export interface SharedExportJobSummary {
  id: string;
  exportType: ExportType | string;
  format: ExportFormat | string;
  status: 'PENDING' | 'PROCESSING' | 'COMPLETED' | 'FAILED' | 'EXPIRED' | string;
  rowCount?: number;
  fileSizeBytes?: string | number | null;
  sha256Hash?: string | null;
  errorMessage?: string | null;
  createdAt: string;
  completedAt?: string | null;
  expiresAt: string;
}

export interface SharedSecurityAlertSummary {
  id: string;
  alertType: string;
  severity: SeverityLevel;
  status: AlertStatus;
  title: string;
  description: string;
  detectedUserId?: string | null;
  documentId?: string | null;
  detectedAt: string;
  assignedTo?: string | null;
  resolvedAt?: string | null;
  resolutionNote?: string | null;
}

export interface SharedIncidentSummary {
  id: string;
  incidentCode: string;
  alertId?: string | null;
  title: string;
  summary: string;
  status: IncidentStatus;
  createdAt: string;
  submittedAt?: string | null;
  closedAt?: string | null;
}
