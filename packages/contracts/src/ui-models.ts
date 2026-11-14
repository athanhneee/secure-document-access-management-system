import type { ExportFormat, ExportType } from './dto/audit-reports.dto.js';

/**
 * Module: Shared UI Models (`@sda/contracts`)
 * Mô hình dữ liệu chuẩn dùng chung giữa `@sda/api` và `@sda/web` cho siêu dữ liệu phân trang và lịch sử tác vụ xuất báo cáo.
 */
export interface SharedPaginationMeta {
  page: number;
  pageSize?: number;
  total: number;
  totalPages: number;
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
