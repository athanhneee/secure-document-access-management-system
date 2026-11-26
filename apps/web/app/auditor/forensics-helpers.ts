import { normalizeWatermarkTokenInput } from '@/app/security/helpers';
import { formatClassificationLabel } from '@/lib/ui-labels';
import type {
  AuditorAlertApiDto,
  AuditorAlertItem,
  AuditorWatermarkProvenance,
  AuditorWatermarkVerifyDto,
} from './types';

/**
 * Thuật toán: Chuẩn Hóa DTO Cảnh Báo An Ninh Chỉ Đọc Cho Kiểm Toán Viên (`mapAuditorAlertDto`)
 */
export function mapAuditorAlertDto(a: AuditorAlertApiDto): AuditorAlertItem {
  const notes = Array.isArray(a.notes)
    ? a.notes
        .map((n) => ({
          id: n.id,
          note: (n.note || n.content || '').trim(),
          authorName:
            n.authorName || n.author?.fullName || n.author?.username || 'Cán bộ an ninh thông tin',
          createdAt: n.createdAt || a.detectedAt || '',
        }))
        .filter((item) => item.note.length > 0)
    : [];
  return {
    id: a.id || '—',
    ruleCode: a.alertType || a.ruleCode || 'ANOMALY_DETECTION',
    title: a.title || 'Phát hiện hành vi bất thường',
    description: (a.description || '').trim(),
    severity: a.severity || 'HIGH',
    status: a.status || 'OPEN',
    detectedUserName:
      a.detectedUser?.fullName ||
      a.detectedUser?.username ||
      (a.detectedUserId ? `Người dùng #${a.detectedUserId}` : 'Chưa định danh'),
    ipAddress: a.ipAddress?.trim() || '—',
    detectedAt: a.detectedAt || '',
    resolutionNote: a.resolutionNote ?? null,
    linkedAuditLogs: a.linkedAuditLogs,
    notes,
  };
}

/**
 * Thuật toán: Chuẩn Hóa Token Watermark Không Phân Biệt Hoa Thường Dùng Chung Với SOC (`normalizeAuditorWatermarkInput`)
 * Mục đích: Chấp nhận cả tiền tố `WM-` và `wm-` (`/\bWM-([0-9a-fA-F]{12,64})\b/iu`), chuỗi hex trần 12–64 ký tự hoặc JSON mã QR, chuẩn hóa về `'WM-' + hex.toLowerCase()`.
 */
export function normalizeAuditorWatermarkInput(
  raw: string,
): { valid: true; token: string } | { valid: false; error: string } {
  return normalizeWatermarkTokenInput(raw);
}

/**
 * Thuật toán: Ánh Xạ 8 Trường Pháp Chứng Watermark Chế Độ Chỉ Đọc (`mapAuditorWatermarkDto`)
 */
export function mapAuditorWatermarkDto(res: AuditorWatermarkVerifyDto): AuditorWatermarkProvenance {
  const rawClassification = res.classificationName || res.document?.classificationName || '';
  const cfg = res.config;
  const configSummary = cfg?.name
    ? `${cfg.name} (độ mờ ${cfg.opacityPercent ?? '—'}% · ${cfg.includeQrCode ? 'có mã QR' : 'không QR'})`
    : '—';
  return {
    verified: res.verified === true,
    watermarkToken: res.watermarkToken || '—',
    renderedText: res.renderedText || '—',
    outputSha256Hash: res.outputSha256Hash || '—',
    originalSha256Hash: res.document?.originalSha256Hash || '—',
    documentTitle: res.document?.title || res.documentTitle || 'Chưa ghi nhận',
    documentCode: res.document?.documentCode || res.documentCode || '—',
    versionNo: typeof res.document?.versionNo === 'number' ? res.document.versionNo : null,
    recipientName: res.user?.fullName || res.user?.username || res.recipientName || 'Chưa ghi nhận',
    recipientEmail: res.user?.email || '—',
    employeeCode: res.user?.employeeCode || res.employeeCode || '—',
    sessionId: res.session?.id || res.sessionId || '—',
    ipAddress: res.session?.ipAddress || res.ipAddress || '—',
    userAgent: res.session?.userAgent || '—',
    generatedAtUtc: res.generatedAt || res.generatedAtUtc || '—',
    classificationName: rawClassification
      ? formatClassificationLabel(rawClassification)
      : 'Chưa phân loại',
    configSummary,
  };
}
