import type {
  AlertApiDto,
  AlertNoteItem,
  IncidentApiDto,
  IncidentItem,
  SecurityAlertItem,
  WatermarkProvenance,
  WatermarkVerifyDto,
} from './types';

export const AUDIT_PARTITIONS = [
  'GLOBAL',
  'AUTH',
  'DOCUMENT',
  'ACCESS_SESSION',
  'RBAC',
  'AUDIT',
  'SECURITY',
  'SECURITY_OPERATIONS',
] as const;

const MAX_PG_BIGINT = 9223372036854775807n;

/**
 * Thuật toán: Kiểm Định Định Danh Số Nguyên Dương PostgreSQL `BIGINT` (`isValidPositiveBigIntId`)
 * Mục đích: Chỉ chấp nhận số nguyên dương thuộc đoạn `[1, 9223372036854775807]`, từ chối `"0"`, số âm và giá trị tràn 64-bit có dấu.
 */
export function isValidPositiveBigIntId(raw: string): boolean {
  const trimmed = raw.trim();
  if (!/^[1-9]\d*$/u.test(trimmed) || trimmed.length > 19) return false;
  try {
    const val = BigInt(trimmed);
    return val >= 1n && val <= MAX_PG_BIGINT;
  } catch {
    return false;
  }
}

const WATERMARK_CLASSIFICATION_LABELS: Readonly<Record<string, string>> = {
  PUBLIC: 'Công khai',
  UNCLASSIFIED: 'Không mật',
  INTERNAL: 'Nội bộ',
  RESTRICTED: 'Nội bộ hạn chế',
  CONFIDENTIAL: 'Mật',
  SECRET: 'Tối mật',
  TOP_SECRET: 'Tuyệt mật',
};

function formatWatermarkClassification(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) return 'Chưa phân loại';
  const normalized = trimmed.toUpperCase().replace(/[\s-]+/gu, '_');
  return WATERMARK_CLASSIFICATION_LABELS[normalized] ?? trimmed;
}

/**
 * Thuật toán: Chuẩn hóa Dữ liệu Cảnh báo, Mô tả Kỹ thuật, IP Nguồn & Lịch sử Ghi chú Điều tra (`mapAlertDto`)
 */
export function mapAlertDto(a: AlertApiDto): SecurityAlertItem {
  const detailResolution =
    typeof a.details?.['resolutionNote'] === 'string' ? a.details['resolutionNote'] : null;
  const normalizedNotes: AlertNoteItem[] = Array.isArray(a.notes)
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
    ruleCode: a.alertType || a.ruleCode || a.alert_type || 'ANOMALY_DETECTION',
    title: a.title || 'Phát hiện hành vi bất thường',
    description: (a.description || '').trim(),
    severity: a.severity || 'HIGH',
    status: a.status || 'OPEN',
    detectedUserId: a.detectedUserId ?? undefined,
    detectedUserName:
      a.detectedUser?.fullName ||
      a.detectedUser?.username ||
      (a.detectedUserId ? `Người dùng #${a.detectedUserId}` : 'Chưa định danh'),
    documentId: a.documentId ?? undefined,
    ipAddress: a.ipAddress?.trim() || '—',
    detectedAt: a.detectedAt || '',
    resolutionNote: a.resolutionNote ?? a.resolution_note ?? detailResolution,
    linkedAuditLogsCount: a.linkedAuditLogsCount ?? a.linkedAuditLogs?.length ?? 0,
    linkedAuditLogs: a.linkedAuditLogs,
    incidentReports: a.incidentReports,
    details: a.details,
    notes: normalizedNotes,
  };
}

/**
 * Thuật toán: Ánh xạ DTO Hồ Sơ Sự Cố Kèm Tách Riêng `closingNote` & Người Nhận Trình Duyệt (`mapIncidentDto`).
 */
export function mapIncidentDto(inc: IncidentApiDto): IncidentItem {
  return {
    id: inc.id || '—',
    incidentCode: inc.incidentCode,
    alertId: inc.alertId ?? null,
    title: inc.title || 'Hồ sơ sự cố an ninh',
    summary: inc.summary || '',
    closingNote: inc.closingNote ?? null,
    findings: inc.findings ?? '',
    impactAssessment: inc.impactAssessment ?? '',
    status: inc.status || 'DRAFT',
    severity: inc.severity || 'HIGH',
    submittedToOwner: inc.submittedToOwner ?? null,
    submittedToAdmin: inc.submittedToAdmin ?? null,
    createdAt: inc.createdAt || '',
    submittedAt: inc.submittedAt ?? null,
    closedAt: inc.closedAt ?? null,
    actions: inc.actions || [],
  };
}

/**
 * Thuật toán: Lọc Đa Chiều Hàng Đợi Cảnh Báo SOC Theo Mức Nghiêm Trọng & Trạng Thái (`filterSecurityAlerts`)
 */
export function filterSecurityAlerts(
  alerts: SecurityAlertItem[],
  severityFilter: string,
  statusFilter: string,
): SecurityAlertItem[] {
  return alerts.filter((alert) => {
    const matchSeverity = severityFilter === 'ALL' || alert.severity === severityFilter;
    const matchStatus = statusFilter === 'ALL' || alert.status === statusFilter;
    return matchSeverity && matchStatus;
  });
}

/**
 * Thuật toán: Chuẩn Hóa & Trích Xuất Token Watermark Không Phân Biệt Hoa Thường Hỗ Trợ QR JSON & Dải 12–64 Ký Tự Hex (`normalizeWatermarkTokenInput`)
 * Mục đích:
 *   - Tự động trích xuất `token` nếu quét mã QR từ PDF rò rỉ và dán nguyên chuỗi JSON `{"token":"WM-..."}`.
 *   - Chấp nhận tiền tố `WM-` hoặc `wm-` không phân biệt hoa thường (`/iu`) và chuẩn hóa đầu ra về `'WM-' + hex.toLowerCase()`.
 */
export function normalizeWatermarkTokenInput(
  raw: string,
): { valid: true; token: string } | { valid: false; error: string } {
  let candidate = raw.trim();
  if (!candidate) {
    return { valid: false, error: 'Vui lòng nhập mã watermark cần đối soát.' };
  }

  if (candidate.startsWith('{') && candidate.endsWith('}')) {
    try {
      const parsed = JSON.parse(candidate) as Record<string, unknown>;
      if (typeof parsed['token'] === 'string' && parsed['token'].trim()) {
        candidate = parsed['token'].trim();
      }
    } catch {
      // Thử trích xuất bằng biểu thức chính quy bên dưới
    }
  }

  const embeddedMatch = /\bWM-([0-9a-fA-F]{12,64})\b/iu.exec(candidate);
  if (embeddedMatch && embeddedMatch[1]) {
    return { valid: true, token: 'WM-' + embeddedMatch[1].toLowerCase() };
  }

  if (/^[0-9a-fA-F]{12,64}$/u.test(candidate)) {
    return { valid: true, token: 'WM-' + candidate.toLowerCase() };
  }

  return {
    valid: false,
    error:
      'Mã watermark không đúng định dạng. Vui lòng nhập mã WM- (12–64 ký tự hex), dán nội dung mã QR hoặc dải chữ watermark trích xuất từ tài liệu PDF.',
  };
}

/**
 * Thuật toán: Lọc Phân loại Cảnh báo Rò rỉ Dữ liệu Mạng (`filterNetworkDlpAlerts`)
 */
export function filterNetworkDlpAlerts(alerts: SecurityAlertItem[]): SecurityAlertItem[] {
  return alerts.filter(
    (a) =>
      a.ruleCode === 'NETWORK_DLP_VIOLATION' ||
      a.ruleCode.includes('DLP') ||
      a.title?.toLowerCase().includes('dlp'),
  );
}

/**
 * Thuật toán: Chuẩn hóa Đầy Đủ 8 Trường Pháp Chứng Watermark Chế độ Fail-Closed (`mapWatermarkVerifyDto`)
 */
export function mapWatermarkVerifyDto(res: WatermarkVerifyDto): WatermarkProvenance {
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
      ? formatWatermarkClassification(rawClassification)
      : 'Chưa phân loại',
    configSummary,
  };
}
