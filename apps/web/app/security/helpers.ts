import type {
  AlertApiDto,
  AlertNoteItem,
  IncidentApiDto,
  IncidentItem,
  SecurityAlertItem,
  WatermarkProvenance,
  WatermarkVerifyDto,
} from './types';

/**
 * Thuật toán: Chuẩn hóa Dữ liệu Cảnh báo, Lịch sử Ghi chú Điều tra & Sự cố An ninh Không Bịa đặt (`mapAlertDto`)
 * Mục đích: Ánh xạ trung thực dữ liệu cảnh báo từ máy chủ kèm `resolutionNote` và danh sách `notes` điều tra; khi trường tùy chọn vắng mặt, hiển thị nhãn trung tính `'—'`.
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
            n.authorName || n.author?.fullName || n.author?.username || 'Cán bộ An ninh (SOC)',
          createdAt: n.createdAt || a.detectedAt || '',
        }))
        .filter((item) => item.note.length > 0)
    : [];

  return {
    id: a.id || '—',
    ruleCode: a.alertType || a.ruleCode || a.alert_type || 'ANOMALY_DETECTION',
    title: a.title || 'Phát hiện hành vi bất thường',
    severity: a.severity || 'HIGH',
    status: a.status || 'OPEN',
    detectedUserId: a.detectedUserId,
    detectedUserName:
      a.detectedUser?.fullName ||
      (a.detectedUserId ? `Người dùng #${a.detectedUserId}` : 'Chưa định danh'),
    documentId: a.documentId,
    ipAddress: a.ipAddress || '—',
    detectedAt: a.detectedAt || '',
    resolutionNote: a.resolutionNote ?? a.resolution_note ?? detailResolution,
    details: a.details,
    notes: normalizedNotes,
  };
}

export function mapIncidentDto(inc: IncidentApiDto): IncidentItem {
  return {
    id: inc.id || '—',
    incidentCode: inc.incidentCode,
    alertId: inc.alertId ?? null,
    title: inc.title || 'Báo cáo sự cố bảo mật',
    summary: inc.summary || '',
    findings: inc.findings ?? '',
    impactAssessment: inc.impactAssessment ?? '',
    status: inc.status || 'DRAFT',
    severity: inc.severity || 'HIGH',
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
 * Thuật toán: Chuẩn Hóa & Kiểm Định Định Dạng Token Watermark Phía Máy Khách (`normalizeWatermarkTokenInput`)
 * Mục đích: Tự động ghép tiền tố `WM-` nếu chuyên viên SOC dán chuỗi hex 12–48 ký tự từ PDF thiếu `WM-`; từ chối sớm bằng thông báo tiếng Việt nếu sai định dạng để tránh lỗi `400`.
 */
export function normalizeWatermarkTokenInput(
  raw: string,
): { valid: true; token: string } | { valid: false; error: string } {
  const trimmed = raw.trim();
  if (!trimmed) {
    return { valid: false, error: 'Vui lòng nhập mã token watermark cần đối soát.' };
  }
  if (/^[0-9a-fA-F]{12,48}$/u.test(trimmed)) {
    return { valid: true, token: `WM-${trimmed.toLowerCase()}` };
  }
  const prefixedMatch = /^WM-([0-9a-fA-F]{12,48})$/iu.exec(trimmed);
  if (prefixedMatch && prefixedMatch[1]) {
    return { valid: true, token: `WM-${prefixedMatch[1].toLowerCase()}` };
  }
  return {
    valid: false,
    error:
      'Mã watermark không đúng định dạng. Vui lòng nhập mã dạng WM-<12..48 ký tự hex> (ví dụ: WM-2e59958fa6c7) hoặc dán chuỗi hex 12–48 ký tự từ tài liệu PDF.',
  };
}

/**
 * Thuật toán: Lọc Phân loại Cảnh báo Rò rỉ Dữ liệu Mạng (`filterNetworkDlpAlerts`)
 * Mục đích: Tách riêng các cảnh báo vi phạm chính sách cổng kiểm soát luồng ra ICAP RFC 3507 khỏi tập cảnh báo SOC chung.
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
 * Thuật toán: Chuẩn hóa Bằng chứng Watermark Pháp chứng Chế độ Fail-Closed (`mapWatermarkVerifyDto`)
 * Mục đích: Bắt buộc `res.verified === true` tường minh từ máy chủ; mọi phản hồi thiếu cờ xác thực đều bị đánh dấu `verified: false`.
 */
export function mapWatermarkVerifyDto(res: WatermarkVerifyDto): WatermarkProvenance {
  return {
    verified: res.verified === true,
    documentTitle: res.document?.title || res.documentTitle || 'Chưa ghi nhận',
    documentCode: res.document?.documentCode || res.documentCode || '—',
    recipientName: res.user?.fullName || res.user?.username || res.recipientName || 'Chưa ghi nhận',
    employeeCode: res.user?.employeeCode || res.employeeCode || '—',
    sessionId: res.session?.id || res.sessionId || '—',
    ipAddress: res.session?.ipAddress || res.ipAddress || '—',
    generatedAtUtc: res.generatedAt || res.generatedAtUtc || '—',
    classificationName:
      res.classificationName || res.document?.classificationName || 'Chưa phân loại',
  };
}
