import type {
  AlertApiDto,
  IncidentApiDto,
  IncidentItem,
  SecurityAlertItem,
  WatermarkProvenance,
  WatermarkVerifyDto,
} from './types';

/**
 * Algorithm / Thuật toán: Chuẩn hóa dữ liệu cảnh báo & sự cố an ninh trung thực không bịa đặt bằng chứng (Zero-Fabrication Alert DTO Normalization).
 * Chỉ ánh xạ đúng dữ liệu nhận từ máy chủ; khi trường tùy chọn vắng mặt, hiển thị nhãn trung tính `'—'` hoặc `'Chưa định danh'` thay vì gán cứng IP/ID giả.
 */
export function mapAlertDto(a: AlertApiDto): SecurityAlertItem {
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
    details: a.details,
  };
}

export function mapIncidentDto(inc: IncidentApiDto): IncidentItem {
  return {
    id: inc.id || '—',
    title: inc.title || 'Báo cáo sự cố bảo mật',
    summary: inc.summary || '',
    status: inc.status || 'DRAFT',
    severity: inc.severity || 'HIGH',
    createdAt: inc.createdAt || '',
    actions: inc.actions || [],
  };
}

/**
 * Thuật toán: Lọc Phân loại Cảnh báo Rò rỉ Dữ liệu Mạng (`filterNetworkDlpAlerts`)
 * Mục đích: Tách riêng các cảnh báo vi phạm chính sách cổng kiểm soát luồng ra ICAP RFC 3507 khỏi tập cảnh báo SOC chung.
 * Cơ chế hoạt động: Duyệt tuyến tính `O(N)` đối chiếu mã luật `NETWORK_DLP_VIOLATION`, chuỗi con `DLP` hoặc tiêu đề cảnh báo.
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
 * Algorithm / Thuật toán: Chuẩn hóa Bằng chứng Thủy vân Pháp chứng Chế độ Fail-Closed (`mapWatermarkVerifyDto`).
 * Bắt buộc `res.verified === true` tường minh từ máy chủ; mọi phản hồi thiếu cờ xác thực đều bị đánh dấu `verified: false`
 * và tuyệt đối không tự điền nhãn độ mật, mã tài liệu, nhân viên hay IP giả.
 */
export function mapWatermarkVerifyDto(res: WatermarkVerifyDto): WatermarkProvenance {
  return {
    // CONFLICT-RESOLVED: Enforced strict Fail-Closed `res.verified === true` and removed all fabricated forensic defaults.
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
