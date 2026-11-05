'use client';

import { useCallback, useEffect, useState } from 'react';
import { apiClient, ApiError } from '@/lib/api-client';
import { mapAlertDto, mapIncidentDto } from '../helpers';
import type {
  AlertApiDto,
  DetectionRuleItem,
  DocumentSessionItem,
  IncidentApiDto,
  IncidentItem,
  SecurityAlertItem,
} from '../types';

/**
 * Thuật toán: Đồng bộ Dữ liệu Giám sát SOC Chịu lỗi & Cắt Phiên Truy cập Khẩn cấp (`useSecurityData`)
 * Mục đích: Nạp song song cảnh báo bảo mật, hồ sơ sự cố, cấu hình luật phát hiện và danh sách phiên đọc đang mở, đồng thời cho phép cưỡng bức ngắt phiên nghi vấn.
 * Cơ chế hoạt động:
 *   - Chạy `Promise.all` kèm nhánh dự phòng `.catch()` riêng cho từng điểm cuối để cô lập lỗi mạng cục bộ; cập nhật lạc quan trạng thái phiên sang `TERMINATED` ngay sau lệnh ngắt `/access-sessions/:id/terminate`.
 */
export function useSecurityData() {
  const [alerts, setAlerts] = useState<SecurityAlertItem[]>([]);
  const [incidents, setIncidents] = useState<IncidentItem[]>([]);
  const [detectionRules, setDetectionRules] = useState<DetectionRuleItem[]>([]);
  const [documentSessions, setDocumentSessions] = useState<DocumentSessionItem[]>([]);
  const [terminatingSessionId, setTerminatingSessionId] = useState<string | null>(null);
  const [pendingTerminateSessionId, setPendingTerminateSessionId] = useState<string | null>(null);

  const [isLoading, setIsLoading] = useState(true);
  const [message, setMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const refreshData = useCallback(async () => {
    setIsLoading(true);
    setErrorMessage(null);
    try {
      const [alertsRes, incRes, rulesRes, sessionsRes] = await Promise.all([
        apiClient<{ data: AlertApiDto[] }>('/security-alerts?pageSize=50').catch(() => ({
          data: [],
        })),
        apiClient<{ data: IncidentApiDto[] }>('/incidents?pageSize=50').catch(() => ({ data: [] })),
        apiClient<DetectionRuleItem[] | { data?: DetectionRuleItem[] }>(
          '/security-detection/rules',
        ).catch(() => []),
        apiClient<{ data: DocumentSessionItem[] }>('/access-sessions').catch(() => ({ data: [] })),
      ]);

      setDocumentSessions(sessionsRes.data || []);
      setAlerts((alertsRes.data || []).map(mapAlertDto));
      setIncidents((incRes.data || []).map(mapIncidentDto));
      setDetectionRules(
        Array.isArray(rulesRes) ? rulesRes : Array.isArray(rulesRes?.data) ? rulesRes.data : [],
      );
    } catch (err) {
      if (err instanceof ApiError) {
        setErrorMessage(err.message);
      } else {
        setErrorMessage('Không thể tải dữ liệu an ninh thông tin.');
      }
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    let ignore = false;
    const run = async () => {
      await Promise.resolve();
      if (!ignore) {
        void refreshData();
      }
    };
    void run();
    return () => {
      ignore = true;
    };
  }, [refreshData]);

  async function runDetection() {
    setIsLoading(true);
    try {
      await apiClient('/security-detection/run', {
        method: 'POST',
        body: JSON.stringify({ windowMinutes: 60 }),
      });
      setMessage('Đã kích hoạt quét phát hiện bất thường trên toàn bộ audit log 60 phút qua.');
      await refreshData();
    } catch (err) {
      if (err instanceof ApiError) {
        setErrorMessage(err.message);
      } else {
        setErrorMessage('Không thể chạy quét bất thường.');
      }
    } finally {
      setIsLoading(false);
    }
  }

  // CONFLICT-RESOLVED: Gỡ bỏ hộp thoại xác nhận gốc của trình duyệt, chuyển sang hộp thoại phương thức ConfirmDialog chuẩn WCAG 2.1 AA (rules/ui-design-system.md §6.3)
  async function terminateSession(explicitId?: string) {
    const sessionId = explicitId ?? pendingTerminateSessionId;
    if (!sessionId) {
      return;
    }
    setTerminatingSessionId(sessionId);
    setErrorMessage(null);
    try {
      await apiClient(`/access-sessions/${sessionId}/terminate`, {
        method: 'POST',
      });
      setMessage('Đã ngắt phiên truy cập tài liệu thành công.');
      setDocumentSessions((prev) =>
        prev.map((s) => (s.id === sessionId ? { ...s, status: 'TERMINATED' } : s)),
      );
      setPendingTerminateSessionId(null);
    } catch (err) {
      if (err instanceof ApiError) {
        setErrorMessage(err.message || 'Không thể ngắt phiên truy cập.');
      } else {
        setErrorMessage('Không thể ngắt phiên truy cập.');
      }
    } finally {
      setTerminatingSessionId(null);
    }
  }

  return {
    alerts,
    incidents,
    detectionRules,
    documentSessions,
    terminatingSessionId,
    pendingTerminateSessionId,
    setPendingTerminateSessionId,
    isLoading,
    message,
    setMessage,
    errorMessage,
    setErrorMessage,
    refreshData,
    runDetection,
    terminateSession,
  };
}
