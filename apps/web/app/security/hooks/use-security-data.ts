'use client';

import { useCallback, useEffect, useState } from 'react';
import { apiClient, ApiError } from '@/lib/api-client';
import { applyOptimisticStatusById } from '@/lib/optimistic-state';
import { mapAlertDto, mapIncidentDto } from '../helpers';
import type {
  AlertApiDto,
  AlertNoteItem,
  DetectionRuleItem,
  DocumentSessionItem,
  GatewayHealthStatus,
  IncidentApiDto,
  IncidentItem,
  SecurityAlertItem,
  SecurityPaginatedResponse,
} from '../types';

export interface OptimisticAlertPatch {
  status?: SecurityAlertItem['status'] | undefined;
  resolutionNote?: string | undefined;
  addedNote?: AlertNoteItem | undefined;
}

async function probeGatewayHealth(signal?: AbortSignal): Promise<GatewayHealthStatus> {
  try {
    const res = await apiClient<{ status?: string }>('/health/ready', { signal });
    const normalized = (res?.status || '').toUpperCase();
    return normalized === 'READY' || normalized === 'OK' ? 'ONLINE' : 'DEGRADED';
  } catch (err) {
    if (err instanceof ApiError && err.status === 503) {
      return 'DEGRADED';
    }
    return 'OFFLINE';
  }
}

/**
 * Thuật toán: Đồng bộ Dữ liệu Giám sát SOC Chế độ Fail-Closed & Ngắt Phiên Khẩn cấp (`useSecurityData`)
 * Mục đích: Tải song song cảnh báo bảo mật, hồ sơ sự cố, luật phát hiện, phiên đọc đang hoạt động và trạng thái sức khỏe cổng DLP mà tuyệt đối không nuốt lỗi API thành mảng rỗng giả.
 * Cơ chế hoạt động:
 *   - Chạy `Promise.all` không che giấu ngoại lệ mạng/`401`/`403`/`500` để cảnh báo rõ ràng cho cán bộ SOC kèm nút thử lại.
 *   - Hỗ trợ cập nhật lạc quan trạng thái cảnh báo, kết luận xử lý (`resolutionNote`) và ghi chú điều tra (`notes`) kèm hàm hoàn tác nguyên tử.
 */
export function useSecurityData() {
  const [alerts, setAlerts] = useState<SecurityAlertItem[]>([]);
  const [incidents, setIncidents] = useState<IncidentItem[]>([]);
  const [detectionRules, setDetectionRules] = useState<DetectionRuleItem[]>([]);
  const [documentSessions, setDocumentSessions] = useState<DocumentSessionItem[]>([]);
  const [gatewayHealth, setGatewayHealth] = useState<GatewayHealthStatus>('ONLINE');
  const [terminatingSessionId, setTerminatingSessionId] = useState<string | null>(null);
  const [pendingTerminateSessionId, setPendingTerminateSessionId] = useState<string | null>(null);

  const [isLoading, setIsLoading] = useState(true);
  const [message, setMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const loadSnapshot = useCallback(async (signal?: AbortSignal) => {
    const reqOpts = signal ? { signal } : undefined;
    const [alertsRes, incRes, rulesRes, sessionsRes, healthStatus] = await Promise.all([
      apiClient<SecurityPaginatedResponse<AlertApiDto>>('/security-alerts?pageSize=50', reqOpts),
      apiClient<SecurityPaginatedResponse<IncidentApiDto>>('/incidents?pageSize=50', reqOpts),
      apiClient<DetectionRuleItem[] | { data?: DetectionRuleItem[] }>(
        '/security-detection/rules',
        reqOpts,
      ),
      apiClient<SecurityPaginatedResponse<DocumentSessionItem>>('/access-sessions', reqOpts),
      probeGatewayHealth(signal),
    ]);
    return { alertsRes, incRes, rulesRes, sessionsRes, healthStatus };
  }, []);

  const refreshData = useCallback(
    async (options?: { silent?: boolean; signal?: AbortSignal }) => {
      if (!options?.silent) {
        setIsLoading(true);
      }
      setErrorMessage(null);
      try {
        const snap = await loadSnapshot(options?.signal);
        if (options?.signal?.aborted) return;

        setGatewayHealth(snap.healthStatus);
        setDocumentSessions(snap.sessionsRes.data || []);
        setAlerts((snap.alertsRes.data || []).map(mapAlertDto));
        setIncidents((snap.incRes.data || []).map(mapIncidentDto));
        setDetectionRules(
          Array.isArray(snap.rulesRes)
            ? snap.rulesRes
            : Array.isArray(snap.rulesRes?.data)
              ? snap.rulesRes.data
              : [],
        );
      } catch (err) {
        if (options?.signal?.aborted) return;
        setGatewayHealth('DEGRADED');
        setErrorMessage(
          err instanceof ApiError
            ? err.message || 'Không thể tải dữ liệu giám sát an ninh SOC.'
            : 'Không thể kết nối máy chủ giám sát an ninh thông tin.',
        );
      } finally {
        if (!options?.silent && !options?.signal?.aborted) {
          setIsLoading(false);
        }
      }
    },
    [loadSnapshot],
  );

  useEffect(() => {
    const controller = new AbortController();
    let cancelled = false;
    void (async () => {
      try {
        const snap = await loadSnapshot(controller.signal);
        if (cancelled) return;
        setGatewayHealth(snap.healthStatus);
        setDocumentSessions(snap.sessionsRes.data || []);
        setAlerts((snap.alertsRes.data || []).map(mapAlertDto));
        setIncidents((snap.incRes.data || []).map(mapIncidentDto));
        setDetectionRules(
          Array.isArray(snap.rulesRes)
            ? snap.rulesRes
            : Array.isArray(snap.rulesRes?.data)
              ? snap.rulesRes.data
              : [],
        );
        setErrorMessage(null);
      } catch (err) {
        if (cancelled) return;
        setGatewayHealth('DEGRADED');
        setErrorMessage(
          err instanceof ApiError
            ? err.message || 'Không thể tải dữ liệu giám sát an ninh SOC.'
            : 'Không thể kết nối máy chủ giám sát an ninh thông tin.',
        );
      } finally {
        if (!cancelled) {
          setIsLoading(false);
        }
      }
    })();
    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [loadSnapshot]);

  async function runDetection() {
    setErrorMessage(null);
    try {
      await apiClient('/security-detection/run', {
        method: 'POST',
        body: JSON.stringify({ windowMinutes: 60 }),
      });
      setMessage('Đã kích hoạt quét phát hiện bất thường trên toàn bộ audit log 60 phút qua.');
      await refreshData({ silent: true });
    } catch (err) {
      setErrorMessage(
        err instanceof ApiError ? err.message : 'Không thể chạy quét phát hiện bất thường.',
      );
    }
  }

  function applyOptimisticAlertUpdate(alertId: string, patch: OptimisticAlertPatch): () => void {
    const previousAlerts = alerts;
    setAlerts((prev) =>
      prev.map((item) => {
        if (item.id !== alertId) return item;
        return {
          ...item,
          status: patch.status ?? item.status,
          resolutionNote:
            patch.resolutionNote !== undefined ? patch.resolutionNote : item.resolutionNote,
          notes: patch.addedNote ? [...(item.notes ?? []), patch.addedNote] : item.notes,
        };
      }),
    );
    return () => {
      setAlerts(previousAlerts);
    };
  }

  async function terminateSession(reason: string, explicitId?: string): Promise<boolean> {
    const sessionId = explicitId ?? pendingTerminateSessionId;
    if (!sessionId) return false;

    setTerminatingSessionId(sessionId);
    setErrorMessage(null);

    try {
      await apiClient(`/access-sessions/${sessionId}/terminate`, {
        method: 'POST',
        body: JSON.stringify({ reason }),
      });
      setDocumentSessions((prev) => applyOptimisticStatusById(prev, sessionId, 'TERMINATED'));
      setPendingTerminateSessionId(null);
      setMessage('Đã cưỡng bức ngắt phiên truy cập tài liệu thành công.');
      void refreshData({ silent: true });
      return true;
    } catch (err) {
      setErrorMessage(
        err instanceof ApiError
          ? err.message || 'Không thể ngắt phiên truy cập.'
          : 'Không thể ngắt phiên truy cập.',
      );
      return false;
    } finally {
      setTerminatingSessionId(null);
    }
  }

  return {
    alerts,
    incidents,
    detectionRules,
    documentSessions,
    gatewayHealth,
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
    applyOptimisticAlertUpdate,
    terminateSession,
  };
}
