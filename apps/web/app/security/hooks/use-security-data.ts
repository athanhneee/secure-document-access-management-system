'use client';

import { useCallback, useEffect, useState } from 'react';
import { apiClient, ApiError } from '@/lib/api-client';
import { useAuth } from '@/lib/auth-context';
import { applyOptimisticStatusById } from '@/lib/optimistic-state';
import { subscribeRealtimeEvent } from '@/lib/realtime-events';
import { mapAlertDto, mapIncidentDto } from '../helpers';
import type {
  AlertApiDto,
  AlertNoteItem,
  DetectionRuleItem,
  DocumentSessionItem,
  IncidentApiDto,
  IncidentItem,
  NetworkDlpStatus,
  SecurityAlertItem,
  SecurityPaginatedResponse,
  SecurityTabErrors,
} from '../types';

export interface OptimisticAlertPatch {
  status?: SecurityAlertItem['status'] | undefined;
  resolutionNote?: string | undefined;
  addedNote?: AlertNoteItem | undefined;
}

const DEFAULT_DLP_STATUS: NetworkDlpStatus = {
  gatewayHealth: 'OFFLINE',
  workerReachable: false,
  icapEnabled: false,
  icapListening: false,
  enforcementMode: 'OFFLINE',
  totalDlpAlerts: 0,
  openDlpAlerts: 0,
  checkedAt: '',
};

const EMPTY_TAB_ERRORS: SecurityTabErrors = {
  alerts: null,
  incidents: null,
  sessions: null,
  rules: null,
  dlp: null,
};

function formatTabError(err: unknown, fallback: string): string {
  return err instanceof ApiError ? err.message || fallback : fallback;
}

/**
 * Thuật toán: Đồng Bộ Đa Phân Hệ SOC Cô Lập Lỗi Từng Tab (`Promise.allSettled`), Phân Trang Máy Chủ & Sức Khỏe DLP Thực (`useSecurityData`)
 * Mục đích:
 *   - Đọc quyền trực tiếp từ `useAuth()` để chỉ gọi API các phân hệ được cấp phép, cô lập lỗi từng tab bằng `Promise.allSettled` mà không làm trắng xóa cả 6 tab (#10).
 *   - Truy vấn phân trang & lọc phía máy chủ cho Cảnh báo, Sự cố, Phiên đọc (`ACTIVE`/`ALL`/`ENDED`/`TERMINATED`) và DLP độc lập (`alertType=NETWORK_DLP_VIOLATION`) kèm `/security-operations/dlp-status` (#06, #12, #13, #29, #33).
 *   - Đăng ký đầy đủ 4 kênh SSE thời gian thực (`SECURITY_ALERT_UPDATED`, `INCIDENT_REPORT_UPDATED`, `DETECTION_RULE_UPDATED`, `ACCESS_SESSION_UPDATED`) (#31).
 */
export function useSecurityData() {
  const { hasPermission } = useAuth();
  const canViewAlerts = hasPermission('SECURITY_ALERT:VIEW');
  const canManageAlerts = hasPermission('SECURITY_ALERT:MANAGE');
  const canViewIncidents =
    hasPermission('SECURITY_ALERT:VIEW') ||
    hasPermission('INCIDENT_REPORT:CREATE') ||
    hasPermission('INCIDENT_REPORT:MANAGE');
  const canTerminateSession = hasPermission('ACCESS_SESSION:TERMINATE');
  const canViewRules = canViewAlerts || canManageAlerts;

  const [alerts, setAlerts] = useState<SecurityAlertItem[]>([]);
  const [alertsTotal, setAlertsTotal] = useState(0);
  const [alertsPage, setAlertsPage] = useState(1);
  const [alertsSeverity, setAlertsSeverity] = useState('ALL');
  const [alertsStatus, setAlertsStatus] = useState('ALL');
  const [alertsSearch, setAlertsSearch] = useState('');

  const [dlpAlerts, setDlpAlerts] = useState<SecurityAlertItem[]>([]);
  const [dlpAlertsTotal, setDlpAlertsTotal] = useState(0);
  const [dlpStatus, setDlpStatus] = useState<NetworkDlpStatus>(DEFAULT_DLP_STATUS);

  const [incidents, setIncidents] = useState<IncidentItem[]>([]);
  const [incidentsTotal, setIncidentsTotal] = useState(0);
  const [incidentsPage, setIncidentsPage] = useState(1);
  const [incidentsStatus, setIncidentsStatus] = useState('ALL');
  const [incidentsSearch, setIncidentsSearch] = useState('');

  const [detectionRules, setDetectionRules] = useState<DetectionRuleItem[]>([]);
  const [isRunningDetection, setIsRunningDetection] = useState(false);

  const [documentSessions, setDocumentSessions] = useState<DocumentSessionItem[]>([]);
  const [sessionsTotal, setSessionsTotal] = useState(0);
  const [activeSessionsCount, setActiveSessionsCount] = useState(0);
  const [sessionsPage, setSessionsPage] = useState(1);
  const [sessionsStatus, setSessionsStatus] = useState<'ACTIVE' | 'ALL' | 'ENDED' | 'TERMINATED'>(
    'ACTIVE',
  );
  const [sessionsSearch, setSessionsSearch] = useState('');

  const [terminatingSessionId, setTerminatingSessionId] = useState<string | null>(null);
  const [pendingTerminateSessionId, setPendingTerminateSessionId] = useState<string | null>(null);

  const [isLoading, setIsLoading] = useState(true);
  const [message, setMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [tabErrors, setTabErrors] = useState<SecurityTabErrors>(EMPTY_TAB_ERRORS);

  const buildAlertsQuery = useCallback(() => {
    const params = new URLSearchParams({ page: String(alertsPage), pageSize: '20' });
    if (alertsSeverity !== 'ALL') params.set('severity', alertsSeverity);
    if (alertsStatus !== 'ALL') params.set('status', alertsStatus);
    if (alertsSearch.trim()) params.set('search', alertsSearch.trim());
    return `/security-alerts?${params.toString()}`;
  }, [alertsPage, alertsSeverity, alertsStatus, alertsSearch]);

  const buildIncidentsQuery = useCallback(() => {
    const params = new URLSearchParams({ page: String(incidentsPage), pageSize: '20' });
    if (incidentsStatus !== 'ALL') params.set('status', incidentsStatus);
    if (incidentsSearch.trim()) params.set('search', incidentsSearch.trim());
    return `/incidents?${params.toString()}`;
  }, [incidentsPage, incidentsStatus, incidentsSearch]);

  const buildSessionsQuery = useCallback(() => {
    const params = new URLSearchParams({
      status: sessionsStatus,
      page: String(sessionsPage),
      limit: '20',
    });
    if (sessionsSearch.trim()) params.set('search', sessionsSearch.trim());
    return `/access-sessions?${params.toString()}`;
  }, [sessionsStatus, sessionsPage, sessionsSearch]);

  const refreshData = useCallback(
    async (options?: { silent?: boolean; signal?: AbortSignal }) => {
      if (!options?.silent) setIsLoading(true);
      setErrorMessage(null);
      const reqOpts = options?.signal ? { signal: options.signal } : undefined;

      const [alertsRes, incRes, rulesRes, sessionsRes, dlpAlertsRes, dlpStatusRes] =
        await Promise.allSettled([
          canViewAlerts
            ? apiClient<SecurityPaginatedResponse<AlertApiDto>>(buildAlertsQuery(), reqOpts)
            : Promise.resolve(null),
          canViewIncidents
            ? apiClient<SecurityPaginatedResponse<IncidentApiDto>>(buildIncidentsQuery(), reqOpts)
            : Promise.resolve(null),
          canViewRules
            ? apiClient<DetectionRuleItem[] | { data?: DetectionRuleItem[] }>(
                '/security-detection/rules',
                reqOpts,
              )
            : Promise.resolve(null),
          canTerminateSession
            ? apiClient<SecurityPaginatedResponse<DocumentSessionItem>>(
                buildSessionsQuery(),
                reqOpts,
              )
            : Promise.resolve(null),
          canViewAlerts
            ? apiClient<SecurityPaginatedResponse<AlertApiDto>>(
                '/security-alerts?alertType=NETWORK_DLP_VIOLATION&pageSize=20',
                reqOpts,
              )
            : Promise.resolve(null),
          canViewAlerts
            ? apiClient<NetworkDlpStatus>('/security-operations/dlp-status', reqOpts)
            : Promise.resolve(null),
        ]);

      if (options?.signal?.aborted) return;

      const nextErrors: SecurityTabErrors = { ...EMPTY_TAB_ERRORS };

      if (alertsRes.status === 'fulfilled' && alertsRes.value) {
        const mapped = (alertsRes.value.data || []).map(mapAlertDto);
        setAlerts(mapped);
        setAlertsTotal(alertsRes.value.meta?.total ?? alertsRes.value.total ?? mapped.length);
      } else if (alertsRes.status === 'rejected') {
        nextErrors.alerts = formatTabError(
          alertsRes.reason,
          'Không thể tải danh sách cảnh báo an ninh.',
        );
      }

      if (incRes.status === 'fulfilled' && incRes.value) {
        const mapped = (incRes.value.data || []).map(mapIncidentDto);
        setIncidents(mapped);
        setIncidentsTotal(incRes.value.meta?.total ?? incRes.value.total ?? mapped.length);
      } else if (incRes.status === 'rejected') {
        nextErrors.incidents = formatTabError(
          incRes.reason,
          'Không thể tải danh sách hồ sơ sự cố an ninh.',
        );
      }

      if (rulesRes.status === 'fulfilled' && rulesRes.value) {
        const list = Array.isArray(rulesRes.value)
          ? rulesRes.value
          : Array.isArray(rulesRes.value.data)
            ? rulesRes.value.data
            : [];
        setDetectionRules(list);
      } else if (rulesRes.status === 'rejected') {
        nextErrors.rules = formatTabError(
          rulesRes.reason,
          'Không thể tải cấu hình quy tắc phát hiện bất thường.',
        );
      }

      if (sessionsRes.status === 'fulfilled' && sessionsRes.value) {
        const rows = sessionsRes.value.data || [];
        setDocumentSessions(rows);
        setSessionsTotal(sessionsRes.value.total ?? sessionsRes.value.meta?.total ?? rows.length);
        setActiveSessionsCount(
          sessionsRes.value.activeCount ?? rows.filter((s) => s.status === 'ACTIVE').length,
        );
      } else if (sessionsRes.status === 'rejected') {
        nextErrors.sessions = formatTabError(
          sessionsRes.reason,
          'Không thể tải danh sách phiên đọc tài liệu.',
        );
      }

      if (dlpAlertsRes.status === 'fulfilled' && dlpAlertsRes.value) {
        const mappedDlp = (dlpAlertsRes.value.data || []).map(mapAlertDto);
        setDlpAlerts(mappedDlp);
        setDlpAlertsTotal(
          dlpAlertsRes.value.meta?.total ?? dlpAlertsRes.value.total ?? mappedDlp.length,
        );
      } else if (dlpAlertsRes.status === 'rejected') {
        nextErrors.dlp = formatTabError(
          dlpAlertsRes.reason,
          'Không thể tải danh sách cảnh báo DLP mạng.',
        );
      }

      if (dlpStatusRes.status === 'fulfilled' && dlpStatusRes.value) {
        setDlpStatus(dlpStatusRes.value);
      } else if (dlpStatusRes.status === 'rejected') {
        setDlpStatus({ ...DEFAULT_DLP_STATUS, checkedAt: new Date().toISOString() });
        nextErrors.dlp =
          nextErrors.dlp ??
          formatTabError(dlpStatusRes.reason, 'Không thể kiểm tra trạng thái cổng DLP mạng.');
      }

      setTabErrors(nextErrors);
      if (!options?.silent) setIsLoading(false);
    },
    [
      canViewAlerts,
      canViewIncidents,
      canViewRules,
      canTerminateSession,
      buildAlertsQuery,
      buildIncidentsQuery,
      buildSessionsQuery,
    ],
  );

  useEffect(() => {
    let ignore = false;
    const controller = new AbortController();
    void Promise.resolve().then(() => {
      if (!ignore) void refreshData({ signal: controller.signal });
    });
    return () => {
      ignore = true;
      controller.abort();
    };
  }, [refreshData]);

  useEffect(() => {
    let timer: ReturnType<typeof setTimeout> | null = null;
    const scheduleSilentRefresh = () => {
      if (timer) clearTimeout(timer);
      timer = setTimeout(() => {
        timer = null;
        void refreshData({ silent: true });
      }, 200);
    };

    const unsubs = [
      subscribeRealtimeEvent('SECURITY_ALERT_UPDATED', scheduleSilentRefresh),
      subscribeRealtimeEvent('INCIDENT_REPORT_UPDATED', scheduleSilentRefresh),
      subscribeRealtimeEvent('DETECTION_RULE_UPDATED', scheduleSilentRefresh),
      subscribeRealtimeEvent('ACCESS_SESSION_UPDATED', scheduleSilentRefresh),
    ];

    return () => {
      for (const unsub of unsubs) unsub();
      if (timer) clearTimeout(timer);
    };
  }, [refreshData]);

  async function runDetection(ruleCodes?: string[]) {
    setErrorMessage(null);
    setIsRunningDetection(true);
    try {
      // CONFLICT-RESOLVED: Không gửi cứng windowMinutes: 60 ghi đè cửa sổ cấu hình riêng của từng quy tắc (#17, N08).
      const payload = ruleCodes && ruleCodes.length > 0 ? { ruleCodes } : {};
      const results = await apiClient<Array<{ isNewAlert?: boolean }>>('/security-detection/run', {
        method: 'POST',
        body: JSON.stringify(payload),
      });
      const createdCount = Array.isArray(results) ? results.filter((r) => r.isNewAlert).length : 0;
      setMessage(
        createdCount > 0
          ? `Đã hoàn tất quét bất thường theo cấu hình từng quy tắc · Phát hiện ${createdCount} cảnh báo mới.`
          : 'Đã hoàn tất quét bất thường theo cấu hình từng quy tắc · Không ghi nhận cảnh báo mới.',
      );
      await refreshData({ silent: true });
    } catch (err) {
      setErrorMessage(
        err instanceof ApiError ? err.message : 'Không thể thực hiện quét phát hiện bất thường.',
      );
    } finally {
      setIsRunningDetection(false);
    }
  }

  function applyOptimisticAlertUpdate(alertId: string, patch: OptimisticAlertPatch): () => void {
    const previousAlerts = alerts;
    const applyPatch = (list: SecurityAlertItem[]) =>
      list.map((item) => {
        if (item.id !== alertId) return item;
        return {
          ...item,
          status: patch.status ?? item.status,
          resolutionNote:
            patch.resolutionNote !== undefined ? patch.resolutionNote : item.resolutionNote,
          notes: patch.addedNote ? [...(item.notes ?? []), patch.addedNote] : item.notes,
        };
      });
    setAlerts(applyPatch);
    setDlpAlerts(applyPatch);
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
      setMessage(
        sessionsStatus === 'ACTIVE'
          ? 'Đã ngắt phiên đọc tài liệu thành công. Chuyển bộ lọc sang "Đã ngắt" hoặc "Tất cả" để xem lịch sử.'
          : 'Đã ngắt phiên đọc tài liệu khẩn cấp thành công.',
      );
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
    alertsTotal,
    alertsPage,
    setAlertsPage,
    alertsSeverity,
    setAlertsSeverity: (v: string) => {
      setAlertsSeverity(v);
      setAlertsPage(1);
    },
    alertsStatus,
    setAlertsStatus: (v: string) => {
      setAlertsStatus(v);
      setAlertsPage(1);
    },
    alertsSearch,
    setAlertsSearch: (v: string) => {
      setAlertsSearch(v);
      setAlertsPage(1);
    },
    dlpAlerts,
    dlpAlertsTotal,
    dlpStatus,
    incidents,
    incidentsTotal,
    incidentsPage,
    setIncidentsPage,
    incidentsStatus,
    setIncidentsStatus: (v: string) => {
      setIncidentsStatus(v);
      setIncidentsPage(1);
    },
    incidentsSearch,
    setIncidentsSearch: (v: string) => {
      setIncidentsSearch(v);
      setIncidentsPage(1);
    },
    detectionRules,
    isRunningDetection,
    documentSessions,
    sessionsTotal,
    activeSessionsCount,
    sessionsPage,
    setSessionsPage,
    sessionsStatus,
    setSessionsStatus: (v: 'ACTIVE' | 'ALL' | 'ENDED' | 'TERMINATED') => {
      setSessionsStatus(v);
      setSessionsPage(1);
    },
    sessionsSearch,
    setSessionsSearch: (v: string) => {
      setSessionsSearch(v);
      setSessionsPage(1);
    },
    terminatingSessionId,
    pendingTerminateSessionId,
    setPendingTerminateSessionId,
    isLoading,
    message,
    setMessage,
    errorMessage,
    setErrorMessage,
    tabErrors,
    refreshData,
    runDetection,
    applyOptimisticAlertUpdate,
    terminateSession,
  };
}
