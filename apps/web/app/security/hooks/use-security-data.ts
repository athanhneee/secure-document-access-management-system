'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { apiClient, ApiError } from '@/lib/api-client';
import { useAuth } from '@/lib/auth-context';
import { applyOptimisticStatusById, removeOptimisticById } from '@/lib/optimistic-state';
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
import {
  abortAllSectionControllers,
  DEFAULT_DLP_STATUS,
  EMPTY_TAB_ERRORS,
  formatSecuritySectionError,
  isRequestAborted,
  nextSectionAbortController,
  type SecuritySectionKey,
} from './security-fetch-helpers';

export interface OptimisticAlertPatch {
  status?: SecurityAlertItem['status'] | undefined;
  resolutionNote?: string | null | undefined;
  addedNote?: AlertNoteItem | undefined;
}

/**
 * Thuật toán: Đồng Bộ 5 Phân Khu SOC Độc Lập Có Giảm Chấn 300ms, `AbortController` Riêng & Kênh SSE Ổn Định (`useSecurityData`)
 * Mục đích:
 *   - Tách thành 5 hàm nạp độc lập (`fetchAlerts`, `fetchIncidents`, `fetchSessions`, `fetchDetectionRules`, `fetchDlpOverview`) để gõ tìm kiếm ở 1 phân khu không bao giờ kích hoạt lại thăm dò DLP 1,5s hay 4 API còn lại.
 *   - Giữ ổn định kết nối SSE qua `useRef` để không ngắt/nối lại SSE theo từng phím gõ và loại trừ lẫn nhau giữa `message` xanh với `errorMessage` đỏ.
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
  const [debouncedAlertsSearch, setDebouncedAlertsSearch] = useState('');

  const [dlpAlerts, setDlpAlerts] = useState<SecurityAlertItem[]>([]);
  const [dlpAlertsTotal, setDlpAlertsTotal] = useState(0);
  const [dlpPage, setDlpPage] = useState(1);
  const [dlpStatus, setDlpStatus] = useState<NetworkDlpStatus>(DEFAULT_DLP_STATUS);

  const [incidents, setIncidents] = useState<IncidentItem[]>([]);
  const [incidentsTotal, setIncidentsTotal] = useState(0);
  const [incidentsPage, setIncidentsPage] = useState(1);
  const [incidentsStatus, setIncidentsStatus] = useState('ALL');
  const [incidentsSearch, setIncidentsSearch] = useState('');
  const [debouncedIncidentsSearch, setDebouncedIncidentsSearch] = useState('');

  const [detectionRules, setDetectionRules] = useState<DetectionRuleItem[]>([]);
  const [isRunningDetection, setIsRunningDetection] = useState(false);

  const [documentSessions, setDocumentSessions] = useState<DocumentSessionItem[]>([]);
  const [sessionsAllTotal, setSessionsAllTotal] = useState(0);
  const [sessionsFilteredTotal, setSessionsFilteredTotal] = useState(0);
  const [activeSessionsCount, setActiveSessionsCount] = useState(0);
  const [sessionsPage, setSessionsPage] = useState(1);
  const [sessionsStatus, setSessionsStatus] = useState<'ACTIVE' | 'ALL' | 'ENDED' | 'TERMINATED'>(
    'ACTIVE',
  );
  const [sessionsSearch, setSessionsSearch] = useState('');
  const [debouncedSessionsSearch, setDebouncedSessionsSearch] = useState('');

  useEffect(() => {
    if (alertsSearch === debouncedAlertsSearch) return;
    const timer = setTimeout(() => {
      setDebouncedAlertsSearch(alertsSearch);
      setAlertsPage(1);
    }, 300);
    return () => clearTimeout(timer);
  }, [alertsSearch, debouncedAlertsSearch]);

  useEffect(() => {
    if (incidentsSearch === debouncedIncidentsSearch) return;
    const timer = setTimeout(() => {
      setDebouncedIncidentsSearch(incidentsSearch);
      setIncidentsPage(1);
    }, 300);
    return () => clearTimeout(timer);
  }, [incidentsSearch, debouncedIncidentsSearch]);

  useEffect(() => {
    if (sessionsSearch === debouncedSessionsSearch) return;
    const timer = setTimeout(() => {
      setDebouncedSessionsSearch(sessionsSearch);
      setSessionsPage(1);
    }, 300);
    return () => clearTimeout(timer);
  }, [sessionsSearch, debouncedSessionsSearch]);

  const [terminatingSessionId, setTerminatingSessionId] = useState<string | null>(null);
  const [pendingTerminateSessionId, setPendingTerminateSessionId] = useState<string | null>(null);

  const [isLoading, setIsLoading] = useState(true);
  const [message, setMessageState] = useState<string | null>(null);
  const [errorMessage, setErrorMessageState] = useState<string | null>(null);
  const [dialogError, setDialogError] = useState<string | null>(null);
  const [tabErrors, setTabErrors] = useState<SecurityTabErrors>(EMPTY_TAB_ERRORS);

  const sectionAbortRef = useRef<Partial<Record<SecuritySectionKey, AbortController>>>({});
  const hasHydratedRef = useRef(false);

  const setMessage = useCallback((nextMsg: string | null) => {
    setMessageState(nextMsg);
    if (nextMsg) setErrorMessageState(null);
  }, []);

  const setErrorMessage = useCallback((nextErr: string | null) => {
    setErrorMessageState(nextErr);
    if (nextErr) setMessageState(null);
  }, []);

  const fetchAlerts = useCallback(async () => {
    if (!canViewAlerts) return;
    const ctrl = nextSectionAbortController(sectionAbortRef, 'alerts');
    const params = new URLSearchParams({ page: String(alertsPage), pageSize: '20' });
    if (alertsSeverity !== 'ALL') params.set('severity', alertsSeverity);
    if (alertsStatus !== 'ALL') params.set('status', alertsStatus);
    if (debouncedAlertsSearch.trim()) params.set('search', debouncedAlertsSearch.trim());

    try {
      const res = await apiClient<SecurityPaginatedResponse<AlertApiDto>>(
        `/security-alerts?${params.toString()}`,
        { signal: ctrl.signal },
      );
      if (ctrl.signal.aborted) return;
      const mapped = (res.data || []).map(mapAlertDto);
      const total = res.meta?.total ?? res.total ?? mapped.length;
      const maxPage = Math.max(1, Math.ceil(total / 20));
      if (alertsPage > maxPage) {
        setAlertsPage(maxPage);
        return;
      }
      setAlerts(mapped);
      setAlertsTotal(total);
      setTabErrors((prev) => (prev.alerts === null ? prev : { ...prev, alerts: null }));
    } catch (err) {
      if (isRequestAborted(err, ctrl.signal)) return;
      setTabErrors((prev) => ({
        ...prev,
        alerts: formatSecuritySectionError(err, 'Không thể tải danh sách cảnh báo an ninh.'),
      }));
    }
  }, [canViewAlerts, alertsPage, alertsSeverity, alertsStatus, debouncedAlertsSearch]);

  const fetchIncidents = useCallback(async () => {
    if (!canViewIncidents) return;
    const ctrl = nextSectionAbortController(sectionAbortRef, 'incidents');
    const params = new URLSearchParams({ page: String(incidentsPage), pageSize: '20' });
    if (incidentsStatus !== 'ALL') params.set('status', incidentsStatus);
    if (debouncedIncidentsSearch.trim()) params.set('search', debouncedIncidentsSearch.trim());

    try {
      const res = await apiClient<SecurityPaginatedResponse<IncidentApiDto>>(
        `/incidents?${params.toString()}`,
        { signal: ctrl.signal },
      );
      if (ctrl.signal.aborted) return;
      const mapped = (res.data || []).map(mapIncidentDto);
      const total = res.meta?.total ?? res.total ?? mapped.length;
      const maxPage = Math.max(1, Math.ceil(total / 20));
      if (incidentsPage > maxPage) {
        setIncidentsPage(maxPage);
        return;
      }
      setIncidents(mapped);
      setIncidentsTotal(total);
      setTabErrors((prev) => (prev.incidents === null ? prev : { ...prev, incidents: null }));
    } catch (err) {
      if (isRequestAborted(err, ctrl.signal)) return;
      setTabErrors((prev) => ({
        ...prev,
        incidents: formatSecuritySectionError(err, 'Không thể tải danh sách hồ sơ sự cố an ninh.'),
      }));
    }
  }, [canViewIncidents, incidentsPage, incidentsStatus, debouncedIncidentsSearch]);

  const fetchSessions = useCallback(async () => {
    if (!canTerminateSession) return;
    const ctrl = nextSectionAbortController(sectionAbortRef, 'sessions');
    const params = new URLSearchParams({
      status: sessionsStatus,
      page: String(sessionsPage),
      limit: '20',
    });
    if (debouncedSessionsSearch.trim()) params.set('search', debouncedSessionsSearch.trim());

    try {
      const res = await apiClient<SecurityPaginatedResponse<DocumentSessionItem>>(
        `/access-sessions?${params.toString()}`,
        { signal: ctrl.signal },
      );
      if (ctrl.signal.aborted) return;
      const rows = res.data || [];
      const filteredTotal = res.meta?.total ?? res.total ?? rows.length;
      const allTotal = res.total ?? filteredTotal;
      const maxPage = Math.max(1, Math.ceil(filteredTotal / 20));
      if (sessionsPage > maxPage) {
        setSessionsPage(maxPage);
        return;
      }
      setDocumentSessions(rows);
      setSessionsAllTotal(allTotal);
      setSessionsFilteredTotal(filteredTotal);
      setActiveSessionsCount(res.activeCount ?? rows.filter((s) => s.status === 'ACTIVE').length);
      setTabErrors((prev) => (prev.sessions === null ? prev : { ...prev, sessions: null }));
    } catch (err) {
      if (isRequestAborted(err, ctrl.signal)) return;
      setTabErrors((prev) => ({
        ...prev,
        sessions: formatSecuritySectionError(err, 'Không thể tải danh sách phiên đọc tài liệu.'),
      }));
    }
  }, [canTerminateSession, sessionsStatus, sessionsPage, debouncedSessionsSearch]);

  const fetchDetectionRules = useCallback(async () => {
    if (!canViewRules) return;
    const ctrl = nextSectionAbortController(sectionAbortRef, 'rules');
    try {
      const res = await apiClient<DetectionRuleItem[] | { data?: DetectionRuleItem[] }>(
        '/security-detection/rules',
        { signal: ctrl.signal },
      );
      if (ctrl.signal.aborted) return;
      const list = Array.isArray(res) ? res : Array.isArray(res.data) ? res.data : [];
      setDetectionRules(list);
      setTabErrors((prev) => (prev.rules === null ? prev : { ...prev, rules: null }));
    } catch (err) {
      if (isRequestAborted(err, ctrl.signal)) return;
      setTabErrors((prev) => ({
        ...prev,
        rules: formatSecuritySectionError(
          err,
          'Không thể tải cấu hình quy tắc phát hiện bất thường.',
        ),
      }));
    }
  }, [canViewRules]);

  const didInitialDlpProbeRef = useRef(false);

  const fetchDlpOverview = useCallback(
    async (opts?: { includeProbe?: boolean }) => {
      if (!canViewAlerts) return;
      const includeProbe = opts?.includeProbe ?? true;
      const ctrl = nextSectionAbortController(sectionAbortRef, 'dlp');
      const [dlpAlertsRes, dlpStatusRes] = await Promise.allSettled([
        apiClient<SecurityPaginatedResponse<AlertApiDto>>(
          `/security-alerts?alertType=NETWORK_DLP_VIOLATION&page=${dlpPage}&pageSize=20`,
          { signal: ctrl.signal },
        ),
        includeProbe
          ? apiClient<NetworkDlpStatus>('/security-operations/dlp-status', { signal: ctrl.signal })
          : Promise.resolve(null),
      ]);
      if (ctrl.signal.aborted) return;

      let dlpErr: string | null = null;
      if (dlpAlertsRes.status === 'fulfilled' && dlpAlertsRes.value) {
        const mappedDlp = (dlpAlertsRes.value.data || []).map(mapAlertDto);
        const totalDlp =
          dlpAlertsRes.value.meta?.total ?? dlpAlertsRes.value.total ?? mappedDlp.length;
        const maxDlpPage = Math.max(1, Math.ceil(totalDlp / 20));
        if (dlpPage > maxDlpPage) {
          setDlpPage(maxDlpPage);
          return;
        }
        setDlpAlerts(mappedDlp);
        setDlpAlertsTotal(totalDlp);
      } else if (
        dlpAlertsRes.status === 'rejected' &&
        !isRequestAborted(dlpAlertsRes.reason, ctrl.signal)
      ) {
        dlpErr = formatSecuritySectionError(
          dlpAlertsRes.reason,
          'Không thể tải danh sách cảnh báo DLP mạng.',
        );
      }

      if (includeProbe) {
        if (dlpStatusRes.status === 'fulfilled' && dlpStatusRes.value) {
          didInitialDlpProbeRef.current = true;
          setDlpStatus(dlpStatusRes.value);
        } else if (
          dlpStatusRes.status === 'rejected' &&
          !isRequestAborted(dlpStatusRes.reason, ctrl.signal)
        ) {
          didInitialDlpProbeRef.current = true;
          setDlpStatus({ ...DEFAULT_DLP_STATUS, checkedAt: new Date().toISOString() });
          dlpErr =
            dlpErr ??
            formatSecuritySectionError(
              dlpStatusRes.reason,
              'Không thể kiểm tra trạng thái cổng DLP mạng.',
            );
        }
      }
      setTabErrors((prev) => (prev.dlp === dlpErr ? prev : { ...prev, dlp: dlpErr }));
    },
    [canViewAlerts, dlpPage],
  );

  const refreshData = useCallback(
    async (options?: { silent?: boolean }) => {
      if (!options?.silent) setIsLoading(true);
      setErrorMessageState(null);
      await Promise.allSettled([
        fetchAlerts(),
        fetchIncidents(),
        fetchDetectionRules(),
        fetchSessions(),
        fetchDlpOverview({ includeProbe: true }),
      ]);
      hasHydratedRef.current = true;
      if (!options?.silent) setIsLoading(false);
    },
    [fetchAlerts, fetchIncidents, fetchDetectionRules, fetchSessions, fetchDlpOverview],
  );

  useEffect(() => {
    void fetchAlerts().finally(() => {
      if (!hasHydratedRef.current) {
        hasHydratedRef.current = true;
        setIsLoading(false);
      }
    });
  }, [fetchAlerts]);

  useEffect(() => {
    void fetchIncidents().finally(() => {
      if (!hasHydratedRef.current) {
        hasHydratedRef.current = true;
        setIsLoading(false);
      }
    });
  }, [fetchIncidents]);

  useEffect(() => {
    void fetchSessions().finally(() => {
      if (!hasHydratedRef.current) {
        hasHydratedRef.current = true;
        setIsLoading(false);
      }
    });
  }, [fetchSessions]);

  useEffect(() => {
    void fetchDetectionRules();
  }, [fetchDetectionRules]);

  useEffect(() => {
    const includeProbe = !didInitialDlpProbeRef.current;
    void fetchDlpOverview({ includeProbe });
  }, [fetchDlpOverview]);

  useEffect(() => () => abortAllSectionControllers(sectionAbortRef), []);

  const sseHandlersRef = useRef({
    fetchAlerts,
    fetchIncidents,
    fetchDetectionRules,
    fetchSessions,
    fetchDlpOverview,
  });
  useEffect(() => {
    sseHandlersRef.current = {
      fetchAlerts,
      fetchIncidents,
      fetchDetectionRules,
      fetchSessions,
      fetchDlpOverview,
    };
  }, [fetchAlerts, fetchIncidents, fetchDetectionRules, fetchSessions, fetchDlpOverview]);

  useEffect(() => {
    const timers: Partial<Record<string, ReturnType<typeof setTimeout>>> = {};
    const schedule = (key: string, fn: () => void) => {
      if (timers[key]) clearTimeout(timers[key]);
      timers[key] = setTimeout(() => {
        delete timers[key];
        fn();
      }, 200);
    };

    const unsubs = [
      subscribeRealtimeEvent('SECURITY_ALERT_UPDATED', () =>
        schedule('alerts', () => {
          void sseHandlersRef.current.fetchAlerts();
          void sseHandlersRef.current.fetchDlpOverview({ includeProbe: false });
        }),
      ),
      subscribeRealtimeEvent('INCIDENT_REPORT_UPDATED', () =>
        schedule('incidents', () => void sseHandlersRef.current.fetchIncidents()),
      ),
      subscribeRealtimeEvent('DETECTION_RULE_UPDATED', () =>
        schedule('rules', () => void sseHandlersRef.current.fetchDetectionRules()),
      ),
      subscribeRealtimeEvent('ACCESS_SESSION_UPDATED', () =>
        schedule('sessions', () => void sseHandlersRef.current.fetchSessions()),
      ),
    ];

    return () => {
      for (const unsub of unsubs) unsub();
      for (const timer of Object.values(timers)) {
        if (timer) clearTimeout(timer);
      }
    };
  }, []);

  async function runDetection(ruleCodes?: string[]) {
    setErrorMessage(null);
    setIsRunningDetection(true);
    try {
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
      await Promise.allSettled([fetchAlerts(), fetchDlpOverview({ includeProbe: false })]);
    } catch (err) {
      setErrorMessage(
        err instanceof ApiError ? err.message : 'Không thể thực hiện quét phát hiện bất thường.',
      );
    } finally {
      setIsRunningDetection(false);
    }
  }

  function applyOptimisticAlertUpdate(alertId: string, patch: OptimisticAlertPatch): () => void {
    const prevAlertItem = alerts.find((item) => item.id === alertId);
    const prevDlpItem = dlpAlerts.find((item) => item.id === alertId);
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
      if (prevAlertItem) {
        setAlerts((list) => list.map((item) => (item.id === alertId ? prevAlertItem : item)));
      }
      if (prevDlpItem) {
        setDlpAlerts((list) => list.map((item) => (item.id === alertId ? prevDlpItem : item)));
      }
    };
  }

  async function terminateSession(reason: string, explicitId?: string): Promise<boolean> {
    const sessionId = explicitId ?? pendingTerminateSessionId;
    if (!sessionId) return false;

    setTerminatingSessionId(sessionId);
    setDialogError(null);

    try {
      await apiClient(`/access-sessions/${sessionId}/terminate`, {
        method: 'POST',
        body: JSON.stringify({ reason }),
      });
      setActiveSessionsCount((prev) => Math.max(0, prev - 1));
      if (sessionsStatus === 'ACTIVE') {
        const remainingCount = documentSessions.filter((item) => item.id !== sessionId).length;
        setDocumentSessions((prev) => removeOptimisticById(prev, sessionId));
        setSessionsFilteredTotal((prev) => Math.max(0, prev - 1));
        if (sessionsPage > 1 && remainingCount === 0) {
          setSessionsPage(sessionsPage - 1);
        }
      } else {
        setDocumentSessions((prev) =>
          applyOptimisticStatusById(prev, sessionId, 'TERMINATED').map((item) =>
            item.id === sessionId ? { ...item, terminatedReason: reason } : item,
          ),
        );
      }
      setPendingTerminateSessionId(null);
      setMessage(
        sessionsStatus === 'ACTIVE'
          ? 'Đã ngắt phiên đọc tài liệu thành công. Chuyển bộ lọc sang "Đã ngắt cưỡng bức" hoặc "Tất cả" để xem lịch sử.'
          : 'Đã ngắt phiên đọc tài liệu khẩn cấp thành công.',
      );
      return true;
    } catch (err) {
      const errMsg =
        err instanceof ApiError
          ? err.message || 'Không thể ngắt phiên truy cập.'
          : 'Không thể ngắt phiên truy cập.';
      if (pendingTerminateSessionId) {
        setDialogError(errMsg);
      } else {
        setErrorMessage(errMsg);
      }
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
    setAlertsSearch,
    dlpAlerts,
    dlpAlertsTotal,
    dlpPage,
    setDlpPage,
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
    setIncidentsSearch,
    detectionRules,
    isRunningDetection,
    documentSessions,
    sessionsTotal: sessionsAllTotal,
    sessionsAllTotal,
    sessionsFilteredTotal,
    activeSessionsCount,
    sessionsPage,
    setSessionsPage,
    sessionsStatus,
    setSessionsStatus: (v: 'ACTIVE' | 'ALL' | 'ENDED' | 'TERMINATED') => {
      setSessionsStatus(v);
      setSessionsPage(1);
    },
    sessionsSearch,
    setSessionsSearch,
    terminatingSessionId,
    pendingTerminateSessionId,
    setPendingTerminateSessionId,
    isLoading,
    message,
    setMessage,
    errorMessage,
    setErrorMessage,
    dialogError,
    setDialogError,
    tabErrors,
    fetchAlerts,
    fetchIncidents,
    fetchSessions,
    fetchDetectionRules,
    fetchDlpOverview,
    refreshData,
    runDetection,
    applyOptimisticAlertUpdate,
    terminateSession,
  };
}
