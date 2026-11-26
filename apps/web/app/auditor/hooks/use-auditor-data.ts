'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { apiClient, apiDownload, ApiError } from '@/lib/api-client';
import { useAuth } from '@/lib/auth-context';
import {
  aggregatePartitionVerifications,
  buildAuditLogsQueryParams,
  extractAuditorPagination,
  isInvalidDateRange,
  mergeExportJobHistory,
  normalizeAuditLogDtos,
  normalizeExportJob,
  triggerEphemeralBlobDownload,
} from '../helpers';
import type {
  AuditAnchorItem,
  AuditLogItem,
  AuditLogsPaginatedResponse,
  AuditorErrorSource,
  AuditTrailFilters,
  ChainVerificationReport,
  ExportFormat,
  ExportJobItem,
  VerifyHashChainResponse,
} from '../types';
import { isAbortError, useExportJobsPolling } from './use-export-polling';

const DEFAULT_AUDIT_PAGE_SIZE = 20;

/**
 * Thuật toán: Quản Lý Trạng Thái Kiểm Toán Phân Quyền Nghiêm Ngặt, Lọc Đa Chiều & Khôi Phục Lỗi Theo Ngữ Cảnh (`useAuditorData`)
 * Mục đích:
 *   - Chỉ gọi các API mà tài khoản thực sự được cấp quyền (`AUDIT_LOG:VIEW`, `AUDIT_LOG:EXPORT` / `SYSTEM_REPORT:EXPORT`) để tuyệt đối không sinh lỗi 403 oan.
 *   - Bảo vệ trạng thái bằng `AbortController`, `Promise.allSettled`, kiểm định khoảng ngày `fromDate <= toDate`, xóa sạch thông báo cũ tránh hiện song song banner xanh/đỏ và theo dõi nguồn lỗi cho nút `Thử lại`.
 */
export function useAuditorData() {
  const { hasPermission, hasGlobalPermission } = useAuth();
  const canViewAuditLogs = hasPermission('AUDIT_LOG:VIEW');
  const canExportAuditLogs = hasPermission('AUDIT_LOG:EXPORT');
  const canExportSystemReport = hasGlobalPermission('SYSTEM_REPORT:EXPORT');
  const canExportReports = canExportAuditLogs || canExportSystemReport;

  const [logs, setLogs] = useState<AuditLogItem[]>([]);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSizeState] = useState(DEFAULT_AUDIT_PAGE_SIZE);
  const [totalPages, setTotalPages] = useState(1);
  const [totalLogs, setTotalLogs] = useState(0);

  const [anchors, setAnchors] = useState<AuditAnchorItem[]>([]);
  const [exportJobs, setExportJobs] = useState<ExportJobItem[]>([]);
  const [verificationReport, setVerificationReport] = useState<ChainVerificationReport | null>(
    null,
  );
  const [verifyPartition, setVerifyPartition] = useState<string>('ALL');

  const [isLoading, setIsLoading] = useState(true);
  const [downloadingJobId, setDownloadingJobId] = useState<string | null>(null);
  const [message, setMessageState] = useState<string | null>(null);
  const [errorMessage, setErrorMessageState] = useState<string | null>(null);
  const [dialogError, setDialogError] = useState<string | null>(null);
  const [lastErrorSource, setLastErrorSource] = useState<AuditorErrorSource>('general');

  const [outcomeFilter, setOutcomeFilterState] = useState<string>('ALL');
  const [actionFilter, setActionFilterState] = useState('');
  const [debouncedActionFilter, setDebouncedActionFilter] = useState('');
  const [partitionFilter, setPartitionFilterState] = useState<string>('ALL');
  const [actorFilter, setActorFilterState] = useState('');
  const [debouncedActorFilter, setDebouncedActorFilter] = useState('');
  const [fromDate, setFromDateState] = useState('');
  const [toDate, setToDateState] = useState('');
  const [sortOrder, setSortOrderState] = useState<'desc' | 'asc'>('desc');
  const [isVerifyingChain, setIsVerifyingChain] = useState(false);

  const prevDebouncedTextRef = useRef('|');
  const refreshAbortRef = useRef<AbortController | null>(null);
  const lastFailedDownloadJobRef = useRef<ExportJobItem | null>(null);
  const activeTabContextRef = useRef<string>('logs');
  const retryHandlersRef = useRef<Partial<Record<AuditorErrorSource, () => void | Promise<void>>>>(
    {},
  );

  const setMessage = useCallback((nextMsg: string | null) => {
    setMessageState(nextMsg);
    if (nextMsg) {
      setErrorMessageState(null);
    }
  }, []);

  const reportError = useCallback((msg: string | null, source: AuditorErrorSource = 'general') => {
    if (msg) {
      setMessageState(null);
      setLastErrorSource(source);
    }
    setErrorMessageState(msg);
  }, []);

  const registerRetryHandler = useCallback(
    (source: AuditorErrorSource, handler: (() => void | Promise<void>) | null) => {
      if (handler) {
        retryHandlersRef.current[source] = handler;
      } else {
        delete retryHandlersRef.current[source];
      }
    },
    [],
  );

  const setActiveTabContext = useCallback((tab: string) => {
    activeTabContextRef.current = tab;
  }, []);

  const dateRangeError = isInvalidDateRange(fromDate, toDate)
    ? 'Ngày bắt đầu không được lớn hơn ngày kết thúc.'
    : null;

  useEffect(() => {
    const nextSig = `${actionFilter}|${actorFilter}`;
    if (prevDebouncedTextRef.current === nextSig) return;
    const timer = setTimeout(() => {
      prevDebouncedTextRef.current = nextSig;
      setDebouncedActionFilter(actionFilter);
      setDebouncedActorFilter(actorFilter);
      setPage(1);
    }, 250);
    return () => clearTimeout(timer);
  }, [actionFilter, actorFilter]);

  const queryFilters = useMemo<AuditTrailFilters>(
    () => ({
      outcomeFilter,
      actionFilter: debouncedActionFilter,
      partitionFilter,
      actorFilter: debouncedActorFilter,
      fromDate,
      toDate,
      sortOrder,
    }),
    [
      outcomeFilter,
      debouncedActionFilter,
      partitionFilter,
      debouncedActorFilter,
      fromDate,
      toDate,
      sortOrder,
    ],
  );

  const activeFilters = useMemo<AuditTrailFilters>(
    () => ({
      outcomeFilter,
      actionFilter,
      partitionFilter,
      actorFilter,
      fromDate,
      toDate,
      sortOrder,
    }),
    [outcomeFilter, actionFilter, partitionFilter, actorFilter, fromDate, toDate, sortOrder],
  );

  const setOutcomeFilter = useCallback((value: string) => {
    setOutcomeFilterState(value);
    setPage(1);
  }, []);

  const setActionFilter = useCallback((value: string) => {
    setActionFilterState(value);
  }, []);

  const setPartitionFilter = useCallback((value: string) => {
    setPartitionFilterState(value);
    setPage(1);
  }, []);

  const setActorFilter = useCallback((value: string) => {
    setActorFilterState(value);
  }, []);

  const setFromDate = useCallback((value: string) => {
    setFromDateState(value);
    setPage(1);
  }, []);

  const setToDate = useCallback((value: string) => {
    setToDateState(value);
    setPage(1);
  }, []);

  const setSortOrder = useCallback((value: 'desc' | 'asc') => {
    setSortOrderState(value);
    setPage(1);
  }, []);

  const resetFilters = useCallback(() => {
    setOutcomeFilterState('ALL');
    setActionFilterState('');
    setPartitionFilterState('ALL');
    setActorFilterState('');
    setFromDateState('');
    setToDateState('');
    setSortOrderState('desc');
    setPage(1);
  }, []);

  const setPageSize = useCallback((nextSize: number) => {
    const normalized = [10, 20, 50].includes(nextSize) ? nextSize : DEFAULT_AUDIT_PAGE_SIZE;
    setPageSizeState(normalized);
    setPage(1);
  }, []);

  const fetchExportJobs = useCallback(async (signal?: AbortSignal) => {
    const exportsRes = await apiClient<
      { data?: Array<Partial<ExportJobItem> & { id: string }> } | ExportJobItem[]
    >('/reports/export', signal ? { signal } : undefined);
    const rawExportList = Array.isArray(exportsRes)
      ? exportsRes
      : Array.isArray(exportsRes?.data)
        ? exportsRes.data
        : [];
    return rawExportList
      .filter((item): item is Partial<ExportJobItem> & { id: string } => Boolean(item?.id))
      .map((item) => normalizeExportJob(item, (item.format as ExportFormat) || 'CSV'));
  }, []);

  const fetchAnchors = useCallback(async (signal?: AbortSignal) => {
    const res = await apiClient<{ data?: AuditAnchorItem[] }>(
      '/audit-logs/anchors',
      signal ? { signal } : undefined,
    );
    return Array.isArray(res?.data) ? res.data : [];
  }, []);

  const fetchAuditLogs = useCallback(
    async (signal?: AbortSignal) => {
      const queryParams = buildAuditLogsQueryParams(queryFilters, page, pageSize);
      const logsRes = await apiClient<AuditLogsPaginatedResponse>(
        `/audit-logs?${queryParams.toString()}`,
        signal ? { signal } : undefined,
      );
      return {
        items: normalizeAuditLogDtos(logsRes.data || []),
        pagination: extractAuditorPagination(logsRes, page, pageSize),
      };
    },
    [queryFilters, page, pageSize],
  );

  const refreshData = useCallback(async () => {
    refreshAbortRef.current?.abort();
    const controller = new AbortController();
    refreshAbortRef.current = controller;

    setIsLoading(true);
    setMessageState(null);
    setErrorMessageState(null);

    try {
      const tasks: Promise<unknown>[] = [];
      const logsIdx =
        canViewAuditLogs && !dateRangeError
          ? tasks.push(fetchAuditLogs(controller.signal)) - 1
          : -1;
      const anchorsIdx = canViewAuditLogs ? tasks.push(fetchAnchors(controller.signal)) - 1 : -1;
      const exportsIdx = canExportReports ? tasks.push(fetchExportJobs(controller.signal)) - 1 : -1;

      const settled = await Promise.allSettled(tasks);
      if (controller.signal.aborted) return;

      const errors: string[] = [];
      let source: AuditorErrorSource = 'general';

      if (dateRangeError) {
        source = 'logs';
        errors.push(dateRangeError);
      }

      if (logsIdx >= 0) {
        const res = settled[logsIdx];
        if (res?.status === 'fulfilled') {
          const logsResult = res.value as {
            items: AuditLogItem[];
            pagination: { page: number; pageSize: number; total: number; totalPages: number };
          };
          setLogs(logsResult.items);
          setTotalPages(logsResult.pagination.totalPages);
          setTotalLogs(logsResult.pagination.total);
          if (page > logsResult.pagination.totalPages) {
            setPage(logsResult.pagination.totalPages);
          }
        } else if (res?.status === 'rejected' && !isAbortError(res.reason, controller.signal)) {
          source = 'logs';
          errors.push(
            res.reason instanceof ApiError
              ? res.reason.message
              : 'Không thể tải nhật ký kiểm toán.',
          );
        }
      }

      if (anchorsIdx >= 0) {
        const res = settled[anchorsIdx];
        if (res?.status === 'fulfilled') {
          setAnchors(res.value as AuditAnchorItem[]);
        }
      }

      if (exportsIdx >= 0) {
        const res = settled[exportsIdx];
        if (res?.status === 'fulfilled') {
          const nextExports = res.value as ExportJobItem[];
          setExportJobs((prev) => mergeExportJobHistory(nextExports, prev));
        } else if (res?.status === 'rejected' && !isAbortError(res.reason, controller.signal)) {
          if (source === 'general') source = 'exports';
          errors.push(
            res.reason instanceof ApiError
              ? res.reason.message
              : 'Không thể tải lịch sử xuất báo cáo.',
          );
        }
      }

      if (errors.length > 0) {
        reportError(errors.join(' '), source);
      }
    } finally {
      if (!controller.signal.aborted) setIsLoading(false);
    }
  }, [
    canExportReports,
    canViewAuditLogs,
    dateRangeError,
    fetchAnchors,
    fetchAuditLogs,
    fetchExportJobs,
    page,
    reportError,
  ]);

  useEffect(() => {
    if (!canExportReports) return;
    let ignore = false;
    const controller = new AbortController();
    void (async () => {
      try {
        const nextExports = await fetchExportJobs(controller.signal);
        if (!ignore) setExportJobs((prev) => mergeExportJobHistory(nextExports, prev));
      } catch (err) {
        if (ignore || isAbortError(err, controller.signal)) return;
        reportError(
          err instanceof ApiError ? err.message : 'Không thể tải lịch sử xuất báo cáo.',
          'exports',
        );
      }
    })();
    return () => {
      ignore = true;
      controller.abort();
    };
  }, [canExportReports, fetchExportJobs, reportError]);

  useEffect(() => {
    if (!canViewAuditLogs) return;
    let ignore = false;
    const controller = new AbortController();
    void fetchAnchors(controller.signal)
      .then((list) => {
        if (!ignore) setAnchors(list);
      })
      .catch(() => {});
    return () => {
      ignore = true;
      controller.abort();
    };
  }, [canViewAuditLogs, fetchAnchors]);

  useEffect(() => {
    if (!canViewAuditLogs) {
      let ignore = false;
      void Promise.resolve().then(() => {
        if (!ignore) setIsLoading(false);
      });
      return () => {
        ignore = true;
      };
    }
    if (dateRangeError) {
      let ignore = false;
      void Promise.resolve().then(() => {
        if (!ignore) {
          setIsLoading(false);
          reportError(dateRangeError, 'logs');
        }
      });
      return () => {
        ignore = true;
      };
    }

    let ignore = false;
    const controller = new AbortController();

    void (async () => {
      setIsLoading(true);
      setErrorMessageState(null);
      try {
        const result = await fetchAuditLogs(controller.signal);
        if (ignore) return;
        setLogs(result.items);
        setTotalPages(result.pagination.totalPages);
        setTotalLogs(result.pagination.total);
        if (page > result.pagination.totalPages) {
          setPage(result.pagination.totalPages);
        }
      } catch (err) {
        if (ignore || isAbortError(err, controller.signal)) return;
        reportError(
          err instanceof ApiError ? err.message : 'Không thể tải nhật ký kiểm toán.',
          'logs',
        );
      } finally {
        if (!ignore && !controller.signal.aborted) setIsLoading(false);
      }
    })();

    return () => {
      ignore = true;
      controller.abort();
    };
  }, [canViewAuditLogs, dateRangeError, fetchAuditLogs, page, reportError]);

  useExportJobsPolling(exportJobs, setExportJobs, canExportReports);

  const verifyHashChain = useCallback(
    async (partitionOverride?: string) => {
      const targetPartition = partitionOverride ?? verifyPartition;
      setIsVerifyingChain(true);
      setMessageState(null);
      setErrorMessageState(null);
      try {
        const endpoint =
          targetPartition && targetPartition !== 'ALL'
            ? `/audit-logs/verify?chainPartition=${encodeURIComponent(targetPartition)}`
            : '/audit-logs/verify';
        const res = await apiClient<VerifyHashChainResponse>(endpoint);
        const { report, partitionCount, violationCount } = aggregatePartitionVerifications(res);
        setVerificationReport(report);
        if (canViewAuditLogs) {
          void fetchAnchors()
            .then(setAnchors)
            .catch(() => {});
        }

        if (report.isChainValid) {
          setMessage(
            report.totalEntriesChecked === 0
              ? 'Chưa có bản ghi nhật ký kiểm toán nào để kiểm tra.'
              : `Đã hoàn tất kiểm tra tính toàn vẹn trên ${partitionCount} phân vùng (${report.chainPartition}): Toàn vẹn, không phát hiện sai lệch (${report.totalEntriesChecked} bản ghi, ${report.totalAnchorsChecked} điểm neo).`,
          );
        } else {
          reportError(`Phát hiện sai lệch tính toàn vẹn tại ${violationCount} vị trí.`, 'verify');
        }
      } catch (err) {
        reportError(
          err instanceof ApiError
            ? err.message || 'Kiểm tra tính toàn vẹn nhật ký thất bại.'
            : 'Đã xảy ra lỗi khi kiểm tra tính toàn vẹn nhật ký.',
          'verify',
        );
      } finally {
        setIsVerifyingChain(false);
      }
    },
    [canViewAuditLogs, fetchAnchors, reportError, setMessage, verifyPartition],
  );

  const downloadExport = useCallback(
    async (job: ExportJobItem) => {
      setErrorMessageState(null);
      setDownloadingJobId(job.id);
      lastFailedDownloadJobRef.current = job;
      try {
        const blob = await apiDownload(`/reports/export/${job.id}/download`);
        triggerEphemeralBlobDownload(blob, job);
        lastFailedDownloadJobRef.current = null;
      } catch (err) {
        reportError(
          err instanceof ApiError ? err.message : 'Đã xảy ra lỗi khi tải tệp báo cáo.',
          'download',
        );
      } finally {
        setDownloadingJobId((prev) => (prev === job.id ? null : prev));
      }
    },
    [reportError],
  );

  const retryLastFailedOperation = useCallback(async () => {
    if (lastErrorSource === 'watermark') {
      const wmRetry = retryHandlersRef.current['watermark'];
      if (wmRetry) {
        await wmRetry();
        return;
      }
    }
    if (lastErrorSource === 'alerts') {
      const alertsRetry = retryHandlersRef.current['alerts'];
      if (alertsRetry) {
        await alertsRetry();
        return;
      }
    }
    if (lastErrorSource === 'verify') {
      await verifyHashChain();
      return;
    }
    if (lastErrorSource === 'download' && lastFailedDownloadJobRef.current) {
      await downloadExport(lastFailedDownloadJobRef.current);
      return;
    }
    if (lastErrorSource === 'logs' || lastErrorSource === 'exports') {
      await refreshData();
      return;
    }

    const activeTab = activeTabContextRef.current;
    if (activeTab === 'watermark-trace' && retryHandlersRef.current['watermark']) {
      await retryHandlersRef.current['watermark']();
      return;
    }
    if (activeTab === 'security-alerts' && retryHandlersRef.current['alerts']) {
      await retryHandlersRef.current['alerts']();
      return;
    }
    if (activeTab === 'chain-verify') {
      await verifyHashChain();
      return;
    }
    await refreshData();
  }, [downloadExport, lastErrorSource, refreshData, verifyHashChain]);

  const prependExportJob = useCallback(
    (job: ExportJobItem, msg: string) => {
      setExportJobs((prev) => [job, ...prev.filter((existing) => existing.id !== job.id)]);
      setDialogError(null);
      setMessage(msg);
    },
    [setMessage],
  );

  return {
    logs,
    page,
    setPage,
    pageSize,
    setPageSize,
    totalPages,
    totalLogs,
    anchors,
    exportJobs,
    verificationReport,
    verifyPartition,
    setVerifyPartition,
    isLoading,
    downloadingJobId,
    message,
    setMessage,
    errorMessage,
    setErrorMessage: reportError,
    dialogError,
    setDialogError,
    lastErrorSource,
    dateRangeError,
    activeFilters,
    outcomeFilter,
    setOutcomeFilter,
    actionFilter,
    setActionFilter,
    partitionFilter,
    setPartitionFilter,
    actorFilter,
    setActorFilter,
    fromDate,
    setFromDate,
    toDate,
    setToDate,
    sortOrder,
    setSortOrder,
    resetFilters,
    isVerifyingChain,
    refreshData,
    verifyHashChain,
    downloadExport,
    retryLastFailedOperation,
    prependExportJob,
    registerRetryHandler,
    setActiveTabContext,
  };
}
