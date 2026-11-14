'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { apiClient, apiDownload, ApiError } from '@/lib/api-client';
import {
  aggregatePartitionVerifications,
  buildAuditLogsQueryParams,
  extractAuditorPagination,
  normalizeAuditLogDtos,
  normalizeExportJob,
  triggerEphemeralBlobDownload,
} from '../helpers';
import type {
  AuditLogItem,
  AuditLogsPaginatedResponse,
  ChainVerificationReport,
  ExportFormat,
  ExportJobItem,
  VerifyHashChainResponse,
} from '../types';
import { isAbortError, useExportJobsPolling } from './use-export-polling';

const AUDIT_PAGE_SIZE = 20;

function mergeExportJobHistory(
  incoming: ExportJobItem[],
  previous: ExportJobItem[],
): ExportJobItem[] {
  if (incoming.length === 0) return previous;
  const incomingIds = new Set(incoming.map((job) => job.id));
  const localUnsynced = previous.filter((job) => !incomingIds.has(job.id));
  return [...localUnsynced, ...incoming];
}

/**
 * Thuật toán: Quản lý Trạng thái Kiểm toán Fail-Closed, Phân Trang Máy Chủ & Debounce 250ms (`useAuditorData`)
 * Mục đích: Đồng bộ phân trang máy chủ (`page`, `pageSize`) với bộ lọc đa chiều (tự động đưa `page` về `1` khi đổi bộ lọc), hủy yêu cầu cũ qua `AbortController` và hiển thị minh bạch mọi lỗi API.
 */
export function useAuditorData() {
  const [logs, setLogs] = useState<AuditLogItem[]>([]);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [totalLogs, setTotalLogs] = useState(0);

  const [exportJobs, setExportJobs] = useState<ExportJobItem[]>([]);
  const [verificationReport, setVerificationReport] = useState<ChainVerificationReport | null>(
    null,
  );

  const [isLoading, setIsLoading] = useState(true);
  const [message, setMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const [outcomeFilter, setOutcomeFilterState] = useState<string>('ALL');
  const [actionFilter, setActionFilterState] = useState('');
  const [fromDate, setFromDateState] = useState('');
  const [toDate, setToDateState] = useState('');
  const [isVerifyingChain, setIsVerifyingChain] = useState(false);
  const prevActionFilterRef = useRef('');

  const setOutcomeFilter = useCallback((value: string) => {
    setOutcomeFilterState(value);
    setPage(1);
  }, []);

  const setActionFilter = useCallback((value: string) => {
    setActionFilterState(value);
    setPage(1);
  }, []);

  const setFromDate = useCallback((value: string) => {
    setFromDateState(value);
    setPage(1);
  }, []);

  const setToDate = useCallback((value: string) => {
    setToDateState(value);
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

  const fetchAuditLogs = useCallback(
    async (signal?: AbortSignal) => {
      const queryParams = buildAuditLogsQueryParams(
        { outcomeFilter, actionFilter, fromDate, toDate },
        page,
        AUDIT_PAGE_SIZE,
      );
      const logsRes = await apiClient<AuditLogsPaginatedResponse>(
        `/audit-logs?${queryParams.toString()}`,
        signal ? { signal } : undefined,
      );
      return {
        items: normalizeAuditLogDtos(logsRes.data || []),
        pagination: extractAuditorPagination(logsRes, page, AUDIT_PAGE_SIZE),
      };
    },
    [outcomeFilter, actionFilter, fromDate, toDate, page],
  );

  const refreshData = useCallback(async () => {
    setIsLoading(true);
    setErrorMessage(null);
    try {
      const [logsResult, nextExports] = await Promise.all([fetchAuditLogs(), fetchExportJobs()]);
      setLogs(logsResult.items);
      setTotalPages(logsResult.pagination.totalPages);
      setTotalLogs(logsResult.pagination.total);
      setExportJobs((prev) => mergeExportJobHistory(nextExports, prev));
    } catch (err) {
      setErrorMessage(
        err instanceof ApiError ? err.message : 'Không thể tải dữ liệu nhật ký kiểm toán.',
      );
    } finally {
      setIsLoading(false);
    }
  }, [fetchAuditLogs, fetchExportJobs]);

  useEffect(() => {
    let ignore = false;
    const controller = new AbortController();
    void (async () => {
      try {
        const nextExports = await fetchExportJobs(controller.signal);
        if (!ignore) setExportJobs((prev) => mergeExportJobHistory(nextExports, prev));
      } catch (err) {
        if (ignore || isAbortError(err, controller.signal)) return;
        setErrorMessage(
          err instanceof ApiError ? err.message : 'Không thể tải hàng đợi xuất báo cáo.',
        );
      }
    })();
    return () => {
      ignore = true;
      controller.abort();
    };
  }, [fetchExportJobs]);

  useEffect(() => {
    let ignore = false;
    const controller = new AbortController();
    const actionChanged = prevActionFilterRef.current !== actionFilter;
    prevActionFilterRef.current = actionFilter;
    const delayMs = actionChanged ? 250 : 0;

    const timer = setTimeout(() => {
      void (async () => {
        setIsLoading(true);
        setErrorMessage(null);
        try {
          const result = await fetchAuditLogs(controller.signal);
          if (ignore) return;
          setLogs(result.items);
          setTotalPages(result.pagination.totalPages);
          setTotalLogs(result.pagination.total);
        } catch (err) {
          if (ignore || isAbortError(err, controller.signal)) return;
          setErrorMessage(
            err instanceof ApiError ? err.message : 'Không thể tải nhật ký kiểm toán.',
          );
        } finally {
          if (!ignore && !controller.signal.aborted) setIsLoading(false);
        }
      })();
    }, delayMs);

    return () => {
      ignore = true;
      clearTimeout(timer);
      controller.abort();
    };
  }, [fetchAuditLogs, actionFilter]);

  useExportJobsPolling(exportJobs, setExportJobs);

  async function verifyHashChain() {
    setIsVerifyingChain(true);
    setErrorMessage(null);
    try {
      const res = await apiClient<VerifyHashChainResponse>('/audit-logs/verify');
      const { report, partitionCount, violationCount } = aggregatePartitionVerifications(res);
      setVerificationReport(report);

      if (report.isChainValid) {
        setMessage(
          report.totalEntriesChecked === 0
            ? 'CHƯA CÓ BẢN GHI / HỢP LỆ: Sổ cái kiểm toán chưa phát sinh bản ghi và không có sai lệch.'
            : `Đã hoàn thành kiểm tra tính toàn vẹn chuỗi băm HMAC-SHA256 trên ${partitionCount} phân vùng (${report.chainPartition}): Hợp lệ 100% (${report.totalEntriesChecked} bản ghi).`,
        );
      } else {
        setErrorMessage(`Phát hiện sai lệch chuỗi băm trong ${violationCount} vị trí!`);
      }
    } catch (err) {
      setErrorMessage(
        err instanceof ApiError
          ? err.message || 'Xác minh chuỗi băm thất bại.'
          : 'Đã xảy ra lỗi khi kiểm tra tính toàn vẹn chuỗi băm.',
      );
    } finally {
      setIsVerifyingChain(false);
    }
  }

  async function downloadExport(job: ExportJobItem) {
    setErrorMessage(null);
    try {
      const blob = await apiDownload(`/reports/export/${job.id}/download`);
      triggerEphemeralBlobDownload(blob, job);
    } catch (err) {
      setErrorMessage(err instanceof ApiError ? err.message : 'Đã xảy ra lỗi khi tải tệp báo cáo.');
    }
  }

  function prependExportJob(job: ExportJobItem, msg: string) {
    setExportJobs((prev) => [job, ...prev.filter((existing) => existing.id !== job.id)]);
    setMessage(msg);
  }

  return {
    logs,
    page,
    setPage,
    totalPages,
    totalLogs,
    exportJobs,
    verificationReport,
    isLoading,
    message,
    errorMessage,
    setErrorMessage,
    outcomeFilter,
    setOutcomeFilter,
    actionFilter,
    setActionFilter,
    fromDate,
    setFromDate,
    toDate,
    setToDate,
    isVerifyingChain,
    refreshData,
    verifyHashChain,
    downloadExport,
    prependExportJob,
  };
}
