'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { apiClient, apiDownload, ApiError } from '@/lib/api-client';
import {
  aggregatePartitionVerifications,
  buildAuditLogsQueryParams,
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
 * Thuật toán: Quản lý Trạng thái Kiểm toán Fail-Closed, Chống Đua Mạng & Debounce 250ms (`useAuditorData`)
 * Mục đích: Tách riêng truy vấn danh sách xuất báo cáo `/reports/export` khỏi thao tác gõ bộ lọc `/audit-logs`, trì hoãn 250ms, hủy yêu cầu cũ qua `AbortController` và hiển thị minh bạch mọi lỗi API.
 */
export function useAuditorData() {
  const [logs, setLogs] = useState<AuditLogItem[]>([]);
  const [exportJobs, setExportJobs] = useState<ExportJobItem[]>([]);
  const [verificationReport, setVerificationReport] = useState<ChainVerificationReport | null>(
    null,
  );

  const [isLoading, setIsLoading] = useState(true);
  const [message, setMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const [outcomeFilter, setOutcomeFilter] = useState<string>('ALL');
  const [actionFilter, setActionFilter] = useState('');
  const [fromDate, setFromDate] = useState('');
  const [toDate, setToDate] = useState('');
  const [isVerifyingChain, setIsVerifyingChain] = useState(false);
  const hasMountedFilterRef = useRef(false);

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
      const queryParams = buildAuditLogsQueryParams({
        outcomeFilter,
        actionFilter,
        fromDate,
        toDate,
      });
      const logsRes = await apiClient<AuditLogsPaginatedResponse>(
        `/audit-logs?${queryParams.toString()}`,
        signal ? { signal } : undefined,
      );
      return normalizeAuditLogDtos(logsRes.data || []);
    },
    [outcomeFilter, actionFilter, fromDate, toDate],
  );

  const refreshData = useCallback(async () => {
    setIsLoading(true);
    setErrorMessage(null);
    try {
      const [nextLogs, nextExports] = await Promise.all([fetchAuditLogs(), fetchExportJobs()]);
      setLogs(nextLogs);
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
    const run = async () => {
      try {
        const nextExports = await fetchExportJobs(controller.signal);
        if (ignore) return;
        setExportJobs((prev) => mergeExportJobHistory(nextExports, prev));
      } catch (err) {
        if (ignore || isAbortError(err, controller.signal)) return;
        setErrorMessage(
          err instanceof ApiError ? err.message : 'Không thể tải hàng đợi xuất báo cáo.',
        );
      }
    };
    void run();
    return () => {
      ignore = true;
      controller.abort();
    };
  }, [fetchExportJobs]);

  useEffect(() => {
    let ignore = false;
    const controller = new AbortController();
    const delayMs = hasMountedFilterRef.current ? 250 : 0;
    hasMountedFilterRef.current = true;

    const timer = setTimeout(() => {
      const run = async () => {
        setIsLoading(true);
        setErrorMessage(null);
        try {
          const nextLogs = await fetchAuditLogs(controller.signal);
          if (ignore) return;
          setLogs(nextLogs);
        } catch (err) {
          if (ignore || isAbortError(err, controller.signal)) return;
          setErrorMessage(
            err instanceof ApiError ? err.message : 'Không thể tải nhật ký kiểm toán.',
          );
        } finally {
          if (!ignore && !controller.signal.aborted) setIsLoading(false);
        }
      };
      void run();
    }, delayMs);

    return () => {
      ignore = true;
      clearTimeout(timer);
      controller.abort();
    };
  }, [fetchAuditLogs]);

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
      setErrorMessage(
        err instanceof ApiError
          ? err.message || 'Không thể tải tệp báo cáo.'
          : 'Đã xảy ra lỗi khi tải tệp báo cáo.',
      );
    }
  }

  function prependExportJob(job: ExportJobItem, msg: string) {
    setExportJobs((prev) => [job, ...prev.filter((existing) => existing.id !== job.id)]);
    setMessage(msg);
  }

  return {
    logs,
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
