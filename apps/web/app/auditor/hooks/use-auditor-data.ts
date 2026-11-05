'use client';

import { useCallback, useEffect, useState } from 'react';
import { apiClient, apiDownload, ApiError } from '@/lib/api-client';
import {
  aggregatePartitionVerifications,
  buildAuditLogsQueryParams,
  normalizeAuditLogDtos,
  normalizeExportJob,
  triggerEphemeralBlobDownload,
} from '../helpers';
import type {
  AuditLogApiDto,
  AuditLogItem,
  ChainVerificationReport,
  ExportFormat,
  ExportJobItem,
  PartitionVerificationResult,
} from '../types';

/**
 * Thuật toán: Hợp Nhất Lịch Sử Tác Vụ Xuất Báo Cáo Bền Vững (`mergeExportJobHistory`)
 * Mục đích: Đồng bộ danh sách tác vụ xuất từ `/reports/export` với các tác vụ vừa khởi tạo trong phiên mà không làm mất trạng thái hoặc sinh bản ghi trùng `id`.
 */
function mergeExportJobHistory(
  incoming: ExportJobItem[],
  previous: ExportJobItem[],
): ExportJobItem[] {
  if (incoming.length === 0) {
    return previous;
  }
  const incomingIds = new Set(incoming.map((job) => job.id));
  const localUnsynced = previous.filter((job) => !incomingIds.has(job.id));
  return [...localUnsynced, ...incoming];
}

/**
 * Thuật toán: Quản lý Trạng thái Kiểm toán Chỉ đọc & Điều phối Xác minh Chuỗi Băm (`useAuditorData`)
 * Mục đích: Kết nối truy vấn lọc nhật ký kiểm toán, kích hoạt đối chiếu toàn vẹn chuỗi băm đa phân vùng `/audit-logs/verify` và tải tệp báo cáo an toàn.
 * Cơ chế hoạt động:
 *   - Sử dụng cờ hủy hiệu ứng `ignore` chống ghi đè trạng thái từ phản hồi mạng cũ (stale response race) khi người dùng thay đổi bộ lọc liên tục.
 *   - Gọi `aggregatePartitionVerifications` tổng hợp kết quả kiểm tra `previous_hash -> entry_hash` và tính liên tục của `chain_sequence` trên toàn bộ phân vùng.
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

  const refreshData = useCallback(async () => {
    setIsLoading(true);
    setErrorMessage(null);
    try {
      const queryParams = buildAuditLogsQueryParams({
        outcomeFilter,
        actionFilter,
        fromDate,
        toDate,
      });
      const [logsRes, exportsRes] = await Promise.all([
        apiClient<{ data: AuditLogApiDto[] }>(`/audit-logs?${queryParams.toString()}`).catch(
          () => ({ data: [] }),
        ),
        apiClient<{ data?: Array<Partial<ExportJobItem> & { id: string }> } | ExportJobItem[]>(
          '/reports/export',
        ).catch(() => ({ data: [] })),
      ]);

      setLogs(normalizeAuditLogDtos(logsRes.data || []));

      const rawExportList = Array.isArray(exportsRes)
        ? exportsRes
        : Array.isArray(exportsRes?.data)
          ? exportsRes.data
          : [];
      const normalizedExports = rawExportList
        .filter((item): item is Partial<ExportJobItem> & { id: string } => Boolean(item?.id))
        .map((item) => normalizeExportJob(item, (item.format as ExportFormat) || 'CSV'));
      setExportJobs((prev) => mergeExportJobHistory(normalizedExports, prev));
    } catch (err) {
      setErrorMessage(err instanceof ApiError ? err.message : 'Không thể tải nhật ký kiểm toán.');
    } finally {
      setIsLoading(false);
    }
  }, [outcomeFilter, actionFilter, fromDate, toDate]);

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

  const activeJobIdsKey = exportJobs
    .filter((job) => job.status === 'PENDING' || job.status === 'PROCESSING')
    .map((job) => job.id)
    .join(',');

  /**
   * Thuật toán: Thăm Dò Định Kỳ Trạng Thái Kết Xuất Báo Cáo Bất Đồng Bộ (2000ms Bounded Export Job Polling)
   * Mục đích: Tự động truy vấn `/reports/export/:id` mỗi 2 giây khi tồn tại tác vụ `PENDING` hoặc `PROCESSING` và dừng ngay khi mọi tác vụ chuyển sang trạng thái kết thúc (`COMPLETED`, `FAILED`, `EXPIRED`).
   */
  useEffect(() => {
    if (!activeJobIdsKey) {
      return;
    }

    const activeIds = activeJobIdsKey.split(',').filter(Boolean);
    let cancelled = false;

    const pollPendingJobs = async () => {
      const settled = await Promise.all(
        activeIds.map((id) =>
          apiClient<Partial<ExportJobItem> & { id: string }>(`/reports/export/${id}`).catch(
            () => null,
          ),
        ),
      );

      if (cancelled) {
        return;
      }

      const updatesById = new Map<string, Partial<ExportJobItem> & { id: string }>();
      for (const item of settled) {
        if (item?.id) {
          updatesById.set(item.id, item);
        }
      }

      if (updatesById.size === 0) {
        return;
      }

      setExportJobs((prev) =>
        prev.map((job) => {
          const fresh = updatesById.get(job.id);
          return fresh ? normalizeExportJob({ ...job, ...fresh }, job.format) : job;
        }),
      );
    };

    const timer = setInterval(() => {
      void pollPendingJobs();
    }, 2000);

    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [activeJobIdsKey]);

  async function verifyHashChain() {
    setIsVerifyingChain(true);
    setErrorMessage(null);
    try {
      const res =
        await apiClient<Record<string, PartitionVerificationResult>>('/audit-logs/verify');
      const { report, partitionCount, violationCount } = aggregatePartitionVerifications(res);
      setVerificationReport(report);

      if (report.isChainValid) {
        setMessage(
          `Đã hoàn thành kiểm tra tính toàn vẹn chuỗi băm HMAC-SHA256 trên ${partitionCount} phân vùng: Hợp lệ 100% (${report.totalEntriesChecked} bản ghi).`,
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
