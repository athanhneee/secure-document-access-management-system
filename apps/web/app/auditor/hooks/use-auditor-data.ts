'use client';

import { useCallback, useEffect, useState } from 'react';
import { apiClient, apiDownload, ApiError } from '@/lib/api-client';
import {
  aggregatePartitionVerifications,
  buildAuditLogsQueryParams,
  normalizeAuditLogDtos,
  triggerEphemeralBlobDownload,
} from '../helpers';
import type {
  AuditLogApiDto,
  AuditLogItem,
  ChainVerificationReport,
  ExportJobItem,
  PartitionVerificationResult,
} from '../types';

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
      const logsRes = await apiClient<{ data: AuditLogApiDto[] }>(
        `/audit-logs?${queryParams.toString()}`,
      ).catch(() => ({ data: [] }));

      setLogs(normalizeAuditLogDtos(logsRes.data || []));
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
    setExportJobs((prev) => [job, ...prev]);
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
