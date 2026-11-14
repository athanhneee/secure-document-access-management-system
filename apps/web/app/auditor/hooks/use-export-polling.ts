'use client';

import { useEffect, type Dispatch, type SetStateAction } from 'react';
import { apiClient } from '@/lib/api-client';
import { normalizeExportJob } from '../helpers';
import type { ExportJobItem } from '../types';

export function isAbortError(err: unknown, signal?: AbortSignal): boolean {
  if (signal?.aborted) return true;
  return err instanceof DOMException && err.name === 'AbortError';
}

/**
 * Thuật toán: Thăm Dò Định Kỳ Hàng Đợi Xuất Báo Cáo Đang Xử Lý Có Hủy An Toàn (`useExportJobsPolling`)
 * Mục đích: Tự động cập nhật trạng thái `PENDING` / `PROCESSING` sang `COMPLETED` mỗi 2 giây kèm `AbortController` và cờ `ignore` sau `await`.
 */
export function useExportJobsPolling(
  exportJobs: ExportJobItem[],
  setExportJobs: Dispatch<SetStateAction<ExportJobItem[]>>,
) {
  const activeJobIdsKey = exportJobs
    .filter((job) => job.status === 'PENDING' || job.status === 'PROCESSING')
    .map((job) => job.id)
    .join(',');

  useEffect(() => {
    if (!activeJobIdsKey) return;

    const activeIds = activeJobIdsKey.split(',').filter(Boolean);
    let ignore = false;
    const controller = new AbortController();

    const pollPendingJobs = async () => {
      try {
        const settled = await Promise.all(
          activeIds.map((id) =>
            apiClient<Partial<ExportJobItem> & { id: string }>(`/reports/export/${id}`, {
              signal: controller.signal,
            }),
          ),
        );
        if (ignore) return;
        const updatesById = new Map<string, Partial<ExportJobItem> & { id: string }>();
        for (const item of settled) {
          if (item?.id) updatesById.set(item.id, item);
        }
        if (updatesById.size === 0) return;
        setExportJobs((prev) =>
          prev.map((job) => {
            const fresh = updatesById.get(job.id);
            return fresh ? normalizeExportJob({ ...job, ...fresh }, job.format) : job;
          }),
        );
      } catch (err) {
        if (ignore || isAbortError(err, controller.signal)) return;
      }
    };

    const timer = setInterval(() => {
      void pollPendingJobs();
    }, 2000);

    return () => {
      ignore = true;
      clearInterval(timer);
      controller.abort();
    };
  }, [activeJobIdsKey, setExportJobs]);
}
