'use client';

import { useEffect, useState, type Dispatch, type SetStateAction } from 'react';
import { apiClient } from '@/lib/api-client';
import {
  isRealtimeStreamConnected,
  subscribeRealtimeConnectionStatus,
  subscribeRealtimeEvent,
} from '@/lib/realtime-events';
import { normalizeExportJob } from '../helpers';
import type { ExportFormat, ExportJobItem } from '../types';

export function isAbortError(err: unknown, signal?: AbortSignal): boolean {
  if (signal?.aborted) return true;
  return err instanceof DOMException && err.name === 'AbortError';
}

const FALLBACK_POLL_INTERVAL_MS = 15_000;

/**
 * Thuật toán: Đồng Bộ Tiến Độ Xuất Báo Cáo Thời Gian Thực Qua SSE & Fallback An Toàn (`useExportJobsPolling`)
 * Mục đích:
 *   - Thay thế hoàn toàn cơ chế polling dồn dập mỗi 2 giây bằng kênh SSE `EXPORT_JOB_UPDATED` để cập nhật tức thời `PENDING` → `PROCESSING` → `COMPLETED` / `FAILED`.
 *   - Chỉ duy trì nhịp kiểm tra dự phòng thưa (`15 giây`) khi luồng SSE tạm mất kết nối và vẫn còn tác vụ đang chạy, đảm bảo không bao giờ kẹt trạng thái.
 */
export function useExportJobsPolling(
  exportJobs: ExportJobItem[],
  setExportJobs: Dispatch<SetStateAction<ExportJobItem[]>>,
) {
  const [isSseConnected, setIsSseConnected] = useState(() => isRealtimeStreamConnected());

  useEffect(() => {
    const unsubStatus = subscribeRealtimeConnectionStatus(setIsSseConnected);
    const unsubEvent = subscribeRealtimeEvent<Partial<ExportJobItem> & { id?: string }>(
      'EXPORT_JOB_UPDATED',
      (event) => {
        const fresh = event.payload;
        if (!fresh?.id) return;
        const jobId = String(fresh.id);
        setExportJobs((prev) => {
          const exists = prev.some((job) => job.id === jobId);
          if (!exists) {
            const fallbackFormat = (fresh.format as ExportFormat | undefined) ?? 'CSV';
            return [normalizeExportJob({ ...fresh, id: jobId }, fallbackFormat), ...prev];
          }
          return prev.map((job) =>
            job.id === jobId
              ? normalizeExportJob({ ...job, ...fresh, id: jobId }, job.format)
              : job,
          );
        });
      },
    );

    return () => {
      unsubStatus();
      unsubEvent();
    };
  }, [setExportJobs]);

  const activeJobIdsKey = exportJobs
    .filter((job) => job.status === 'PENDING' || job.status === 'PROCESSING')
    .map((job) => job.id)
    .join(',');

  useEffect(() => {
    if (!activeJobIdsKey || isSseConnected) return;

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
    }, FALLBACK_POLL_INTERVAL_MS);

    return () => {
      ignore = true;
      clearInterval(timer);
      controller.abort();
    };
  }, [activeJobIdsKey, isSseConnected, setExportJobs]);
}
