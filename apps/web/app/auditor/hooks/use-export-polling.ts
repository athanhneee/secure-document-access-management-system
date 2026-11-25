'use client';

import { useEffect, useRef, useState, type Dispatch, type SetStateAction } from 'react';
import { apiClient } from '@/lib/api-client';
import {
  isRealtimeStreamConnected,
  subscribeRealtimeConnectionStatus,
  subscribeRealtimeEvent,
} from '@/lib/realtime-events';
import { mergeExportJobHistory, normalizeExportJob } from '../helpers';
import type { ExportFormat, ExportJobItem } from '../types';

export function isAbortError(err: unknown, signal?: AbortSignal): boolean {
  if (signal?.aborted) return true;
  return err instanceof DOMException && err.name === 'AbortError';
}

const DISCONNECTED_POLL_INTERVAL_MS = 15_000;
const CONNECTED_SAFETY_POLL_INTERVAL_MS = 30_000;

/**
 * Thuật toán: Đồng Bộ Tiến Độ Xuất Báo Cáo Thời Gian Thực Qua SSE & Đối Soát An Toàn Đơn Yêu Cầu (`useExportJobsPolling`)
 * Mục đích:
 *   - Cập nhật tức thì qua kênh SSE `EXPORT_JOB_UPDATED` (`PENDING` → `PROCESSING` → `COMPLETED` / `FAILED`).
 *   - Gom đối soát dự phòng về đúng 1 lời gọi `GET /reports/export` (triệt tiêu N+1), tự đối soát khi SSE kết nối lại và duy trì nhịp an toàn để không bao giờ kẹt `PENDING` nếu rơi gói Redis.
 */
export function useExportJobsPolling(
  exportJobs: ExportJobItem[],
  setExportJobs: Dispatch<SetStateAction<ExportJobItem[]>>,
  enabled = true,
) {
  const [isSseConnected, setIsSseConnected] = useState(() => isRealtimeStreamConnected());
  const prevSseRef = useRef(isSseConnected);

  useEffect(() => {
    if (!enabled) return;
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
  }, [enabled, setExportJobs]);

  const activeJobIdsKey = exportJobs
    .filter((job) => job.status === 'PENDING' || job.status === 'PROCESSING')
    .map((job) => job.id)
    .join(',');

  useEffect(() => {
    const sseTransitioned = prevSseRef.current !== isSseConnected;
    prevSseRef.current = isSseConnected;

    if (!enabled || !activeJobIdsKey) return;

    let ignore = false;
    const controller = new AbortController();

    const syncExportQueue = async () => {
      try {
        const res = await apiClient<
          { data?: Array<Partial<ExportJobItem> & { id: string }> } | ExportJobItem[]
        >('/reports/export', { signal: controller.signal });
        if (ignore) return;
        const rawList = Array.isArray(res) ? res : Array.isArray(res?.data) ? res.data : [];
        const normalized = rawList
          .filter((item): item is Partial<ExportJobItem> & { id: string } => Boolean(item?.id))
          .map((item) => normalizeExportJob(item, (item.format as ExportFormat) || 'CSV'));
        setExportJobs((prev) => mergeExportJobHistory(normalized, prev));
      } catch (err) {
        if (ignore || isAbortError(err, controller.signal)) return;
      }
    };

    if (sseTransitioned || !isSseConnected) {
      void syncExportQueue();
    }

    const pollIntervalMs = isSseConnected
      ? CONNECTED_SAFETY_POLL_INTERVAL_MS
      : DISCONNECTED_POLL_INTERVAL_MS;
    const timer = setInterval(() => {
      void syncExportQueue();
    }, pollIntervalMs);

    return () => {
      ignore = true;
      clearInterval(timer);
      controller.abort();
    };
  }, [activeJobIdsKey, enabled, isSseConnected, setExportJobs]);
}
