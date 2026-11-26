'use client';

import { useEffect, useState, type MutableRefObject } from 'react';
import { ApiError } from '@/lib/api-client';
import type { NetworkDlpStatus, SecurityTabErrors } from '../types';

export type SecuritySectionKey = 'alerts' | 'incidents' | 'sessions' | 'rules' | 'dlp';

export const DEFAULT_DLP_STATUS: NetworkDlpStatus = {
  gatewayHealth: 'OFFLINE',
  workerReachable: false,
  icapEnabled: false,
  icapListening: false,
  enforcementMode: 'OFFLINE',
  totalDlpAlerts: 0,
  openDlpAlerts: 0,
  checkedAt: '',
};

export const EMPTY_TAB_ERRORS: SecurityTabErrors = {
  alerts: null,
  incidents: null,
  sessions: null,
  rules: null,
  dlp: null,
};

/**
 * Thuật toán: Giảm Chấn Giá Trị Tìm Kiếm 300ms Bảo Toàn Bộ Gõ Tiếng Việt Telex/VNI (`useDebouncedValue`)
 * Mục đích: Tách biệt trạng thái nhập tức thời của `<Input>` với từ khóa gửi lên API sau 300ms ngừng gõ, không bao giờ unmount ô nhập liệu.
 */
export function useDebouncedValue<T>(value: T, delayMs = 300): T {
  const [debounced, setDebounced] = useState<T>(value);

  useEffect(() => {
    const timer = setTimeout(() => {
      setDebounced(value);
    }, delayMs);
    return () => clearTimeout(timer);
  }, [value, delayMs]);

  return debounced;
}

/**
 * Thuật toán: Cấp Phát `AbortController` Độc Lập Theo Từng Phân Khu SOC (`nextSectionAbortController`)
 * Mục đích: Khi người dùng gõ tìm kiếm trong một tab, chỉ hủy truy vấn cũ của đúng phân khu đó mà không cắt ngang 4 phân khu còn lại.
 */
export function nextSectionAbortController(
  controllersRef: MutableRefObject<Partial<Record<SecuritySectionKey, AbortController>>>,
  section: SecuritySectionKey,
): AbortController {
  controllersRef.current[section]?.abort();
  const next = new AbortController();
  controllersRef.current[section] = next;
  return next;
}

export function abortAllSectionControllers(
  controllersRef: MutableRefObject<Partial<Record<SecuritySectionKey, AbortController>>>,
): void {
  for (const ctrl of Object.values(controllersRef.current)) {
    ctrl?.abort();
  }
  controllersRef.current = {};
}

export function isRequestAborted(err: unknown, signal?: AbortSignal): boolean {
  if (signal?.aborted) return true;
  return err instanceof DOMException && err.name === 'AbortError';
}

export function formatSecuritySectionError(err: unknown, fallback: string): string {
  return err instanceof ApiError ? err.message || fallback : fallback;
}
