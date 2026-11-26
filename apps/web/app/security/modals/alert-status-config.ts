import type { SecurityAlertItem } from '../types';

/**
 * Thuật toán: Bảng Ánh Xạ Máy Trạng Thái Cảnh Báo An Ninh (`VALID_TRANSITIONS` & `STATUS_LABELS`)
 * Mục đích: Ràng buộc tập trạng thái đích hợp lệ cho từng trạng thái cảnh báo SOC hiện hành.
 */
export const VALID_TRANSITIONS: Record<SecurityAlertItem['status'], SecurityAlertItem['status'][]> =
  {
    OPEN: ['INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'],
    INVESTIGATING: ['RESOLVED', 'FALSE_POSITIVE', 'OPEN'],
    RESOLVED: ['INVESTIGATING'],
    FALSE_POSITIVE: ['INVESTIGATING'],
  };

export const STATUS_LABELS: Record<SecurityAlertItem['status'], string> = {
  OPEN: 'Chờ xử lý',
  INVESTIGATING: 'Đang điều tra',
  RESOLVED: 'Đã xử lý',
  FALSE_POSITIVE: 'Báo động giả',
};
