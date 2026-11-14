'use client';

import { useCallback, useState } from 'react';
import { apiClient, ApiError } from '@/lib/api-client';
import type { WatermarkConfigRow } from '../types';

export const DEFAULT_WATERMARK_TEMPLATE =
  '{username} · {employeeCode} | {documentCode} · {timestamp} | {shortToken}';

interface UseWatermarkSettingsOptions {
  onRefresh: () => Promise<void>;
  onSuccess: (msg: string) => void;
  onError: (msg: string | null) => void;
}

/**
 * Thuật toán: Quản Lý Trạng Thái Hồ Sơ Thủy Ấn Động & Đồng Bộ Lưu Trữ Máy Chủ (`useWatermarkSettings`)
 * Mục đích: Đồng bộ tham số độ mờ, cỡ chữ, cờ mã QR và mẫu chuỗi `templateText` từ `/watermarks/configs` và cập nhật qua `PATCH /watermarks/configs/:id`.
 */
export function useWatermarkSettings({
  onRefresh,
  onSuccess,
  onError,
}: UseWatermarkSettingsOptions) {
  const [configs, setConfigs] = useState<WatermarkConfigRow[]>([]);
  const [activeConfigId, setActiveConfigId] = useState<string | null>(null);
  const [showQr, setShowQr] = useState(true);
  const [opacity, setOpacity] = useState(25);
  const [fontSize, setFontSize] = useState(14);
  const [templateText, setTemplateText] = useState(DEFAULT_WATERMARK_TEMPLATE);
  const [isSaving, setIsSaving] = useState(false);

  const hydrateConfigs = useCallback((loaded: WatermarkConfigRow[]) => {
    setConfigs(loaded);
    if (loaded.length > 0 && loaded[0]) {
      setActiveConfigId(loaded[0].id);
      setOpacity(loaded[0].opacityPercent);
      setFontSize(loaded[0].fontSize);
      setShowQr(loaded[0].includeQrCode);
      setTemplateText(loaded[0].templateText || DEFAULT_WATERMARK_TEMPLATE);
    }
  }, []);

  function selectConfig(configId: string) {
    const found = configs.find((c) => c.id === configId);
    if (found) {
      setActiveConfigId(found.id);
      setOpacity(found.opacityPercent);
      setFontSize(found.fontSize);
      setShowQr(found.includeQrCode);
      setTemplateText(found.templateText || DEFAULT_WATERMARK_TEMPLATE);
    }
  }

  async function saveConfig() {
    if (!activeConfigId) {
      onError('Không tìm thấy cấu hình watermark hợp lệ trên hệ thống.');
      return;
    }
    setIsSaving(true);
    onError(null);
    try {
      const activeOriginal = configs.find((c) => c.id === activeConfigId);
      const payload: Record<string, unknown> = {
        opacityPercent: opacity,
        fontSize,
        includeQrCode: showQr,
      };
      if (
        templateText.trim() &&
        (activeOriginal?.templateText !== undefined ||
          templateText.trim() !== DEFAULT_WATERMARK_TEMPLATE)
      ) {
        payload['templateText'] = templateText.trim();
      }
      await apiClient(`/watermarks/configs/${activeConfigId}`, {
        method: 'PATCH',
        body: JSON.stringify(payload),
      });
      onSuccess(
        'Đã lưu cấu hình Watermark thành công lên máy chủ. Mọi phiên xem trước và tải xuống tiếp theo sẽ áp dụng thiết lập này.',
      );
      await onRefresh();
    } catch (err) {
      onError(
        err instanceof ApiError
          ? err.message || 'Không thể lưu cấu hình Watermark.'
          : 'Đã xảy ra lỗi khi lưu cấu hình watermark.',
      );
    } finally {
      setIsSaving(false);
    }
  }

  return {
    configs,
    activeConfigId,
    showQr,
    setShowQr,
    opacity,
    setOpacity,
    fontSize,
    setFontSize,
    templateText,
    setTemplateText,
    isSaving,
    hydrateConfigs,
    selectConfig,
    saveConfig,
  };
}
