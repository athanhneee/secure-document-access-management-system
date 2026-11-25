'use client';

import { useCallback, useState } from 'react';
import { apiClient, ApiError } from '@/lib/api-client';
import type { WatermarkConfigRow } from '../types';
import {
  DEFAULT_WATERMARK_COLOR_HEX,
  DEFAULT_WATERMARK_ROTATION,
  DEFAULT_WATERMARK_TEMPLATE,
  isValidHexColor,
  isWatermarkColorTooLight,
  requiresQrOrFullTokenForWatermarkConfig,
  selectInitialWatermarkConfig,
} from '../watermark-helpers';

export { DEFAULT_WATERMARK_TEMPLATE };

interface UseWatermarkSettingsOptions {
  onRefresh?: () => Promise<void>;
  onSuccess: (msg: string) => void;
  onError: (msg: string | null) => void;
}

/**
 * Thuật toán: Quản Lý Trạng Thái Hồ Sơ Thủy Ấn Động Đầy Đủ Tham Số & Chọn Mặc Định `isDefault` (`useWatermarkSettings`)
 * Mục đích: Đồng bộ độ mờ (10–90%), cỡ chữ (8–72px), góc xoay (-90°..90°), màu sắc (`colorHex`), cờ mã QR và mẫu `templateText` từ `/watermarks/configs`, ưu tiên cấu hình `isDefault` khi khởi tạo và cập nhật trực tiếp từ phản hồi `PATCH /watermarks/configs/:id`.
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
  const [fontSize, setFontSize] = useState(12);
  const [colorHex, setColorHex] = useState(DEFAULT_WATERMARK_COLOR_HEX);
  const [rotationDegrees, setRotationDegrees] = useState(DEFAULT_WATERMARK_ROTATION);
  const [templateText, setTemplateText] = useState(DEFAULT_WATERMARK_TEMPLATE);
  const [isSaving, setIsSaving] = useState(false);

  const applyConfigToForm = useCallback((chosen: WatermarkConfigRow) => {
    setOpacity(chosen.opacityPercent);
    setFontSize(chosen.fontSize);
    setShowQr(chosen.includeQrCode);
    setColorHex(chosen.colorHex || DEFAULT_WATERMARK_COLOR_HEX);
    setRotationDegrees(chosen.rotationDegrees ?? DEFAULT_WATERMARK_ROTATION);
    setTemplateText(chosen.templateText || DEFAULT_WATERMARK_TEMPLATE);
  }, []);

  const hydrateConfigs = useCallback(
    (loaded: WatermarkConfigRow[]) => {
      setConfigs(loaded);
      if (loaded.length === 0) return;
      setActiveConfigId((prevId) => {
        const chosen = selectInitialWatermarkConfig(loaded, prevId);
        if (!chosen) return prevId;
        applyConfigToForm(chosen);
        return chosen.id;
      });
    },
    [applyConfigToForm],
  );

  function selectConfig(configId: string) {
    const found = configs.find((c) => c.id === configId);
    if (found) {
      setActiveConfigId(found.id);
      applyConfigToForm(found);
    }
  }

  async function saveConfig() {
    if (!activeConfigId) {
      onError('Không tìm thấy cấu hình watermark bảo mật hợp lệ trên hệ thống.');
      return;
    }

    const trimmedTemplate = templateText.trim();
    if (trimmedTemplate.length < 5 || trimmedTemplate.length > 250) {
      onError('Mẫu văn bản watermark phải dài từ 5 đến 250 ký tự.');
      return;
    }

    const trimmedColor = colorHex.trim();
    if (!isValidHexColor(trimmedColor)) {
      onError('Mã màu watermark không hợp lệ (cần đúng định dạng #RRGGBB, ví dụ #717171).');
      return;
    }
    if (isWatermarkColorTooLight(trimmedColor)) {
      onError('Màu watermark quá nhạt (độ sáng > 88%), không đủ độ tương phản trên trang sáng.');
      return;
    }

    const activeOriginal = configs.find((c) => c.id === activeConfigId);
    if (
      requiresQrOrFullTokenForWatermarkConfig({
        classificationCode: activeOriginal?.classificationLevel?.code,
        classificationRank: activeOriginal?.classificationLevel?.rank,
        includeQrCode: showQr,
        templateText: trimmedTemplate,
      })
    ) {
      onError(
        'Cấu hình dành cho tài liệu Tối mật / Tuyệt mật không được tắt mã QR trừ khi mẫu có chứa {watermarkToken}.',
      );
      return;
    }

    setIsSaving(true);
    onError(null);
    try {
      const payload: Record<string, unknown> = {
        opacityPercent: Math.round(opacity),
        fontSize: Math.round(fontSize),
        includeQrCode: showQr,
        colorHex: trimmedColor,
        rotationDegrees: Math.round(rotationDegrees),
        templateText: trimmedTemplate,
      };
      const updated = await apiClient<Partial<WatermarkConfigRow>>(
        `/watermarks/configs/${activeConfigId}`,
        {
          method: 'PATCH',
          body: JSON.stringify(payload),
        },
      );
      setConfigs((prev) =>
        prev.map((item) =>
          item.id === activeConfigId
            ? {
                ...item,
                opacityPercent: updated.opacityPercent ?? Math.round(opacity),
                fontSize: updated.fontSize ?? Math.round(fontSize),
                includeQrCode: updated.includeQrCode ?? showQr,
                colorHex: updated.colorHex ?? trimmedColor,
                rotationDegrees: updated.rotationDegrees ?? Math.round(rotationDegrees),
                templateText: updated.templateText ?? trimmedTemplate,
              }
            : item,
        ),
      );
      onSuccess(
        'Đã lưu cấu hình watermark bảo mật thành công và tự động làm mới bộ đệm xem trước. Mọi lượt xem và tải về tiếp theo sẽ áp dụng ngay thiết lập mới.',
      );
      if (onRefresh) {
        await onRefresh();
      }
    } catch (err) {
      onError(
        err instanceof ApiError
          ? err.message || 'Không thể lưu cấu hình watermark bảo mật.'
          : 'Đã xảy ra lỗi khi lưu cấu hình watermark bảo mật.',
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
    colorHex,
    setColorHex,
    rotationDegrees,
    setRotationDegrees,
    templateText,
    setTemplateText,
    isSaving,
    hydrateConfigs,
    selectConfig,
    saveConfig,
  };
}
