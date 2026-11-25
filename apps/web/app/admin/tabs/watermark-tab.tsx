'use client';

import { AlertTriangle, Stamp } from 'lucide-react';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import type { WatermarkConfigRow } from '../types';
import {
  DEFAULT_WATERMARK_COLOR_HEX,
  DEFAULT_WATERMARK_ROTATION,
  DEFAULT_WATERMARK_TEMPLATE,
  isValidHexColor,
  isWatermarkColorTooLight,
  normalizeHexColor,
  requiresQrOrFullTokenForWatermarkConfig,
  WATERMARK_COLOR_PRESETS,
  WATERMARK_FONT_SIZE_MAX,
  WATERMARK_FONT_SIZE_MIN,
  WATERMARK_OPACITY_MAX,
  WATERMARK_OPACITY_MIN,
  WATERMARK_ROTATION_MAX,
  WATERMARK_ROTATION_MIN,
  WATERMARK_ROTATION_PRESETS,
  WATERMARK_TEMPLATE_VARIABLES,
} from '../watermark-helpers';
import { WatermarkPreviewCard } from './watermark-preview-card';

interface WatermarkTabProps {
  configs: WatermarkConfigRow[];
  activeConfigId: string | null;
  showQr: boolean;
  opacity: number;
  fontSize: number;
  colorHex?: string | undefined;
  rotationDegrees?: number | undefined;
  templateText?: string | undefined;
  previewUsername?: string | null | undefined;
  previewFullName?: string | null | undefined;
  isSaving: boolean;
  onSelectConfig: (configId: string) => void;
  onShowQrChange: (show: boolean) => void;
  onOpacityChange: (opacity: number) => void;
  onFontSizeChange: (fontSize: number) => void;
  onColorHexChange?: ((colorHex: string) => void) | undefined;
  onRotationDegreesChange?: ((degrees: number) => void) | undefined;
  onTemplateTextChange?: ((value: string) => void) | undefined;
  onSaveConfig: () => void;
}

/**
 * Thuật toán: Giao Diện Quản Trị Tham Số Thủy Ấn Pháp Chứng Đầy Đủ (`WatermarkTab`)
 * Hỗ trợ cấu hình toàn bộ trường được API `PATCH /watermarks/configs/:id` tiếp nhận:
 * mẫu văn bản (10 biến), độ mờ `10–90%`, cỡ chữ `8–72px`, góc xoay `-90°..90°`, màu `#RRGGBB` có kiểm tra tương phản và mã QR.
 */
export function WatermarkTab({
  configs,
  activeConfigId,
  showQr,
  opacity,
  fontSize,
  colorHex,
  rotationDegrees,
  templateText,
  previewUsername,
  previewFullName,
  isSaving,
  onSelectConfig,
  onShowQrChange,
  onOpacityChange,
  onFontSizeChange,
  onColorHexChange,
  onRotationDegreesChange,
  onTemplateTextChange,
  onSaveConfig,
}: WatermarkTabProps) {
  const activeConfig = configs.find((c) => c.id === activeConfigId);
  const effectiveTemplate =
    templateText ?? activeConfig?.templateText ?? DEFAULT_WATERMARK_TEMPLATE;
  const effectiveColorHex = colorHex ?? activeConfig?.colorHex ?? DEFAULT_WATERMARK_COLOR_HEX;
  const pickerColorHex = normalizeHexColor(effectiveColorHex);
  const effectiveRotation =
    rotationDegrees ?? activeConfig?.rotationDegrees ?? DEFAULT_WATERMARK_ROTATION;

  const colorInvalid = effectiveColorHex.trim().length > 0 && !isValidHexColor(effectiveColorHex);
  const colorTooLight = !colorInvalid && isWatermarkColorTooLight(effectiveColorHex);
  const missingHighTierQrOrToken = requiresQrOrFullTokenForWatermarkConfig({
    classificationCode: activeConfig?.classificationLevel?.code,
    classificationRank: activeConfig?.classificationLevel?.rank,
    includeQrCode: showQr,
    templateText: effectiveTemplate,
  });

  function appendTemplateVariable(variableToken: string) {
    if (!onTemplateTextChange) return;
    const base = effectiveTemplate.trim();
    const next = base.length > 0 ? `${base} | ${variableToken}` : variableToken;
    onTemplateTextChange(next.slice(0, 250));
  }

  return (
    <div className="grid gap-4 md:grid-cols-2">
      <Card>
        <CardHeader className="pb-3 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
          <CardTitle className="text-sm sm:text-base text-[#222222]">
            Cấu hình watermark bảo mật
          </CardTitle>
          <InteractiveHoverButton
            variant="primary"
            size="sm"
            text={isSaving ? 'Đang lưu…' : 'Lưu cấu hình'}
            icon={<Stamp size={16} strokeWidth={1.75} aria-hidden="true" />}
            onClick={onSaveConfig}
            disabled={
              isSaving ||
              !activeConfigId ||
              colorInvalid ||
              colorTooLight ||
              missingHighTierQrOrToken
            }
            isLoading={isSaving}
            className="shrink-0"
          />
        </CardHeader>
        <CardContent className="space-y-4 text-xs">
          {configs.length > 1 && (
            <div className="space-y-1">
              <label htmlFor="wm-config-select" className="font-medium text-[#222222]">
                Mẫu cấu hình
              </label>
              <select
                id="wm-config-select"
                value={activeConfigId || ''}
                onChange={(e) => onSelectConfig(e.target.value)}
                className="w-full min-h-11 sm:h-9 rounded-full border border-[#dddddd] bg-[#ffffff] px-3 text-xs text-[#222222]"
              >
                {configs.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.name} {c.isDefault ? '(Mặc định)' : ''}
                  </option>
                ))}
              </select>
            </div>
          )}

          <div className="space-y-1.5">
            <label htmlFor="wm-template-text" className="font-medium text-[#222222]">
              Mẫu văn bản watermark
            </label>
            <Input
              id="wm-template-text"
              value={effectiveTemplate}
              maxLength={250}
              readOnly={!onTemplateTextChange}
              onChange={(e) => onTemplateTextChange?.(e.target.value)}
              placeholder={DEFAULT_WATERMARK_TEMPLATE}
              className="min-h-11 sm:h-9 text-xs font-mono"
            />
            <div className="flex flex-wrap gap-1.5 pt-0.5">
              {WATERMARK_TEMPLATE_VARIABLES.map((item) => (
                <button
                  key={item.token}
                  type="button"
                  title={`Chèn ${item.label}`}
                  onClick={() => appendTemplateVariable(item.token)}
                  className="min-h-11 sm:min-h-8 rounded-full border border-[#dddddd] bg-[#f7f7f7] px-2.5 py-0.5 font-mono text-xs text-[#222222] hover:border-[#FF385C] hover:text-[#E31C5F] transition-colors cursor-pointer"
                >
                  {item.token}
                </button>
              ))}
            </div>
            <p className="text-xs text-[#717171]">
              Nhấn vào từng thẻ biến để chèn nhanh. Khuyên dùng dấu <code>|</code> hoặc{' '}
              <code>-</code> ngăn cách để tương thích tuyệt đối phông chữ PDF chuẩn.
            </p>
          </div>

          <div className="flex justify-between items-center pt-1">
            <label htmlFor="wm-qr" className="font-medium text-[#222222]">
              Đính kèm mã QR truy vết
            </label>
            <input
              id="wm-qr"
              type="checkbox"
              checked={showQr}
              onChange={(e) => onShowQrChange(e.target.checked)}
              className="h-5 w-5 rounded border-[#dddddd] bg-[#ffffff] accent-[#FF385C] cursor-pointer"
            />
          </div>

          {missingHighTierQrOrToken && (
            <Alert variant="warning" className="text-xs">
              <AlertTriangle
                size={16}
                strokeWidth={1.75}
                className="shrink-0 text-[#E07912]"
                aria-hidden="true"
              />
              <AlertDescription className="ml-2">
                Cấu hình cho cấp <strong>{activeConfig?.classificationLevel?.name}</strong> bắt buộc
                bật mã QR hoặc chèn biến <code>{'{watermarkToken}'}</code> đầy đủ vào mẫu văn bản.
              </AlertDescription>
            </Alert>
          )}

          <div className="space-y-1.5">
            <div className="flex justify-between">
              <label htmlFor="wm-opacity" className="font-medium text-[#222222]">
                Độ đậm / mờ ({WATERMARK_OPACITY_MIN}–{WATERMARK_OPACITY_MAX}%)
              </label>
              <span className="font-bold text-[#222222]">{opacity}%</span>
            </div>
            <input
              id="wm-opacity"
              type="range"
              min={WATERMARK_OPACITY_MIN}
              max={WATERMARK_OPACITY_MAX}
              value={opacity}
              onChange={(e) => onOpacityChange(Number(e.target.value))}
              className="w-full accent-[#FF385C]"
            />
          </div>

          <div className="space-y-1.5">
            <div className="flex justify-between">
              <label htmlFor="wm-font-size" className="font-medium text-[#222222]">
                Cỡ chữ ({WATERMARK_FONT_SIZE_MIN}–{WATERMARK_FONT_SIZE_MAX}px)
              </label>
              <span className="font-bold text-[#222222]">{fontSize}px</span>
            </div>
            <input
              id="wm-font-size"
              type="range"
              min={WATERMARK_FONT_SIZE_MIN}
              max={WATERMARK_FONT_SIZE_MAX}
              value={fontSize}
              onChange={(e) => onFontSizeChange(Number(e.target.value))}
              className="w-full accent-[#FF385C]"
            />
          </div>

          <div className="space-y-1.5">
            <div className="flex justify-between">
              <label htmlFor="wm-rotation" className="font-medium text-[#222222]">
                Góc xoay ({WATERMARK_ROTATION_MIN}° đến +{WATERMARK_ROTATION_MAX}°)
              </label>
              <span className="font-bold text-[#222222]">{effectiveRotation}°</span>
            </div>
            <input
              id="wm-rotation"
              type="range"
              min={WATERMARK_ROTATION_MIN}
              max={WATERMARK_ROTATION_MAX}
              step={1}
              value={effectiveRotation}
              onChange={(e) => onRotationDegreesChange?.(Number(e.target.value))}
              className="w-full accent-[#FF385C]"
            />
            <div className="flex flex-wrap gap-1.5">
              {WATERMARK_ROTATION_PRESETS.map((angle) => (
                <button
                  key={angle}
                  type="button"
                  onClick={() => onRotationDegreesChange?.(angle)}
                  className={`min-h-11 sm:min-h-8 rounded-full border px-2.5 py-0.5 text-xs font-medium cursor-pointer transition-colors ${
                    effectiveRotation === angle
                      ? 'border-[#FF385C] bg-[#FF385C] text-[#ffffff]'
                      : 'border-[#dddddd] bg-[#ffffff] text-[#222222] hover:border-[#FF385C]'
                  }`}
                >
                  {angle > 0 ? `+${angle}°` : `${angle}°`}
                </button>
              ))}
            </div>
          </div>

          <div className="space-y-1.5">
            <div className="flex items-center justify-between gap-2">
              <label htmlFor="wm-color-hex" className="font-medium text-[#222222]">
                Màu sắc watermark (#RRGGBB)
              </label>
              <label htmlFor="wm-color-picker" className="text-xs text-[#717171]">
                Bảng chọn màu
              </label>
            </div>
            <div className="flex items-center gap-2">
              <input
                id="wm-color-picker"
                type="color"
                value={pickerColorHex}
                onChange={(e) => onColorHexChange?.(e.target.value.toUpperCase())}
                className="h-11 sm:h-9 w-12 shrink-0 rounded-[12px] border border-[#dddddd] bg-[#ffffff] p-1 cursor-pointer"
              />
              <Input
                id="wm-color-hex"
                value={effectiveColorHex}
                maxLength={7}
                onChange={(e) => onColorHexChange?.(e.target.value.toUpperCase())}
                placeholder={DEFAULT_WATERMARK_COLOR_HEX}
                className="min-h-11 sm:h-9 text-xs font-mono"
              />
            </div>
            <div className="flex flex-wrap items-center gap-1.5 pt-0.5">
              {WATERMARK_COLOR_PRESETS.map((preset) => (
                <button
                  key={preset.hex}
                  type="button"
                  onClick={() => onColorHexChange?.(preset.hex)}
                  className={`inline-flex min-h-11 sm:min-h-8 items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs cursor-pointer transition-colors ${
                    effectiveColorHex.toUpperCase() === preset.hex.toUpperCase()
                      ? 'border-[#FF385C] bg-[#f7f7f7] font-semibold text-[#222222]'
                      : 'border-[#dddddd] bg-[#ffffff] text-[#717171] hover:border-[#222222]'
                  }`}
                >
                  <span
                    className={`inline-block h-3 w-3 rounded-full border border-[#dddddd] ${preset.swatchClass}`}
                    aria-hidden="true"
                  />
                  <span>{preset.label}</span>
                </button>
              ))}
            </div>
            {colorInvalid && (
              <p className="text-[#C13515]">
                Mã màu cần đúng định dạng 6 ký tự thập lục phân (ví dụ: <code>#717171</code>).
              </p>
            )}
            {colorTooLight && (
              <p className="text-[#C13515]">
                Màu quá sáng (độ chói &gt; 88%) sẽ không đủ tương phản trên tài liệu nền trắng.
              </p>
            )}
          </div>
        </CardContent>
      </Card>

      <WatermarkPreviewCard
        opacity={opacity}
        fontSize={fontSize}
        colorHex={effectiveColorHex}
        rotationDegrees={effectiveRotation}
        showQr={showQr}
        templateText={effectiveTemplate}
        previewUsername={previewUsername}
        previewFullName={previewFullName}
        classificationLabel={activeConfig?.classificationLevel?.name}
      />
    </div>
  );
}
