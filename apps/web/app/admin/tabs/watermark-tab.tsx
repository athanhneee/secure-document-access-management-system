'use client';

import { Check, Stamp } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { DEFAULT_WATERMARK_TEMPLATE } from '../hooks/use-watermark-settings';
import type { WatermarkConfigRow } from '../types';
import { WatermarkPreviewCard } from './watermark-preview-card';

interface WatermarkTabProps {
  configs: WatermarkConfigRow[];
  activeConfigId: string | null;
  showQr: boolean;
  opacity: number;
  fontSize: number;
  templateText?: string | undefined;
  previewUsername?: string | null | undefined;
  isSaving: boolean;
  onSelectConfig: (configId: string) => void;
  onShowQrChange: (show: boolean) => void;
  onOpacityChange: (opacity: number) => void;
  onFontSizeChange: (fontSize: number) => void;
  onTemplateTextChange?: ((value: string) => void) | undefined;
  onSaveConfig: () => void;
}

export function WatermarkTab({
  configs,
  activeConfigId,
  showQr,
  opacity,
  fontSize,
  templateText,
  previewUsername,
  isSaving,
  onSelectConfig,
  onShowQrChange,
  onOpacityChange,
  onFontSizeChange,
  onTemplateTextChange,
  onSaveConfig,
}: WatermarkTabProps) {
  const activeConfig = configs.find((c) => c.id === activeConfigId);
  const effectiveTemplate =
    templateText ?? activeConfig?.templateText ?? DEFAULT_WATERMARK_TEMPLATE;

  return (
    <div className="grid gap-6 md:grid-cols-2">
      <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)]">
        <CardHeader className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
          <div>
            <CardTitle className="text-base text-[#222222]">Cấu hình Watermark động</CardTitle>
            <CardDescription className="text-xs text-[#717171]">
              Thiết lập các thành phần đóng dấu bản quyền và lưu trực tiếp lên máy chủ
            </CardDescription>
          </div>
          <InteractiveHoverButton
            variant="primary"
            size="sm"
            text={isSaving ? 'Đang lưu...' : 'Lưu lên Server'}
            icon={<Stamp size={16} strokeWidth={1.75} aria-hidden="true" />}
            onClick={onSaveConfig}
            disabled={isSaving || !activeConfigId}
            isLoading={isSaving}
          />
        </CardHeader>
        <CardContent className="space-y-4 text-xs">
          {configs.length > 1 && (
            <div className="space-y-1">
              <label htmlFor="wm-config-select" className="font-medium text-[#222222]">
                Chọn mẫu cấu hình:
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

          <div className="space-y-1">
            <label htmlFor="wm-template-text" className="font-medium text-[#222222]">
              Mẫu văn bản thủy vân (`templateText`):
            </label>
            <Input
              id="wm-template-text"
              value={effectiveTemplate}
              readOnly={!onTemplateTextChange}
              onChange={(e) => onTemplateTextChange?.(e.target.value)}
              placeholder="{username} · {employeeCode} | {documentCode} · {timestamp} | {shortToken}"
              className="min-h-11 sm:h-9 text-xs font-mono"
            />
            <p className="text-[13px] text-[#717171]">
              Biến hỗ trợ: <code>{'{username}'}</code>, <code>{'{employeeCode}'}</code>,{' '}
              <code>{'{documentCode}'}</code>, <code>{'{timestamp}'}</code>,{' '}
              <code>{'{shortToken}'}</code>
            </p>
          </div>

          <div className="rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-3 space-y-1.5 font-bold text-xs text-[#008A05]">
            <div className="flex items-center gap-2">
              <Check size={16} strokeWidth={1.75} className="shrink-0" aria-hidden="true" />
              <span>Họ tên đầy đủ, Mã nhân viên &amp; Thời điểm tạo phiên (UTC)</span>
            </div>
            <div className="flex items-center gap-2">
              <Check size={16} strokeWidth={1.75} className="shrink-0" aria-hidden="true" />
              <span>Mã tài liệu &amp; Mã token ngẫu nhiên CSPRNG (WM-...)</span>
            </div>
          </div>

          <div className="flex justify-between items-center">
            <label htmlFor="wm-qr" className="font-medium text-[#222222]">
              Đính kèm mã QR truy vết:
            </label>
            <input
              id="wm-qr"
              type="checkbox"
              checked={showQr}
              onChange={(e) => onShowQrChange(e.target.checked)}
              className="h-5 w-5 rounded border-[#dddddd] bg-[#ffffff] accent-[#FF385C] cursor-pointer"
            />
          </div>

          <div className="space-y-1.5">
            <div className="flex justify-between">
              <label htmlFor="wm-opacity" className="font-medium text-[#222222]">
                Độ đậm / mờ (Opacity):
              </label>
              <span className="font-bold text-[#222222]">{opacity}%</span>
            </div>
            <input
              id="wm-opacity"
              type="range"
              min="10"
              max="80"
              value={opacity}
              onChange={(e) => onOpacityChange(Number(e.target.value))}
              className="w-full accent-[#FF385C]"
            />
          </div>

          <div className="space-y-1.5">
            <div className="flex justify-between">
              <label htmlFor="wm-font-size" className="font-medium text-[#222222]">
                Cỡ chữ (Font size):
              </label>
              <span className="font-bold text-[#222222]">{fontSize}px</span>
            </div>
            <input
              id="wm-font-size"
              type="range"
              min="10"
              max="24"
              value={fontSize}
              onChange={(e) => onFontSizeChange(Number(e.target.value))}
              className="w-full accent-[#FF385C]"
            />
          </div>
        </CardContent>
      </Card>

      <WatermarkPreviewCard
        opacity={opacity}
        fontSize={fontSize}
        showQr={showQr}
        templateText={effectiveTemplate}
        previewUsername={previewUsername}
      />
    </div>
  );
}
