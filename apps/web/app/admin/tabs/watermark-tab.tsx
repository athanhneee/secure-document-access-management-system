'use client';

import { Check, QrCode, Stamp } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import type { WatermarkConfigRow } from '../types';

interface WatermarkTabProps {
  configs: WatermarkConfigRow[];
  activeConfigId: string | null;
  showQr: boolean;
  opacity: number;
  fontSize: number;
  isSaving: boolean;
  onSelectConfig: (configId: string) => void;
  onShowQrChange: (show: boolean) => void;
  onOpacityChange: (opacity: number) => void;
  onFontSizeChange: (fontSize: number) => void;
  onSaveConfig: () => void;
}

export function WatermarkTab({
  configs,
  activeConfigId,
  showQr,
  opacity,
  fontSize,
  isSaving,
  onSelectConfig,
  onShowQrChange,
  onOpacityChange,
  onFontSizeChange,
  onSaveConfig,
}: WatermarkTabProps) {
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
                className="w-full h-8 rounded-full border border-[#dddddd] bg-[#ffffff] px-3 text-xs text-[#222222]"
              >
                {configs.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.name} {c.isDefault ? '(Mặc định)' : ''}
                  </option>
                ))}
              </select>
            </div>
          )}

          <div className="space-y-2">
            <span className="font-medium text-[#222222] block">
              Thành phần bắt buộc trên watermark:
            </span>
            <div className="rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-3 space-y-1.5 font-bold text-[11px] text-[#717171]">
              <div className="flex items-center gap-2 text-[#008A05]">
                <Check size={16} strokeWidth={1.75} className="shrink-0" aria-hidden="true" />
                <span>Họ tên đầy đủ & Mã định danh nhân viên (Employee Code)</span>
              </div>
              <div className="flex items-center gap-2 text-[#008A05]">
                <Check size={16} strokeWidth={1.75} className="shrink-0" aria-hidden="true" />
                <span>Thời điểm tạo phiên xem / tải (UTC Timestamp)</span>
              </div>
              <div className="flex items-center gap-2 text-[#008A05]">
                <Check size={16} strokeWidth={1.75} className="shrink-0" aria-hidden="true" />
                <span>Mã tài liệu & Mã token ngẫu nhiên CSPRNG (WM-...)</span>
              </div>
            </div>
          </div>

          <div className="space-y-2">
            <div className="flex justify-between items-center">
              <label htmlFor="wm-qr" className="font-medium text-[#222222]">
                Đính kèm mã QR truy vết:
              </label>
              <input
                id="wm-qr"
                type="checkbox"
                checked={showQr}
                onChange={(e) => onShowQrChange(e.target.checked)}
                className="h-4 w-4 rounded border-[#dddddd] bg-[#ffffff] accent-[#FF385C]"
              />
            </div>
          </div>

          <div className="space-y-2">
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

          <div className="space-y-2">
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

      <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)] flex flex-col">
        <CardHeader className="pb-3">
          <CardTitle className="text-base text-[#222222]">
            Xem trước trực quan (Live Canvas Preview)
          </CardTitle>
          <CardDescription className="text-xs text-[#717171]">
            Mô phỏng hình ảnh watermark thực thi bởi Watermark Engine
          </CardDescription>
        </CardHeader>
        <CardContent className="flex-1 flex items-center justify-center p-6">
          <div className="relative w-full aspect-[4/3] rounded-[20px] border border-[#ebebeb] bg-[#ffffff] p-4 shadow-inner overflow-hidden flex flex-col justify-between">
            <div className="space-y-2 opacity-20 pointer-events-none select-none text-[10px] text-[#717171]">
              <div className="h-3 w-1/3 bg-[#dddddd] rounded" />
              <div className="h-2 w-full bg-[#ebebeb] rounded" />
              <div className="h-2 w-5/6 bg-[#ebebeb] rounded" />
              <div className="h-2 w-4/6 bg-[#ebebeb] rounded" />
              <div className="h-2 w-full bg-[#ebebeb] rounded" />
            </div>

            <div
              className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none select-none rotate-[-25deg] transition-all"
              style={{ opacity: opacity / 100 }}
            >
              <div
                className="font-bold text-center text-[#C13515] leading-tight space-y-1"
                style={{ fontSize: `${fontSize}px` }}
              >
                <div>NGUYEN VAN A · EMP-882190</div>
                <div>DOC-TOPSECRET-001 · 2026-09-23 12:45:00 UTC</div>
                <div className="text-[10px] text-[#008A05]">WM-8f3a9b2c1e7d4410</div>
              </div>

              {showQr && (
                // CONFLICT-RESOLVED: Loại bỏ hộp khung nền/viền bọc quanh icon QrCode và giới hạn kích thước chuẩn tối đa 24px theo rules/ui-design-system.md.
                <QrCode
                  size={24}
                  strokeWidth={1.75}
                  className="mt-2 text-[#C13515]"
                  aria-hidden="true"
                />
              )}
            </div>

            <div className="text-[10px] font-bold text-[#b0b0b0] text-right">Trang 1 / 1</div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
