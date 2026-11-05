'use client';

import { Check, QrCode, Stamp } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import type { WatermarkConfigRow } from '../types';

const OPACITY_CLASS_MAP: Record<number, string> = {
  10: 'opacity-10',
  15: 'opacity-15',
  20: 'opacity-20',
  25: 'opacity-25',
  30: 'opacity-30',
  35: 'opacity-35',
  40: 'opacity-40',
  45: 'opacity-45',
  50: 'opacity-50',
  55: 'opacity-55',
  60: 'opacity-60',
  65: 'opacity-65',
  70: 'opacity-70',
  75: 'opacity-75',
  80: 'opacity-80',
};

const FONT_SIZE_CLASS_MAP: Record<number, string> = {
  10: 'text-[10px]',
  11: 'text-[11px]',
  12: 'text-[12px]',
  13: 'text-[13px]',
  14: 'text-[14px]',
  15: 'text-[15px]',
  16: 'text-[16px]',
  17: 'text-[17px]',
  18: 'text-[18px]',
  19: 'text-[19px]',
  20: 'text-[20px]',
  21: 'text-[21px]',
  22: 'text-[22px]',
  23: 'text-[23px]',
  24: 'text-[24px]',
};

/**
 * Thuật toán: Lượng Tử Hóa Tĩnh Độ Đậm & Cỡ Chữ Thủy Ấn Tương Thích CSP Nonce (`resolveWatermarkPreviewClasses`)
 * Mục đích: Ánh xạ thông số thanh trượt sang các lớp tiện ích Tailwind v4 tĩnh mà không sinh thuộc tính `style` nội tuyến bị chặn bởi CSP.
 * Cơ chế hoạt động: Làm tròn `opacity` theo bội số 5 trong miền `[10, 80]` và kẹp `fontSize` nguyên trong miền `[10, 24]` để tra cứu `O(1)`.
 */
function resolveWatermarkPreviewClasses(opacity: number, fontSize: number) {
  // CONFLICT-RESOLVED: Thay thế thuộc tính style nội tuyến bằng bảng ánh xạ lớp tĩnh Tailwind v4 nhằm tuân thủ tuyệt đối CSP style-src không cho phép mã nội tuyến.
  const quantizedOpacity = Math.min(80, Math.max(10, Math.round(opacity / 5) * 5));
  const clampedFontSize = Math.min(24, Math.max(10, Math.round(fontSize)));
  return {
    opacityClass: OPACITY_CLASS_MAP[quantizedOpacity] ?? 'opacity-25',
    fontSizeClass: FONT_SIZE_CLASS_MAP[clampedFontSize] ?? 'text-[14px]',
  };
}

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
  const { opacityClass, fontSizeClass } = resolveWatermarkPreviewClasses(opacity, fontSize);

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
              className={`absolute inset-0 flex flex-col items-center justify-center pointer-events-none select-none rotate-[-25deg] transition-all ${opacityClass}`}
            >
              <div
                className={`font-bold text-center text-[#C13515] leading-tight space-y-1 ${fontSizeClass}`}
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
