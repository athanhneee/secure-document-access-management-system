'use client';

import { QrCode } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { DEFAULT_WATERMARK_TEMPLATE } from '../hooks/use-watermark-settings';

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
  10: 'text-[13px]',
  11: 'text-xs',
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
 * Thuật toán: Lượng Tử Hóa Tĩnh Độ Đậm / Cỡ Chữ & Nội Suy Biến Mẫu Thủy Ấn (`WatermarkPreviewCard`)
 * Mục đích: Tương thích tuyệt đối CSP không `style` nội tuyến và thay thế động các biến `{username}`, `{employeeCode}`, `{documentCode}`, `{timestamp}`, `{shortToken}` từ `templateText`.
 */
function resolveWatermarkPreviewClasses(opacity: number, fontSize: number) {
  const quantizedOpacity = Math.min(80, Math.max(10, Math.round(opacity / 5) * 5));
  const clampedFontSize = Math.min(24, Math.max(10, Math.round(fontSize)));
  return {
    opacityClass: OPACITY_CLASS_MAP[quantizedOpacity] ?? 'opacity-25',
    fontSizeClass: FONT_SIZE_CLASS_MAP[clampedFontSize] ?? 'text-[14px]',
  };
}

function renderWatermarkTemplateLines(
  rawTemplate: string,
  currentUsername?: string | null,
): string[] {
  const sampleValues: Record<string, string> = {
    username: (currentUsername || 'nguyen.vana').toUpperCase(),
    employeeCode: 'EMP-882190',
    documentCode: 'DOC-TOPSECRET-001',
    timestamp: '2026-09-23 12:45:00 UTC',
    shortToken: 'WM-2e59958fa6c7',
  };
  const source = rawTemplate.trim() || DEFAULT_WATERMARK_TEMPLATE;
  const substituted = source.replace(
    /\{(username|employeeCode|documentCode|timestamp|shortToken)\}/gu,
    (_, key: string) => sampleValues[key] ?? key,
  );
  return substituted
    .split(/\s*\|\s*|\r?\n/u)
    .map((line) => line.trim())
    .filter(Boolean);
}

interface WatermarkPreviewCardProps {
  opacity: number;
  fontSize: number;
  showQr: boolean;
  templateText: string;
  previewUsername?: string | null | undefined;
}

export function WatermarkPreviewCard({
  opacity,
  fontSize,
  showQr,
  templateText,
  previewUsername,
}: WatermarkPreviewCardProps) {
  const { opacityClass, fontSizeClass } = resolveWatermarkPreviewClasses(opacity, fontSize);
  const previewLines = renderWatermarkTemplateLines(templateText, previewUsername);

  return (
    <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)] flex flex-col">
      <CardHeader className="pb-3">
        <CardTitle className="text-base text-[#222222]">
          Xem trước trực quan (Live Canvas Preview)
        </CardTitle>
        <CardDescription className="text-xs text-[#717171]">
          Mô phỏng hình ảnh watermark thực thi bởi Watermark Engine
        </CardDescription>
      </CardHeader>
      <CardContent className="flex-1 flex items-center justify-center p-4 sm:p-6">
        <div className="relative w-full aspect-[4/3] rounded-[20px] border border-[#ebebeb] bg-[#ffffff] p-4 shadow-inner overflow-hidden flex flex-col justify-between">
          <div className="space-y-2 opacity-20 pointer-events-none select-none text-[13px] text-[#717171]">
            <div className="h-3 w-1/3 bg-[#dddddd] rounded" />
            <div className="h-2 w-full bg-[#ebebeb] rounded" />
            <div className="h-2 w-5/6 bg-[#ebebeb] rounded" />
            <div className="h-2 w-4/6 bg-[#ebebeb] rounded" />
          </div>

          <div
            className={`absolute inset-0 flex flex-col items-center justify-center pointer-events-none select-none rotate-[-25deg] transition-all px-3 ${opacityClass}`}
          >
            <div
              className={`font-bold text-center text-[#C13515] leading-tight space-y-1 ${fontSizeClass}`}
            >
              {previewLines.map((line, index) => (
                <div
                  key={`${index}-${line}`}
                  className={line.startsWith('WM-') ? 'text-[13px] text-[#008A05]' : undefined}
                >
                  {line}
                </div>
              ))}
            </div>

            {showQr && (
              <QrCode
                size={24}
                strokeWidth={1.75}
                className="mt-2 text-[#C13515]"
                aria-hidden="true"
              />
            )}
          </div>

          <div className="text-[13px] font-bold text-[#717171] text-right">Trang 1 / 1</div>
        </div>
      </CardContent>
    </Card>
  );
}
