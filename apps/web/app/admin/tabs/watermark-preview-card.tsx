'use client';

import { useEffect, useMemo, useRef } from 'react';
import { QrCode } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import {
  DEFAULT_WATERMARK_COLOR_HEX,
  DEFAULT_WATERMARK_ROTATION,
  normalizeHexColor,
  renderWatermarkTemplateText,
  toWatermarkPdfSafePreviewText,
} from '../watermark-helpers';

const CANVAS_WIDTH = 640;
const CANVAS_HEIGHT = 480;

interface WatermarkPreviewCardProps {
  opacity: number;
  fontSize: number;
  colorHex?: string | undefined;
  rotationDegrees?: number | undefined;
  showQr: boolean;
  templateText: string;
  previewUsername?: string | null | undefined;
  previewFullName?: string | null | undefined;
  classificationLabel?: string | null | undefined;
}

/**
 * Thuật toán: Kết Xuất Trực Tiếp Canvas Thủy Ấn Pháp Chứng Đồng Bộ 1-1 Với Động Cơ PDF (`WatermarkPreviewCard`)
 * Mục đích: Phản ánh trung thực màu sắc `colorHex`, góc xoay `rotationDegrees` (cùng chiều tọa độ `pdf-lib`),
 * cỡ chữ tuyến tính `8–72px` không nghịch đảo, độ mờ `10–90%`, dải `[SECURE-DOC]` đầu/cuối trang, mã QR góc phải dưới
 * và 10 biến định danh sau chuyển tự WinAnsi ASCII — hoàn toàn không sử dụng thuộc tính `style={{}}` nội tuyến.
 */
export function WatermarkPreviewCard({
  opacity,
  fontSize,
  colorHex = DEFAULT_WATERMARK_COLOR_HEX,
  rotationDegrees = DEFAULT_WATERMARK_ROTATION,
  showQr,
  templateText,
  previewUsername,
  previewFullName,
  classificationLabel,
}: WatermarkPreviewCardProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const safeColorHex = normalizeHexColor(colorHex);
  const clampedOpacity = Math.min(90, Math.max(10, Math.round(opacity)));
  const clampedFontSize = Math.min(72, Math.max(8, Math.round(fontSize)));
  const clampedRotation = Math.min(90, Math.max(-90, Math.round(rotationDegrees)));

  const renderedRawText = useMemo(
    () =>
      renderWatermarkTemplateText(templateText, {
        username: previewUsername,
        fullName: previewFullName,
        classificationLabel,
      }),
    [templateText, previewUsername, previewFullName, classificationLabel],
  );
  const pdfSafeText = useMemo(
    () => toWatermarkPdfSafePreviewText(renderedRawText),
    [renderedRawText],
  );
  const hasAsciiFolding = renderedRawText !== pdfSafeText;

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const dpr = typeof window !== 'undefined' ? Math.min(window.devicePixelRatio || 1, 2) : 1;
    canvas.width = CANVAS_WIDTH * dpr;
    canvas.height = CANVAS_HEIGHT * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    // 1. Nền trang tài liệu giả lập
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, CANVAS_WIDTH, CANVAS_HEIGHT);

    // Khung văn bản mẫu mô phỏng tài liệu PDF
    ctx.fillStyle = '#ebebeb';
    ctx.fillRect(36, 48, 190, 14);
    const bodyLineWidths = [560, 520, 540, 470, 550, 490, 530, 420];
    bodyLineWidths.forEach((lineWidth, idx) => {
      ctx.fillStyle = idx % 3 === 0 ? '#dddddd' : '#f7f7f7';
      ctx.fillRect(36, 82 + idx * 34, lineWidth, 10);
    });

    // 2. Dải cảnh báo đầu & cuối trang [SECURE-DOC] khớp watermark-engine.service.ts
    const bannerText = `[SECURE-DOC] ${pdfSafeText}`;
    ctx.save();
    ctx.globalAlpha = 0.72;
    ctx.fillStyle = '#717171';
    ctx.font = '700 9px Inter, Helvetica, Arial, sans-serif';
    ctx.textBaseline = 'top';
    ctx.fillText(bannerText, 20, 12, CANVAS_WIDTH - 40);
    ctx.textBaseline = 'bottom';
    ctx.fillText(bannerText, 20, CANVAS_HEIGHT - 10, CANVAS_WIDTH - 92);
    ctx.restore();

    // 3. Lưới văn bản watermark xoay đúng góc (đảo dấu sang hệ tọa độ Y xuống dưới của Canvas để khớp góc pdf-lib)
    const canvasRadians = (-clampedRotation * Math.PI) / 180;
    const scaledFontPx = Math.max(8, Math.min(72, clampedFontSize));
    const displayLines = pdfSafeText
      .split(/\s*\|\s*/u)
      .map((part) => part.trim())
      .filter(Boolean);
    const lineHeight = Math.round(scaledFontPx * 1.28);

    ctx.save();
    ctx.globalAlpha = clampedOpacity / 100;
    ctx.fillStyle = safeColorHex;
    ctx.font = `700 ${scaledFontPx}px Helvetica, Arial, sans-serif`;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';

    const gridPoints: Array<[number, number]> = [
      [CANVAS_WIDTH * 0.5, CANVAS_HEIGHT * 0.5],
      [CANVAS_WIDTH * 0.24, CANVAS_HEIGHT * 0.25],
      [CANVAS_WIDTH * 0.76, CANVAS_HEIGHT * 0.74],
    ];
    for (const [cx, cy] of gridPoints) {
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(canvasRadians);
      if (displayLines.length <= 2) {
        ctx.fillText(pdfSafeText, 0, 0, CANVAS_WIDTH * 0.88);
      } else {
        const startY = -((displayLines.length - 1) * lineHeight) / 2;
        displayLines.forEach((line, idx) => {
          ctx.fillText(line, 0, startY + idx * lineHeight, CANVAS_WIDTH * 0.82);
        });
      }
      ctx.restore();
    }
    ctx.restore();

    // 4. Mã QR góc phải dưới khớp watermark-engine.service.ts (45pt trên PDF)
    if (showQr) {
      const qrSize = 54;
      const qrX = CANVAS_WIDTH - qrSize - 18;
      const qrY = CANVAS_HEIGHT - qrSize - 24;
      ctx.save();
      ctx.globalAlpha = 0.85;
      ctx.fillStyle = '#ffffff';
      ctx.fillRect(qrX - 4, qrY - 4, qrSize + 8, qrSize + 8);
      ctx.strokeStyle = '#dddddd';
      ctx.lineWidth = 1;
      ctx.strokeRect(qrX - 4, qrY - 4, qrSize + 8, qrSize + 8);

      const cell = 6;
      const pattern = [
        '111110101',
        '100010010',
        '101010111',
        '100010001',
        '111110101',
        '000000110',
        '101101011',
        '010010100',
        '111011011',
      ];
      ctx.fillStyle = '#222222';
      pattern.forEach((row, r) => {
        for (let c = 0; c < row.length; c += 1) {
          if (row[c] === '1') {
            ctx.fillRect(qrX + c * cell, qrY + r * cell, cell - 1, cell - 1);
          }
        }
      });
      ctx.restore();
    }
  }, [pdfSafeText, safeColorHex, clampedOpacity, clampedFontSize, clampedRotation, showQr]);

  return (
    <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)] flex flex-col">
      <CardHeader className="pb-3">
        <CardTitle className="text-base text-[#222222]">Xem trước watermark</CardTitle>
        <CardDescription className="text-xs text-[#717171]">
          Mô phỏng 1-1 màu sắc, góc xoay, cỡ chữ, độ mờ và chuỗi WinAnsi ASCII in trên tệp PDF thật.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex-1 flex flex-col justify-between gap-3 p-4 sm:p-6 pt-2">
        <div className="relative w-full aspect-[4/3] rounded-[20px] border border-[#ebebeb] bg-[#ffffff] shadow-inner overflow-hidden">
          <canvas
            ref={canvasRef}
            width={CANVAS_WIDTH}
            height={CANVAS_HEIGHT}
            aria-label={`Xem trước watermark: ${pdfSafeText}`}
            className="w-full h-full block"
          >
            {`Xem trước watermark: ${pdfSafeText}`}
          </canvas>
          <div className="absolute bottom-2 right-3 text-xs font-semibold text-[#717171] pointer-events-none select-none">
            Trang 1 / 1
          </div>
        </div>

        <div className="rounded-[14px] border border-[#ebebeb] bg-[#f7f7f7] p-3 space-y-2 text-xs">
          <div className="flex flex-wrap items-center gap-1.5">
            <Badge variant="outline" className="font-mono">
              Màu: {safeColorHex}
            </Badge>
            <Badge variant="outline">Góc: {clampedRotation}°</Badge>
            <Badge variant="outline">Cỡ chữ: {clampedFontSize}px</Badge>
            <Badge variant="outline">Độ mờ: {clampedOpacity}%</Badge>
            <Badge variant={showQr ? 'success' : 'secondary'}>
              <QrCode size={16} strokeWidth={1.75} className="mr-1" aria-hidden="true" />
              {showQr ? 'Có QR góc phải' : 'Không gắn QR'}
            </Badge>
          </div>
          <div className="space-y-0.5">
            <span className="font-semibold text-[#222222] block">
              Chuỗi in thực tế trên PDF (WinAnsi ASCII):
            </span>
            <p className="font-mono text-[#717171] break-all">{pdfSafeText}</p>
            {hasAsciiFolding && (
              <p className="text-[#E07912]">
                Lưu ý: Dấu tiếng Việt và ký hiệu đặc biệt (như <code>·</code>, <code>—</code>) tự
                động chuyển sang ký tự ASCII an toàn để tương thích phông Helvetica chuẩn của PDF.
              </p>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
