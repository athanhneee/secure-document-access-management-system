import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { describe, it } from 'node:test';
import {
  DEFAULT_WATERMARK_TEMPLATE,
  isValidHexColor,
  isWatermarkColorTooLight,
  renderWatermarkTemplateText,
  requiresQrOrFullTokenForWatermarkConfig,
  selectInitialWatermarkConfig,
  toWatermarkPdfSafePreviewText,
  WATERMARK_FONT_SIZE_MAX,
  WATERMARK_FONT_SIZE_MIN,
  WATERMARK_OPACITY_MAX,
  WATERMARK_OPACITY_MIN,
} from '../../apps/web/app/admin/watermark-helpers.ts';

describe('Admin Watermark Configuration, WinAnsi Preview & Default Selection Contracts', () => {
  it('uses ASCII-safe default template (no middle dot ·) and mirrors backend WinAnsi folding without producing ?', () => {
    assert.ok(!DEFAULT_WATERMARK_TEMPLATE.includes('·'));
    assert.match(DEFAULT_WATERMARK_TEMPLATE, /^[\x20-\x7E]+$/u);

    const folded = toWatermarkPdfSafePreviewText('Nguyễn Quản Trị · NV-001 | Tuyệt mật — Trang 1…');
    assert.equal(folded, 'Nguyen Quan Tri - NV-001 | Tuyet mat - Trang 1...');
    assert.ok(!folded.includes('?'));
  });

  it('interpolates all 10 backend watermark variables including extended placeholders and double braces', () => {
    const rendered = renderWatermarkTemplateText(
      '{{classification}} | {fullName} ({username}/{employeeCode}) | {documentCode} | {timestamp} | {utcTimestamp} | {shortToken} | {token} | {watermarkToken}',
      {
        username: 'qa.admin',
        fullName: 'Nguyễn Quản Trị',
        classificationLabel: 'Tuyệt mật',
      },
    );

    assert.ok(rendered.includes('Tuyệt mật'));
    assert.ok(rendered.includes('Nguyễn Quản Trị'));
    assert.ok(rendered.includes('qa.admin'));
    assert.ok(rendered.includes('NV-001248'));
    assert.ok(rendered.includes('TL-2026-001'));
    assert.ok(rendered.includes('2026-11-25 14:30:00 UTC'));
    assert.ok(rendered.includes('WM-2e59958fa6c7'));
    assert.ok(rendered.includes('WM-2e59958fa6c79a41b8d0e3f21a5c7e904b6d8f12c3e5a7b9'));

    // Identity fallback if template omits both {username} and {fullName}
    const fallback = renderWatermarkTemplateText('CONFIDENTIAL | {documentCode}', {
      username: 'qa.reader',
      fullName: 'Lê Đọc Giả',
    });
    assert.ok(fallback.includes('Lê Đọc Giả'));
  });

  it('selects isDefault config on initial load regardless of DB row order while preserving existing selection', () => {
    const configs = [
      { id: '2', name: 'SECRET', isDefault: false },
      { id: '3', name: 'TOP_SECRET', isDefault: false },
      { id: '1', name: 'Mặc định toàn hệ thống', isDefault: true },
    ];

    assert.equal(selectInitialWatermarkConfig(configs)?.id, '1');
    assert.equal(selectInitialWatermarkConfig(configs, '3')?.id, '3');
    assert.equal(selectInitialWatermarkConfig(configs, '999')?.id, '1');
    assert.equal(
      selectInitialWatermarkConfig([{ id: '9', name: 'Only', isDefault: false }])?.id,
      '9',
    );
    assert.equal(selectInitialWatermarkConfig([]), null);
  });

  it('enforces hex color contrast guard (luminance <= 0.88) and SECRET/TOP_SECRET QR integrity', () => {
    assert.equal(isValidHexColor('#808080'), true);
    assert.equal(isValidHexColor('#991B1B'), true);
    assert.equal(isValidHexColor('invalid'), false);
    assert.equal(isWatermarkColorTooLight('#FFFFFF'), true);
    assert.equal(isWatermarkColorTooLight('#F5F5F5'), true);
    assert.equal(isWatermarkColorTooLight('#808080'), false);
    assert.equal(isWatermarkColorTooLight('#991B1B'), false);
    assert.equal(isWatermarkColorTooLight('#7F1D1D'), false);

    assert.equal(
      requiresQrOrFullTokenForWatermarkConfig({
        classificationCode: 'TOP_SECRET',
        classificationRank: 4,
        includeQrCode: false,
        templateText: '{username} | {shortToken}',
      }),
      true,
    );
    assert.equal(
      requiresQrOrFullTokenForWatermarkConfig({
        classificationCode: 'TOP_SECRET',
        classificationRank: 4,
        includeQrCode: false,
        templateText: '{username} | {watermarkToken}',
      }),
      false,
    );
    assert.equal(
      requiresQrOrFullTokenForWatermarkConfig({
        classificationCode: 'INTERNAL',
        classificationRank: 1,
        includeQrCode: false,
        templateText: '{username} | {shortToken}',
      }),
      false,
    );

    assert.equal(WATERMARK_OPACITY_MIN, 10);
    assert.equal(WATERMARK_OPACITY_MAX, 90);
    assert.equal(WATERMARK_FONT_SIZE_MIN, 8);
    assert.equal(WATERMARK_FONT_SIZE_MAX, 72);
  });

  it('exposes colorHex & rotationDegrees controls in WatermarkTab and live canvas rendering without 10px->13px bug in WatermarkPreviewCard', async () => {
    const [tabSrc, previewSrc, hookSrc] = await Promise.all([
      readFile(new URL('../../apps/web/app/admin/tabs/watermark-tab.tsx', import.meta.url), 'utf8'),
      readFile(
        new URL('../../apps/web/app/admin/tabs/watermark-preview-card.tsx', import.meta.url),
        'utf8',
      ),
      readFile(
        new URL('../../apps/web/app/admin/hooks/use-watermark-settings.ts', import.meta.url),
        'utf8',
      ),
    ]);

    assert.match(tabSrc, /id="wm-color-picker"/u);
    assert.match(tabSrc, /id="wm-color-hex"/u);
    assert.match(tabSrc, /id="wm-rotation"/u);
    assert.match(tabSrc, /WATERMARK_OPACITY_MAX/u);
    assert.match(tabSrc, /WATERMARK_FONT_SIZE_MAX/u);
    assert.doesNotMatch(previewSrc, /10:\s*'text-\[13px\]'/u);
    assert.doesNotMatch(previewSrc, /rotate-\[-25deg\]/u);
    assert.match(previewSrc, /<canvas/u);
    assert.match(previewSrc, /ctx\.rotate\(canvasRadians\)/u);
    assert.match(previewSrc, /ctx\.fillStyle = safeColorHex/u);
    assert.match(hookSrc, /selectInitialWatermarkConfig/u);
    assert.match(hookSrc, /colorHex:\s*trimmedColor/u);
    assert.match(hookSrc, /rotationDegrees:\s*Math\.round\(rotationDegrees\)/u);
  });
});
