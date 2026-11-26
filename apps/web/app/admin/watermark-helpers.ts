/**
 * @module WatermarkHelpers
 * Thuật toán: Chuẩn Hóa Văn Bản Watermark Tương Thích WinAnsi, Nội Suy Đầy Đủ 10 Biến Định Danh,
 * Kiểm Tra Tương Phản Màu WCAG & Lựa Chọn Cấu Hình Mặc Định Bất Biến Thứ Tự CSDL (`watermark-helpers`).
 */

export const DEFAULT_WATERMARK_TEMPLATE =
  'CONFIDENTIAL | {username} ({employeeCode}) | {documentCode} | {timestamp} | {shortToken}';

export const DEFAULT_WATERMARK_COLOR_HEX = '#717171';
export const DEFAULT_WATERMARK_ROTATION = -30;
export const WATERMARK_OPACITY_MIN = 10;
export const WATERMARK_OPACITY_MAX = 90;
export const WATERMARK_FONT_SIZE_MIN = 8;
export const WATERMARK_FONT_SIZE_MAX = 72;
export const WATERMARK_ROTATION_MIN = -90;
export const WATERMARK_ROTATION_MAX = 90;
export const WATERMARK_MAX_LUMINANCE = 0.88;

export interface WatermarkColorPreset {
  hex: string;
  label: string;
  swatchClass: string;
}

export const WATERMARK_COLOR_PRESETS: readonly WatermarkColorPreset[] = [
  { hex: '#717171', label: 'Xám chuẩn', swatchClass: 'bg-[#717171]' },
  { hex: '#222222', label: 'Than chì', swatchClass: 'bg-[#222222]' },
  { hex: '#C13515', label: 'Đỏ mật', swatchClass: 'bg-[#C13515]' },
  { hex: '#E07912', label: 'Cam cảnh báo', swatchClass: 'bg-[#E07912]' },
  { hex: '#008489', label: 'Xanh bảo mật', swatchClass: 'bg-[#008489]' },
  { hex: '#008A05', label: 'Xanh kiểm chứng', swatchClass: 'bg-[#008A05]' },
];

export const WATERMARK_ROTATION_PRESETS = [-45, -30, 0, 30, 45] as const;

export const WATERMARK_TEMPLATE_VARIABLES: ReadonlyArray<{ token: string; label: string }> = [
  { token: '{username}', label: 'Tên đăng nhập' },
  { token: '{fullName}', label: 'Họ và tên' },
  { token: '{employeeCode}', label: 'Mã nhân viên' },
  { token: '{documentCode}', label: 'Mã tài liệu' },
  { token: '{classification}', label: 'Cấp độ mật' },
  { token: '{timestamp}', label: 'Thời điểm UTC' },
  { token: '{utcTimestamp}', label: 'Thời điểm UTC đầy đủ' },
  { token: '{shortToken}', label: 'Mã truy vết ngắn (WM-12hex)' },
  { token: '{token}', label: 'Bí danh mã truy vết ngắn' },
  { token: '{watermarkToken}', label: 'Mã truy vết đầy đủ (48hex)' },
];

/**
 * Thuật toán: Xác Thực Mã Màu `#RRGGBB` & Tính Độ Chói Tương Đối Chuẩn Rec.709 (`computeColorLuminance`)
 * Khớp tuyệt đối công thức chặn màu quá nhạt (`luminance > 0.88`) của `WatermarksService.updateConfig`.
 */
export function isValidHexColor(hex: string): boolean {
  return /^#[0-9A-Fa-f]{6}$/u.test(hex.trim());
}

export function normalizeHexColor(hex: string | undefined | null): string {
  const trimmed = (hex ?? '').trim();
  if (isValidHexColor(trimmed)) return trimmed.toUpperCase();
  return DEFAULT_WATERMARK_COLOR_HEX;
}

export function computeColorLuminance(hex: string): number {
  const trimmed = hex.trim();
  if (!isValidHexColor(trimmed)) return 0.5;
  const body = trimmed.slice(1);
  const r = Number.parseInt(body.slice(0, 2), 16) / 255;
  const g = Number.parseInt(body.slice(2, 4), 16) / 255;
  const b = Number.parseInt(body.slice(4, 6), 16) / 255;
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

export function isWatermarkColorTooLight(hex: string): boolean {
  return isValidHexColor(hex) && computeColorLuminance(hex) > WATERMARK_MAX_LUMINANCE;
}

/**
 * Thuật toán: Phản Chiếu Chính Xác Bộ Chuyển Tự WinAnsi ASCII Của Động Cơ PDF (`toWatermarkPdfSafePreviewText`)
 * Đảm bảo chuỗi hiển thị trên khung xem trước và tệp PDF thật giống nhau 1-1 (không bao giờ biến `·` thành `?`).
 */
export function toWatermarkPdfSafePreviewText(text: string): string {
  return text
    .replace(/[\u00B7\u2022\u2023\u2219\u30FB]/gu, '-')
    .replace(/[\u2013\u2014\u2212]/gu, '-')
    .replace(/[\u2018\u2019\u201A]/gu, "'")
    .replace(/[\u201C\u201D\u201E]/gu, '"')
    .replace(/\u2026/gu, '...')
    .replace(/\u00D7/gu, 'x')
    .replace(/[\u00A0\u202F\u2009\t\r\n]+/gu, ' ')
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/gu, '')
    .replace(/đ/gu, 'd')
    .replace(/Đ/gu, 'D')
    .replace(/[^\x20-\x7E]/gu, '?');
}

export interface WatermarkPreviewRenderOptions {
  username?: string | null | undefined;
  fullName?: string | null | undefined;
  classificationLabel?: string | null | undefined;
  classificationCode?: string | null | undefined;
  classificationRank?: number | null | undefined;
  includeQrCode?: boolean | undefined;
}

/**
 * Thuật toán: Kiểm Tra Mẫu Watermark Bắt Buộc Chứa `{username}` Hoặc `{fullName}` (`hasWatermarkRecipientIdentity`).
 */
export function hasWatermarkRecipientIdentity(templateText: string): boolean {
  return /\{\{?(?:username|fullName)\}?\}/u.test(templateText);
}

/**
 * Thuật toán: Nội Suy Đầy Đủ 10 Biến Định Danh Pháp Chứng Đồng Bộ 1-1 Với `formatForensicWatermarkText` Phía API (`BUG-055`).
 * Nếu mẫu thiếu `{username}`/`{fullName}` thì ghép tiền tố `${fullName} (${employeeCode}) | ` vào trước `substituted` thay vì xóa mất `{watermarkToken}`,
 * và bảo toàn trọn vẹn mã 48-hex không bị cắt cụt bởi `.slice(0, 1000)`.
 */
export function renderWatermarkTemplateText(
  rawTemplate: string,
  options: WatermarkPreviewRenderOptions = {},
): string {
  const username = options.username?.trim() || 'nguyen.vana';
  const fullName = options.fullName?.trim() || 'Nguyễn Văn An';
  const employeeCode = 'NV-001248';
  const documentCode = 'TL-2026-001';
  const utcTimestamp = '2026-11-25 14:30:00 UTC';
  const classification = options.classificationLabel?.trim() || 'CONFIDENTIAL';
  const sampleFullCode = `WM-${'0a0b'.repeat(12)}`;
  const sampleShortCode = `WM-${'0a0b'.repeat(3)}`;

  const source = rawTemplate.trim() || DEFAULT_WATERMARK_TEMPLATE;
  let substituted = source
    .replace(/\{\{(\w+)\}\}/gu, '{$1}')
    .replace(/\{classification\}/gu, classification)
    .replace(/\{fullName\}/gu, fullName)
    .replace(/\{username\}/gu, username)
    .replace(/\{employeeCode\}/gu, employeeCode)
    .replace(/\{documentCode\}/gu, documentCode)
    .replace(/\{timestamp\}/gu, utcTimestamp)
    .replace(/\{utcTimestamp\}/gu, utcTimestamp)
    .replace(/\{watermarkToken\}/gu, sampleFullCode)
    .replace(/\{shortToken\}/gu, sampleShortCode)
    .replace(/\{token\}/gu, sampleShortCode);

  if (!substituted.includes(username) && !substituted.includes(fullName)) {
    substituted =
      substituted.trim().length > 0
        ? `${fullName} (${employeeCode}) | ${substituted}`
        : `${fullName} (${employeeCode}) | ${documentCode} | ${utcTimestamp} | ${sampleShortCode}`;
  }

  const normalizedClassUpper = classification.toUpperCase();
  const isHighClassification =
    (typeof options.classificationRank === 'number' && options.classificationRank >= 3) ||
    options.classificationCode === 'SECRET' ||
    options.classificationCode === 'TOP_SECRET' ||
    normalizedClassUpper === 'SECRET' ||
    normalizedClassUpper === 'TOP_SECRET' ||
    normalizedClassUpper === 'TỐI MẬT' ||
    normalizedClassUpper === 'TUYỆT MẬT';

  const mustPreserveFullToken =
    substituted.includes(sampleFullCode) ||
    (isHighClassification && options.includeQrCode === false);
  if (mustPreserveFullToken && !substituted.includes(sampleFullCode)) {
    substituted = `${substituted} | ${sampleFullCode}`;
  }

  if (substituted.length <= 1000) {
    return substituted;
  }
  if (mustPreserveFullToken) {
    const suffix = ` | ${sampleFullCode}`;
    const withoutToken = substituted
      .split(sampleFullCode)
      .join('')
      .replace(/\s+\|\s*$/u, '')
      .trim();
    const maxHeadLength = Math.max(0, 1000 - suffix.length);
    return `${withoutToken.slice(0, maxHeadLength)}${suffix}`;
  }
  return substituted.slice(0, 1000);
}

/**
 * Thuật toán: Chọn Cấu Hình Watermark Khởi Tạo Ưu Tiên `isDefault` Bất Biến Thứ Tự Hàng CSDL (`selectInitialWatermarkConfig`).
 */
export function selectInitialWatermarkConfig<T extends { id: string; isDefault?: boolean }>(
  loaded: readonly T[],
  prevId?: string | null,
): T | null {
  if (loaded.length === 0) return null;
  if (prevId) {
    const existing = loaded.find((item) => item.id === prevId);
    if (existing) return existing;
  }
  return loaded.find((item) => item.isDefault) ?? loaded[0] ?? null;
}

/**
 * Thuật toán: Kiểm Tra Ràng Buộc Bảo Toàn QR / `{watermarkToken}` Đối Với Bậc Mật `SECRET` / `TOP_SECRET`.
 */
export function requiresQrOrFullTokenForWatermarkConfig(params: {
  classificationCode?: string | null | undefined;
  classificationRank?: number | null | undefined;
  includeQrCode: boolean;
  templateText: string;
}): boolean {
  const isHighTier =
    params.classificationCode === 'SECRET' ||
    params.classificationCode === 'TOP_SECRET' ||
    (typeof params.classificationRank === 'number' && params.classificationRank >= 3);
  if (!isHighTier) return false;
  const hasFullToken = /\{\{?watermarkToken\}?\}/u.test(params.templateText);
  return !params.includeQrCode && !hasFullToken;
}
