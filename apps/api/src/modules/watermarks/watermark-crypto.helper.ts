/**
 * Module: WatermarkCryptoHelper — Sinh mã thủy vân ngẫu nhiên mật mã CSPRNG, chuẩn hóa văn bản WinAnsi, nội suy mẫu định danh và phân giải cấu hình thủy vân phân cấp.
 */
import crypto from 'node:crypto';
import QRCode from 'qrcode';
import type { getDatabaseClient } from '@sda/database';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export interface WatermarkUserData {
  id: bigint;
  username: string;
  fullName?: string | null | undefined;
  employeeCode?: string | null | undefined;
}

export interface WatermarkDocumentData {
  id: string;
  documentCode?: string | null | undefined;
  title: string;
  classificationName?: string | undefined;
  requireWatermark: boolean;
}

export interface WatermarkConfigData {
  id: bigint;
  template_text: string;
  opacity_percent: number;
  rotation_degrees: number;
  font_size: number;
  color_hex: string;
  include_qr_code: boolean;
  is_visible: boolean;
}

export interface WatermarkResult {
  watermarkedBuffer: Buffer;
  watermarkToken: string;
  outputSha256Hash: string;
  renderedText: string;
  pageCount: number;
}

/**
 * Thuật toán: Sinh mã token thủy vân pháp y 192-bit bằng CSPRNG (`WM-<48-hex>`)
 * Mục đích: Đảm bảo xác suất trùng lặp hoặc đoán trước mã thủy vân là không khả thi về mặt tính toán ($2^{-192}$).
 * Cơ chế hoạt động:
 *   - Đọc 24 byte từ nguồn entropy hệ điều hành `crypto.randomBytes(24)` và mã hóa thập lục phân gắn tiền tố `WM-`.
 *
 * Algorithm: 192-Bit CSPRNG Forensic Watermark Token Generation.
 * Produces `WM-<48-hex-chars>` using `crypto.randomBytes(24)`.
 */
export function generateCryptographicWatermarkToken(): string {
  return `WM-${crypto.randomBytes(24).toString('hex')}`;
}

/**
 * Thuật toán: Gấp dấu tiếng Việt Unicode NFD sang tập ký tự in ASCII tương thích WinAnsi
 * Mục đích: Đảm bảo `pdf-lib` nhúng phông chuẩn `Helvetica` không bao giờ ném lỗi mã hóa với tên người dùng tiếng Việt.
 * Cơ chế hoạt động:
 *   - Chuẩn hóa `NFD`, loại bỏ dấu tổ hợp `[\u0300-\u036f]`, ánh xạ `đ/Đ -> d/D` và thay ký tự ngoài `[\x20-\x7E]` bằng `?`.
 *
 * Algorithm: Unicode NFD Diacritic Folding to WinAnsi Printable ASCII.
 * Strips combining diacritical marks, maps Vietnamese `đ/Đ` -> `d/D`, and replaces
 * out-of-range glyphs with `?` so `pdf-lib` StandardFonts never throw encoding errors.
 */
export function toWinAnsiSafeText(text: string): string {
  return text
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/gu, '')
    .replace(/đ/gu, 'd')
    .replace(/Đ/gu, 'D')
    .replace(/[^\x20-\x7E]/gu, '?');
}

/**
 * Algorithm: Hexadecimal RGB Color Normalization (`#RRGGBB` -> `[0, 1]^3`).
 */
export function parseHexColor(hex: string): { r: number; g: number; b: number } {
  const clean = hex.replace('#', '');
  if (clean.length === 6) {
    const r = parseInt(clean.substring(0, 2), 16) / 255;
    const g = parseInt(clean.substring(2, 4), 16) / 255;
    const b = parseInt(clean.substring(4, 6), 16) / 255;
    return { r: isNaN(r) ? 0.5 : r, g: isNaN(g) ? 0.5 : g, b: isNaN(b) ? 0.5 : b };
  }
  return { r: 0.5, g: 0.5, b: 0.5 };
}

/**
 * Algorithm: Forensic Identity Template Interpolation with Attribution Guardrail.
 * Replaces placeholders (`{fullName}`, `{employeeCode}`, `{documentCode}`, `{utcTimestamp}`, `{shortToken}`)
 * and enforces fallback composite attribution if the template omits user identity placeholders.
 */
export function formatForensicWatermarkText(
  template: string,
  user: WatermarkUserData,
  document: WatermarkDocumentData,
  token: string,
  now: Date = new Date(),
): string {
  const fullName = user.fullName?.trim() || user.username;
  const employeeCode = user.employeeCode?.trim() || `UID:${user.id.toString()}`;
  const documentCode = document.documentCode?.trim() || document.id.slice(0, 8);
  const utcTimestamp = now.toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
  const classification = document.classificationName || 'CONFIDENTIAL';
  const shortToken = token.replace(/^WM-/, '').slice(0, 12);

  let text = template
    .replace(/\{\{(\w+)\}\}/g, '{$1}')
    .replace(/{classification}/g, classification)
    .replace(/{fullName}/g, fullName)
    .replace(/{username}/g, user.username)
    .replace(/{employeeCode}/g, employeeCode)
    .replace(/{documentCode}/g, documentCode)
    .replace(/{timestamp}/g, utcTimestamp)
    .replace(/{utcTimestamp}/g, utcTimestamp)
    .replace(/{shortToken}/g, shortToken)
    .replace(/{token}/g, shortToken);

  if (!text.includes(user.username) && !text.includes(fullName)) {
    text = `${fullName} (${employeeCode}) | ${documentCode} | ${utcTimestamp} | ${shortToken}`;
  }

  return text;
}

/**
 * Algorithm: Error-Correction-Level-M PNG QR Code Encoding.
 */
export async function renderQrCodePngBuffer(payload: string): Promise<Buffer> {
  return QRCode.toBuffer(payload, {
    type: 'png',
    width: 90,
    margin: 1,
    errorCorrectionLevel: 'M',
  });
}

/**
 * Thuật toán: Phân giải phân cấp cấu hình thủy vân có dự phòng an toàn (3-Tier Watermark Config Fallback Resolution)
 * Mục đích: Luôn tìm được cấu hình thủy vân hợp lệ cho mọi cấp độ mật của tài liệu ngay cả khi CSDL chưa cấu hình riêng.
 * Cơ chế hoạt động:
 *   - Tầng 1: Tìm cấu hình đang bật gắn riêng với `classificationLevelId`.
 *   - Tầng 2: Rơi về cấu hình mặc định của hệ thống (`is_default: true, is_active: true`).
 *   - Tầng 3: Rơi về hằng số an toàn cứng trong mã nguồn (`opacity: 25%`, `rotation: -30°`, `include_qr_code: true`, `is_visible: true`).
 *
 * Algorithm: Hierarchical Watermark Configuration Fallback Resolution.
 * Resolves classification-specific active config -> database default config -> hardcoded fail-safe defaults.
 */
export async function resolveWatermarkConfig(
  database: PrismaClient,
  classificationLevelId?: bigint | null,
): Promise<WatermarkConfigData> {
  if (classificationLevelId) {
    const config = await database.watermarkConfig.findFirst({
      where: { classification_level_id: classificationLevelId, is_active: true },
    });
    if (config) return mapConfigRow(config);
  }

  const defaultConfig = await database.watermarkConfig.findFirst({
    where: { is_default: true, is_active: true },
  });
  if (defaultConfig) return mapConfigRow(defaultConfig);

  return {
    id: 1n,
    template_text: '{fullName} ({employeeCode}) | {documentCode} | {utcTimestamp} | {shortToken}',
    opacity_percent: 25,
    rotation_degrees: -30,
    font_size: 11,
    color_hex: '#808080',
    include_qr_code: true,
    is_visible: true,
  };
}

function mapConfigRow(row: WatermarkConfigData): WatermarkConfigData {
  return {
    id: row.id,
    template_text: row.template_text,
    opacity_percent: row.opacity_percent,
    rotation_degrees: row.rotation_degrees,
    font_size: row.font_size,
    color_hex: row.color_hex,
    include_qr_code: row.include_qr_code,
    is_visible: row.is_visible,
  };
}
