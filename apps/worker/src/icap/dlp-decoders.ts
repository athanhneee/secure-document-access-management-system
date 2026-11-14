import type { DlpScanOptions } from './icap.types.js';

/**
 * Thuật toán / Tổng quan module:
 * Bộ mở rộng bề mặt kiểm tra đa biểu diễn (Multi-Encoding Surface Expander) cho DLP mạng:
 * - Gom URI/query string của ICAP & HTTP đóng gói cùng toàn bộ cặp khóa-giá trị HTTP headers.
 * - Giải mã URL nhiều vòng (`%XX` / `+`), giải mã các khối ứng viên Base64/Base64URL (`>= 24` ký tự) có ngân sách giới hạn,
 *   và giải mã văn bản UTF-16LE / UTF-16BE để chống lách bộ lọc DLP bằng mã hóa bề mặt.
 */

export const ZERO_WIDTH_AND_FORMAT_CHARS_RE =
  /\u034F|[\u00AD\u061C\u180E\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]/gu;

const BASE64_CANDIDATE_RE = /[A-Za-z0-9+/_-]{24,}={0,2}/gu;
const PDF_UTF16BE_HEX_STRING_RE = /<FEFF([0-9A-Fa-f]{4}){4,512}>/gu;
const MAX_BASE64_CANDIDATES = 64;
const MAX_BASE64_DECODED_BYTES = 1024 * 1024;

/**
 * Thuật toán: Giải mã chuỗi hex UTF-16BE trong từ điển metadata PDF (`<FEFF0057004D...>`) sang chuỗi Unicode thuần.
 */
export function extractPdfUtf16BeHexSurfaces(rawText: string): string[] {
  if (!rawText.includes('<FEFF') && !rawText.includes('<feff')) return [];
  const results: string[] = [];
  PDF_UTF16BE_HEX_STRING_RE.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = PDF_UTF16BE_HEX_STRING_RE.exec(rawText)) !== null && results.length < 32) {
    const hexBody = match[0].slice(5, -1);
    const rawBuf = Buffer.from(hexBody, 'hex');
    const swapped = Buffer.allocUnsafe(rawBuf.length);
    for (let i = 0; i + 1 < rawBuf.length; i += 2) {
      swapped[i] = rawBuf[i + 1]!;
      swapped[i + 1] = rawBuf[i]!;
    }
    results.push(swapped.toString('utf16le'));
  }
  return results;
}

export function normalizeDlpText(raw: string): string {
  return raw.normalize('NFKC').replace(ZERO_WIDTH_AND_FORMAT_CHARS_RE, '');
}

/**
 * Thuật toán: Giải mã chuỗi phần trăm URL chịu lỗi phân mảnh (Fault-Tolerant Multi-Pass Percent Decoder).
 * Thực hiện tối đa 2 vòng giải mã `%XX` để phát hiện cả tấn công mã hóa URL kép (`%2557%254D-...`).
 */
export function decodeUrlPercentEscapes(input: string): string {
  let current = input;
  for (let pass = 0; pass < 2; pass++) {
    if (!current.includes('%') && !current.includes('+')) break;
    const plusConverted = current.replace(/\+/gu, ' ');
    let next: string;
    try {
      next = decodeURIComponent(plusConverted);
    } catch {
      next = plusConverted.replace(/%([0-9a-fA-F]{2})/gu, (_m, hex: string) =>
        String.fromCharCode(parseInt(hex, 16)),
      );
    }
    if (next === current) break;
    current = next;
  }
  return current;
}

/**
 * Thuật toán: Trích xuất và giải mã các ứng viên Base64 / Base64URL có độ dài `>= 24` ký tự sang UTF-8 & UTF-16LE.
 */
export function extractBase64CandidateTexts(sourceTexts: readonly string[]): string[] {
  const decodedSurfaces: string[] = [];
  const seenCandidates = new Set<string>();
  let remainingBytes = MAX_BASE64_DECODED_BYTES;

  for (const source of sourceTexts) {
    BASE64_CANDIDATE_RE.lastIndex = 0;
    let match: RegExpExecArray | null;
    while (
      seenCandidates.size < MAX_BASE64_CANDIDATES &&
      remainingBytes > 0 &&
      (match = BASE64_CANDIDATE_RE.exec(source)) !== null
    ) {
      const candidate = match[0];
      if (seenCandidates.has(candidate)) continue;
      seenCandidates.add(candidate);

      const stdB64 = candidate.replace(/-/gu, '+').replace(/_/gu, '/');
      const padLen = (4 - (stdB64.length % 4)) % 4;
      if (padLen === 3) continue;
      const padded = stdB64 + '='.repeat(padLen);

      const decoded = Buffer.from(padded, 'base64');
      if (decoded.length < 12) continue;
      remainingBytes -= decoded.length;

      const utf8Text = decoded.toString('utf8');
      decodedSurfaces.push(utf8Text);
      if (utf8Text.includes('%')) {
        decodedSurfaces.push(decodeUrlPercentEscapes(utf8Text));
      }
      if (decoded.includes(0x00) && decoded.length >= 16) {
        decodedSurfaces.push(decoded.toString('utf16le'));
      }
    }
  }

  return decodedSurfaces;
}

/**
 * Thuật toán: Giải mã tải trọng nhị phân UTF-16LE (và đảo byte UTF-16BE nếu có BOM `FE FF`) để bắt chuỗi Unicode 2-byte.
 */
export function extractUtf16Surfaces(buffer: Buffer): string[] {
  if (buffer.length < 8) return [];
  const hasNullByte = buffer.includes(0x00);
  const hasLeBom = buffer[0] === 0xff && buffer[1] === 0xfe;
  const hasBeBom = buffer[0] === 0xfe && buffer[1] === 0xff;
  if (!hasNullByte && !hasLeBom && !hasBeBom) return [];

  const results: string[] = [buffer.toString('utf16le')];
  if (buffer.length > 2) {
    results.push(buffer.subarray(1).toString('utf16le'));
  }
  if (hasBeBom) {
    const evenLen = buffer.length - (buffer.length % 2);
    const swapped = Buffer.allocUnsafe(evenLen);
    for (let i = 0; i < evenLen; i += 2) {
      swapped[i] = buffer[i + 1]!;
      swapped[i + 1] = buffer[i]!;
    }
    results.push(swapped.toString('utf16le'));
  }
  return results;
}

/**
 * Thuật toán: Tổng hợp toàn bộ các bề mặt văn bản đã chuẩn hóa Unicode `NFKC` để đưa vào đường ống đối sánh DLP.
 */
export function buildNormalizedDlpSurfaces(
  bodyBuffer: Buffer,
  options?: DlpScanOptions,
  extraArchiveTexts: readonly string[] = [],
): string[] {
  const rawTexts: string[] = [];

  if (options?.requestUri) rawTexts.push(options.requestUri);
  if (options?.httpUri) rawTexts.push(options.httpUri);
  if (options?.httpHeaders) {
    for (const [k, v] of Object.entries(options.httpHeaders)) {
      rawTexts.push(`${k}: ${v}`);
    }
  }
  if (options?.icapHeaders) {
    for (const [k, v] of Object.entries(options.icapHeaders)) {
      if (k !== 'encapsulated' && k !== 'preview' && k !== 'host') {
        rawTexts.push(`${k}: ${v}`);
      }
    }
  }

  if (bodyBuffer.length > 0) {
    const utf8Body = bodyBuffer.toString('utf8');
    rawTexts.push(utf8Body);
    rawTexts.push(...extractPdfUtf16BeHexSurfaces(utf8Body));
    rawTexts.push(...extractUtf16Surfaces(bodyBuffer));
  }
  rawTexts.push(...extraArchiveTexts);

  const urlDecoded = rawTexts
    .filter((t) => t.includes('%') || t.includes('+'))
    .map((t) => decodeUrlPercentEscapes(t));

  const base64Decoded = extractBase64CandidateTexts([...rawTexts, ...urlDecoded]);

  return [...rawTexts, ...urlDecoded, ...base64Decoded]
    .map((s) => normalizeDlpText(s))
    .filter((s) => s.length > 0);
}
