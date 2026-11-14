import type { IcapMethod, EncapsulatedSection } from './icap.types.js';

export interface ExtractedEncapsulatedPayload {
  incompleteHeaders: boolean;
  httpHeaders?: Record<string, string>;
  httpMethod?: string;
  httpUri?: string;
  httpStatusCode?: number;
  httpStatusMessage?: string;
  body: Buffer;
  isComplete: boolean;
  consumedBytes: number;
  isPreviewIof: boolean;
}

/**
 * Thuật toán: Phân tách ánh xạ byte-offset của trường header `Encapsulated` theo RFC 3507 §4.4.1.
 */
export function parseEncapsulatedHeader(headerValue?: string): EncapsulatedSection {
  const result: EncapsulatedSection = {};
  if (!headerValue) return result;

  for (const part of headerValue.split(',')) {
    const [key, val] = part.trim().split('=');
    if (!key || val === undefined) continue;
    const trimmedVal = val.trim();
    if (!/^\d+$/u.test(trimmedVal)) {
      throw new Error(`ICAP_400: Invalid Encapsulated offset "${trimmedVal}"`);
    }
    const offset = parseInt(trimmedVal, 10);
    if (!Number.isSafeInteger(offset) || offset < 0) {
      throw new Error(`ICAP_400: Out-of-range Encapsulated offset "${trimmedVal}"`);
    }
    const k = key.toLowerCase();
    if (k === 'req-hdr') result.reqHdr = offset;
    else if (k === 'req-body') result.reqBody = offset;
    else if (k === 'res-hdr') result.resHdr = offset;
    else if (k === 'res-body') result.resBody = offset;
    else if (k === 'null-body') result.nullBody = offset;
  }
  return result;
}

/**
 * Thuật toán: Giải mã tuần tự khung truyền tải phân mảnh hệ thập lục phân (Hex-Chunked Stream Decoder - RFC 3507 / RFC 2616).
 * Cơ chế:
 *   - Duyệt con trỏ `offset` qua từng khung `<hex-size>[;ext]\r\n<payload>\r\n` và kiểm tra hậu tố `\r\n`.
 *   - Dừng sạch ngay tại điểm kết thúc `0[;ext]\r\n...\r\n` (`consumedBytes = terminatorEnd`) mà KHÔNG đọc lấn hoặc vứt bỏ
 *     các byte pipelined thuộc yêu cầu ICAP kế tiếp trên cùng kết nối TCP keep-alive.
 *   - Khi `expectPostPreviewTerminator === true` (đã gửi `100 Continue` sau pha Preview), đợi đủ dấu kết thúc `0` thứ hai.
 */
export function decodeIcapChunks(
  chunkBuffer: Buffer,
  options?: { expectPostPreviewTerminator?: boolean | undefined },
): {
  data: Buffer;
  isComplete: boolean;
  consumedBytes: number;
  isPreviewIof?: boolean;
} {
  const chunks: Buffer[] = [];
  let offset = 0;
  let isComplete = false;
  let isPreviewIof = false;
  let zeroChunksSeen = 0;
  let consumedBytes = 0;

  while (offset < chunkBuffer.length) {
    const newlineIndex = chunkBuffer.indexOf('\r\n', offset);
    if (newlineIndex === -1) break;

    const sizeLine = chunkBuffer.subarray(offset, newlineIndex).toString('utf-8').trim();
    const semiParts = sizeLine.split(';');
    const hexSizeStr = semiParts[0]?.trim() ?? '';
    if (!/^[0-9a-fA-F]+$/u.test(hexSizeStr)) {
      throw new Error('ICAP_400: Invalid chunk size hex encoding');
    }

    const chunkSize = parseInt(hexSizeStr, 16);
    if (!Number.isSafeInteger(chunkSize) || chunkSize < 0) {
      throw new Error('ICAP_400: Invalid chunk size');
    }

    if (chunkSize === 0) {
      const trailerBlankIndex = chunkBuffer.indexOf('\r\n\r\n', newlineIndex);
      if (trailerBlankIndex === -1) break;
      const terminatorEnd = trailerBlankIndex + 4;

      const extensions = semiParts
        .slice(1)
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean);
      if (extensions.includes('ieof')) {
        isPreviewIof = true;
        isComplete = true;
        consumedBytes = terminatorEnd;
        break;
      }

      zeroChunksSeen += 1;
      if (options?.expectPostPreviewTerminator && zeroChunksSeen < 2) {
        offset = terminatorEnd;
        consumedBytes = terminatorEnd;
        isComplete = false;
        continue;
      }
      isComplete = true;
      consumedBytes = terminatorEnd;
      break;
    }

    const chunkDataStart = newlineIndex + 2;
    const chunkDataEnd = chunkDataStart + chunkSize;

    if (chunkDataEnd + 2 > chunkBuffer.length) {
      if (chunkDataStart < chunkBuffer.length) {
        chunks.push(
          chunkBuffer.subarray(chunkDataStart, Math.min(chunkDataEnd, chunkBuffer.length)),
        );
      }
      isComplete = false;
      break;
    }

    if (chunkBuffer[chunkDataEnd] !== 0x0d || chunkBuffer[chunkDataEnd + 1] !== 0x0a) {
      throw new Error('ICAP_400: Missing CRLF after chunk payload');
    }

    chunks.push(chunkBuffer.subarray(chunkDataStart, chunkDataEnd));
    offset = chunkDataEnd + 2;
    consumedBytes = offset;
  }

  return {
    data: Buffer.concat(chunks),
    isComplete,
    consumedBytes,
    ...(isPreviewIof ? { isPreviewIof: true } : {}),
  };
}

/**
 * Thuật toán: Trích Xuất Phân Đoạn HTTP Header Đóng Gói & Giải Mã Thân Dữ Liệu (Encapsulated HTTP Payload Extractor)
 * Cơ chế: Kiểm tra tính đơn điệu của byte-offset `Encapsulated`, tách dòng trạng thái/yêu cầu HTTP, gọi `decodeIcapChunks`
 * và trả về chính xác `consumedBytes` phục vụ cắt phần dư pipelining trên cùng kết nối TCP.
 */
export function extractEncapsulatedHttpPayload(
  method: IcapMethod,
  remainingBuffer: Buffer,
  encapsulated: EncapsulatedSection,
  options?: { expectPostPreviewTerminator?: boolean | undefined },
): ExtractedEncapsulatedPayload {
  let httpHeaders: Record<string, string> | undefined;
  let httpMethod: string | undefined;
  let httpUri: string | undefined;
  let httpStatusCode: number | undefined;
  let httpStatusMessage: string | undefined;

  const bodyOffset = encapsulated.resBody ?? encapsulated.reqBody;

  if (encapsulated.resHdr !== undefined || encapsulated.reqHdr !== undefined) {
    const httpHeaderStart = encapsulated.resHdr ?? encapsulated.reqHdr!;
    const httpHeaderEnd = bodyOffset ?? encapsulated.nullBody ?? remainingBuffer.length;

    if (httpHeaderEnd < httpHeaderStart) {
      throw new Error('ICAP_400: Invalid Encapsulated section ordering');
    }

    if (
      (bodyOffset !== undefined || encapsulated.nullBody !== undefined) &&
      remainingBuffer.length < httpHeaderEnd
    ) {
      return {
        incompleteHeaders: true,
        body: Buffer.alloc(0),
        isComplete: false,
        consumedBytes: 0,
        isPreviewIof: false,
      };
    }

    if (httpHeaderStart < remainingBuffer.length) {
      const httpHeaderText = remainingBuffer
        .subarray(httpHeaderStart, Math.min(httpHeaderEnd, remainingBuffer.length))
        .toString('utf-8');
      const httpLines = httpHeaderText.split('\r\n');
      const firstHttpLine = httpLines[0]?.trim();

      if (firstHttpLine) {
        const parts = firstHttpLine.split(/\s+/u);
        if (firstHttpLine.startsWith('HTTP/')) {
          httpStatusCode = parseInt(parts[1] ?? '200', 10);
          httpStatusMessage = parts.slice(2).join(' ');
        } else {
          httpMethod = parts[0];
          httpUri = parts[1];
        }
      }

      httpHeaders = {};
      for (let j = 1; j < httpLines.length; j++) {
        const hLine = httpLines[j]?.trim();
        if (!hLine) continue;
        const cIdx = hLine.indexOf(':');
        if (cIdx !== -1) {
          httpHeaders[hLine.slice(0, cIdx).trim().toLowerCase()] = hLine.slice(cIdx + 1).trim();
        }
      }
    }
  }

  let body = Buffer.alloc(0);
  let isComplete = false;
  let isPreviewIof = false;
  let consumedBytes = 0;

  if (method === 'OPTIONS' || encapsulated.nullBody !== undefined || bodyOffset === undefined) {
    isComplete = true;
    consumedBytes = encapsulated.nullBody ?? 0;
  } else if (bodyOffset < remainingBuffer.length) {
    const decoded = decodeIcapChunks(remainingBuffer.subarray(bodyOffset), options);
    body = Buffer.from(decoded.data);
    isComplete = decoded.isComplete;
    consumedBytes = bodyOffset + decoded.consumedBytes;
    isPreviewIof = decoded.isPreviewIof ?? false;
  }

  return {
    incompleteHeaders: false,
    ...(httpHeaders !== undefined ? { httpHeaders } : {}),
    ...(httpMethod !== undefined ? { httpMethod } : {}),
    ...(httpUri !== undefined ? { httpUri } : {}),
    ...(httpStatusCode !== undefined ? { httpStatusCode } : {}),
    ...(httpStatusMessage !== undefined ? { httpStatusMessage } : {}),
    body,
    isComplete,
    consumedBytes,
    isPreviewIof,
  };
}
