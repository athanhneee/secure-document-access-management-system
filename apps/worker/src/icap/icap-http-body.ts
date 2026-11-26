import type { IcapMethod, EncapsulatedSection } from './icap.types.js';

export interface ExtractedEncapsulatedPayload {
  incompleteHeaders: boolean;
  httpHeaders?: Record<string, string>;
  httpRequestHeaders?: Record<string, string>;
  httpResponseHeaders?: Record<string, string>;
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
 * Thuật toán: Kiểm tra gói tin ICAP có thực sự mang phân đoạn thân dữ liệu HTTP (`req-body` hoặc `res-body`)
 * và không bị đánh dấu `null-body` theo RFC 3507 §4.4.1 & §4.5 hay không.
 */
export function hasEncapsulatedHttpBody(encapsulated: EncapsulatedSection): boolean {
  return (
    encapsulated.nullBody === undefined &&
    (encapsulated.reqBody !== undefined || encapsulated.resBody !== undefined)
  );
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

interface ParsedHttpHeaderSection {
  httpMethod?: string;
  httpUri?: string;
  httpStatusCode?: number;
  httpStatusMessage?: string;
  headers: Record<string, string>;
}

/**
 * Thuật toán: Phân tích một phân đoạn HTTP Header đơn lẻ (`req-hdr` hoặc `res-hdr`),
 * giữ nguyên dòng yêu cầu / dòng trạng thái và gộp các header trùng tên bằng `, ` để không mất dữ liệu DLP.
 */
function parseHttpHeaderBlock(httpHeaderText: string): ParsedHttpHeaderSection {
  const httpLines = httpHeaderText.split('\r\n');
  const firstHttpLine = httpLines[0]?.trim();
  const parsed: ParsedHttpHeaderSection = { headers: {} };

  if (firstHttpLine) {
    const parts = firstHttpLine.split(/\s+/u);
    if (firstHttpLine.startsWith('HTTP/')) {
      parsed.httpStatusCode = parseInt(parts[1] ?? '200', 10);
      parsed.httpStatusMessage = parts.slice(2).join(' ');
    } else {
      if (parts[0]) parsed.httpMethod = parts[0];
      if (parts[1]) parsed.httpUri = parts[1];
    }
  }

  for (let j = 1; j < httpLines.length; j++) {
    const hLine = httpLines[j]?.trim();
    if (!hLine) continue;
    const cIdx = hLine.indexOf(':');
    if (cIdx !== -1) {
      const key = hLine.slice(0, cIdx).trim().toLowerCase();
      const val = hLine.slice(cIdx + 1).trim();
      const existing = parsed.headers[key];
      parsed.headers[key] = existing !== undefined ? `${existing}, ${val}` : val;
    }
  }

  return parsed;
}

/**
 * Thuật toán: Trích Xuất Phân Đoạn HTTP Header Đóng Gói (`req-hdr` + `res-hdr` độc lập chuẩn RFC 3507 §4.9) & Giải Mã Thân Dữ Liệu.
 * Cơ chế: Kiểm tra tính đơn điệu của byte-offset `Encapsulated`, phân tích độc lập cả `req-hdr` lẫn `res-hdr` khi cả hai cùng tồn tại,
 * bảo toàn `httpMethod`/`httpUri` từ `req-hdr`, mã trạng thái từ `res-hdr` và gộp headers của cả hai không ghi đè mất bí mật cho DLP.
 */
export function extractEncapsulatedHttpPayload(
  method: IcapMethod,
  remainingBuffer: Buffer,
  encapsulated: EncapsulatedSection,
  options?: { expectPostPreviewTerminator?: boolean | undefined },
): ExtractedEncapsulatedPayload {
  let httpHeaders: Record<string, string> | undefined;
  let httpRequestHeaders: Record<string, string> | undefined;
  let httpResponseHeaders: Record<string, string> | undefined;
  let httpMethod: string | undefined;
  let httpUri: string | undefined;
  let httpStatusCode: number | undefined;
  let httpStatusMessage: string | undefined;

  const bodyOffset = encapsulated.resBody ?? encapsulated.reqBody;
  const tailOffset = bodyOffset ?? encapsulated.nullBody;

  if (method !== 'OPTIONS' && tailOffset === undefined) {
    throw new Error('ICAP_400: Missing Encapsulated body or null-body offset');
  }

  if (encapsulated.resHdr !== undefined || encapsulated.reqHdr !== undefined) {
    const hasReqHdr = encapsulated.reqHdr !== undefined;
    const hasResHdr = encapsulated.resHdr !== undefined;

    if (hasReqHdr && hasResHdr && encapsulated.resHdr! < encapsulated.reqHdr!) {
      throw new Error('ICAP_400: Invalid Encapsulated section ordering');
    }

    const lastHeaderStart = hasResHdr ? encapsulated.resHdr! : encapsulated.reqHdr!;
    const headerRegionEnd = tailOffset ?? remainingBuffer.length;
    if (headerRegionEnd < lastHeaderStart) {
      throw new Error('ICAP_400: Invalid Encapsulated section ordering');
    }

    if (
      (tailOffset !== undefined && remainingBuffer.length < tailOffset) ||
      (hasReqHdr && hasResHdr && remainingBuffer.length < encapsulated.resHdr!)
    ) {
      return {
        incompleteHeaders: true,
        body: Buffer.alloc(0),
        isComplete: false,
        consumedBytes: 0,
        isPreviewIof: false,
      };
    }

    const mergedHeaders: Record<string, string> = {};
    let parsedAnyHeaderBlock = false;

    if (hasReqHdr && encapsulated.reqHdr! < remainingBuffer.length) {
      const reqEnd = hasResHdr ? encapsulated.resHdr! : headerRegionEnd;
      const reqText = remainingBuffer
        .subarray(encapsulated.reqHdr!, Math.min(reqEnd, remainingBuffer.length))
        .toString('utf-8');
      const reqParsed = parseHttpHeaderBlock(reqText);
      parsedAnyHeaderBlock = true;
      httpMethod = reqParsed.httpMethod;
      httpUri = reqParsed.httpUri;
      httpRequestHeaders = reqParsed.headers;
      for (const [k, v] of Object.entries(reqParsed.headers)) {
        mergedHeaders[k] = v;
      }
    }

    if (hasResHdr && encapsulated.resHdr! < remainingBuffer.length) {
      const resText = remainingBuffer
        .subarray(encapsulated.resHdr!, Math.min(headerRegionEnd, remainingBuffer.length))
        .toString('utf-8');
      const resParsed = parseHttpHeaderBlock(resText);
      parsedAnyHeaderBlock = true;
      if (resParsed.httpStatusCode !== undefined) httpStatusCode = resParsed.httpStatusCode;
      if (resParsed.httpStatusMessage !== undefined) {
        httpStatusMessage = resParsed.httpStatusMessage;
      }
      if (httpMethod === undefined && resParsed.httpMethod !== undefined) {
        httpMethod = resParsed.httpMethod;
      }
      if (httpUri === undefined && resParsed.httpUri !== undefined) {
        httpUri = resParsed.httpUri;
      }
      httpResponseHeaders = resParsed.headers;
      for (const [k, v] of Object.entries(resParsed.headers)) {
        const existing = mergedHeaders[k];
        if (k === 'content-encoding' || existing === undefined || existing === v) {
          mergedHeaders[k] = v;
        } else {
          mergedHeaders[k] = `${existing}, ${v}`;
        }
      }
    }

    if (parsedAnyHeaderBlock) {
      httpHeaders = mergedHeaders;
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
    ...(httpRequestHeaders !== undefined ? { httpRequestHeaders } : {}),
    ...(httpResponseHeaders !== undefined ? { httpResponseHeaders } : {}),
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
