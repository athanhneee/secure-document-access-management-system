import type {
  IcapMethod,
  IcapRequest,
  EncapsulatedSection,
  IcapServerConfig,
  DlpViolation,
} from './icap.types.js';
import {
  parseEncapsulatedHeader,
  decodeIcapChunks,
  extractEncapsulatedHttpPayload,
} from './icap-http-body.js';
import {
  buildOptionsResponse,
  build204Response,
  buildBlockResponse,
} from './icap-wire-responses.js';

export {
  parseEncapsulatedHeader,
  decodeIcapChunks,
  extractEncapsulatedHttpPayload,
  buildOptionsResponse,
  build204Response,
  buildBlockResponse,
};

/**
 * Algorithm / Thuật toán tổng quan module:
 * Bộ phân tích cú pháp và đóng gói bản tin giao thức RFC 3507 ICAP (Internet Content Adaptation Protocol).
 * - Pha 1: Định vị ranh giới ICAP header `\r\n\r\n`; trả về `null` nếu khung header chưa truyền đủ.
 * - Pha 2: Xác thực dòng yêu cầu (`OPTIONS`, `REQMOD`, `RESPMOD`), phiên bản `ICAP/` và bảng header ICAP.
 * - Pha 3 & 4: Ủy quyền trích xuất phân đoạn HTTP đóng gói và giải mã khung truyền tải `hex-chunked` qua `icap-http-body.ts`.
 */
export class IcapParser {
  /**
   * Thuật toán: Phân tách khung bản tin ICAP RFC 3507 và lan truyền cờ `incompleteHeaders` khi HTTP header đóng gói chưa nhận đủ qua TCP.
   */
  public static parseRequest(rawBuffer: Buffer): IcapRequest | null {
    const headerEndIndex = rawBuffer.indexOf('\r\n\r\n');
    if (headerEndIndex === -1) {
      return null;
    }

    const icapHeaderPart = rawBuffer.slice(0, headerEndIndex).toString('utf-8');
    const remainingBuffer = rawBuffer.slice(headerEndIndex + 4);

    const lines = icapHeaderPart.split('\r\n');
    const requestLine = lines[0];
    if (!requestLine) {
      throw new Error('ICAP_400: Empty ICAP request line');
    }

    const requestLineParts = requestLine.trim().split(/\s+/u);
    if (requestLineParts.length < 3) {
      throw new Error('ICAP_400: Malformed ICAP request line');
    }

    const rawMethod = requestLineParts[0]?.toUpperCase() ?? '';
    const uri = (requestLineParts[1] ?? '').replace(/\p{Cc}/gu, '').slice(0, 256);
    const version = (requestLineParts[2] ?? 'ICAP/1.0').trim();

    if (!version.startsWith('ICAP/')) {
      throw new Error('ICAP_400: Invalid ICAP protocol version');
    }

    if (rawMethod !== 'OPTIONS' && rawMethod !== 'RESPMOD' && rawMethod !== 'REQMOD') {
      throw new Error(`ICAP_405: Unsupported ICAP method ${rawMethod}`);
    }
    const method = rawMethod as IcapMethod;

    const headers: Record<string, string> = {};
    for (let i = 1; i < lines.length; i++) {
      const line = lines[i]?.trim();
      if (!line) continue;
      const colonIdx = line.indexOf(':');
      if (colonIdx <= 0) {
        throw new Error('ICAP_400: Malformed ICAP header line');
      }
      headers[line.slice(0, colonIdx).trim().toLowerCase()] = line.slice(colonIdx + 1).trim();
    }

    const encapsulated = parseEncapsulatedHeader(headers['encapsulated']);
    const previewHeader = headers['preview'];
    let previewBytes: number | undefined;
    if (previewHeader !== undefined) {
      if (!/^\d+$/u.test(previewHeader.trim())) {
        throw new Error('ICAP_400: Invalid Preview header');
      }
      previewBytes = parseInt(previewHeader.trim(), 10);
    }

    const payload = extractEncapsulatedHttpPayload(method, remainingBuffer, encapsulated);
    // CONFLICT-RESOLVED: Lan truyền tường minh incompleteHeaders để IcapServer không khóa sớm headersValidated khi HTTP header đóng gói bị phân mảnh TCP.
    if (payload.incompleteHeaders) {
      return {
        method,
        uri,
        version,
        headers,
        encapsulated,
        ...(previewBytes !== undefined ? { previewBytes, isPreview: true } : {}),
        body: Buffer.alloc(0),
        incompleteHeaders: payload.incompleteHeaders,
        isComplete: false,
      };
    }

    return {
      method,
      uri,
      version,
      headers,
      encapsulated,
      ...(previewBytes !== undefined ? { previewBytes, isPreview: true } : {}),
      ...(payload.isPreviewIof ? { isPreviewIof: true } : {}),
      ...(payload.httpHeaders !== undefined ? { httpHeaders: payload.httpHeaders } : {}),
      ...(payload.httpMethod !== undefined ? { httpMethod: payload.httpMethod } : {}),
      ...(payload.httpUri !== undefined ? { httpUri: payload.httpUri } : {}),
      ...(payload.httpStatusCode !== undefined ? { httpStatusCode: payload.httpStatusCode } : {}),
      ...(payload.httpStatusMessage !== undefined
        ? { httpStatusMessage: payload.httpStatusMessage }
        : {}),
      body: payload.body,
      incompleteHeaders: payload.incompleteHeaders,
      isComplete: payload.isComplete,
    };
  }

  public static parseEncapsulatedHeader(headerValue?: string): EncapsulatedSection {
    return parseEncapsulatedHeader(headerValue);
  }

  public static decodeIcapChunks(chunkBuffer: Buffer): {
    data: Buffer;
    isComplete: boolean;
    isPreviewIof?: boolean;
  } {
    return decodeIcapChunks(chunkBuffer);
  }

  public static buildOptionsResponse(config?: IcapServerConfig): Buffer {
    return buildOptionsResponse(config);
  }

  public static build204Response(): Buffer {
    return build204Response();
  }

  public static buildBlockResponse(violations: DlpViolation[]): Buffer {
    return buildBlockResponse(violations);
  }
}
