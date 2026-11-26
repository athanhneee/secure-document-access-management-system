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
 * Thuật toán tổng quan module:
 * Bộ phân tích cú pháp và đóng gói bản tin giao thức RFC 3507 ICAP (Internet Content Adaptation Protocol).
 * - Định vị ranh giới ICAP header `\r\n\r\n`, xác thực dòng yêu cầu (`OPTIONS`, `REQMOD`, `RESPMOD`) và bảng header ICAP.
 * - Ủy quyền trích xuất HTTP đóng gói và trả về `consumedBytes` chính xác cho kết nối tái sử dụng keep-alive / pipelining.
 */
export class IcapParser {
  /**
   * Thuật toán: Phân tách khung bản tin ICAP RFC 3507 và lan truyền `incompleteHeaders`, `consumedBytes` và `continuedAfterPreview`.
   */
  public static parseRequest(
    rawBuffer: Buffer,
    options?: { continuedAfterPreview?: boolean | undefined },
  ): IcapRequest | null {
    const headerEndIndex = rawBuffer.indexOf('\r\n\r\n');
    if (headerEndIndex === -1) {
      return null;
    }

    const icapHeaderPart = rawBuffer.subarray(0, headerEndIndex).toString('utf-8');
    const remainingBuffer = rawBuffer.subarray(headerEndIndex + 4);

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
    const uri = (requestLineParts[1] ?? '').replace(/\p{Cc}/gu, '').slice(0, 1024);
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

    const isPreview = previewBytes !== undefined;
    const payload = extractEncapsulatedHttpPayload(method, remainingBuffer, encapsulated, {
      expectPostPreviewTerminator: Boolean(isPreview && options?.continuedAfterPreview),
    });

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
      ...(payload.httpRequestHeaders !== undefined
        ? { httpRequestHeaders: payload.httpRequestHeaders }
        : {}),
      ...(payload.httpResponseHeaders !== undefined
        ? { httpResponseHeaders: payload.httpResponseHeaders }
        : {}),
      ...(payload.httpMethod !== undefined ? { httpMethod: payload.httpMethod } : {}),
      ...(payload.httpUri !== undefined ? { httpUri: payload.httpUri } : {}),
      ...(payload.httpStatusCode !== undefined ? { httpStatusCode: payload.httpStatusCode } : {}),
      ...(payload.httpStatusMessage !== undefined
        ? { httpStatusMessage: payload.httpStatusMessage }
        : {}),
      body: payload.body,
      incompleteHeaders: payload.incompleteHeaders,
      isComplete: payload.isComplete,
      consumedBytes: headerEndIndex + 4 + payload.consumedBytes,
    };
  }

  public static parseEncapsulatedHeader(headerValue?: string): EncapsulatedSection {
    return parseEncapsulatedHeader(headerValue);
  }

  public static decodeIcapChunks(chunkBuffer: Buffer): {
    data: Buffer;
    isComplete: boolean;
    consumedBytes: number;
    isPreviewIof?: boolean;
  } {
    return decodeIcapChunks(chunkBuffer);
  }

  public static buildOptionsResponse(config?: IcapServerConfig): Buffer {
    return buildOptionsResponse(config);
  }

  public static build204Response(options?: { keepAlive?: boolean }): Buffer {
    return build204Response(options);
  }

  public static buildBlockResponse(
    violations: DlpViolation[],
    options?: { keepAlive?: boolean },
  ): Buffer {
    return buildBlockResponse(violations, options);
  }
}
