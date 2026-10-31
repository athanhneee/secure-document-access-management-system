import type {
  IcapMethod,
  IcapRequest,
  EncapsulatedSection,
  IcapServerConfig,
  DlpViolation,
} from './icap.types.js';

export class IcapParser {
  private static escapeHtml(input: string): string {
    return input
      .replace(/&/gu, '&amp;')
      .replace(/</gu, '&lt;')
      .replace(/>/gu, '&gt;')
      .replace(/"/gu, '&quot;')
      .replace(/'/gu, '&#39;');
  }

  private static sanitizeHeaderToken(input: string): string {
    return input.replace(/[\r\n]+/gu, ' ').trim();
  }

  /**
   * Parses an incoming raw TCP buffer into a structured IcapRequest object according to RFC 3507.
   * Throws an Error with prefix `ICAP_405:` or `ICAP_400:` on protocol violations once headers arrive.
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
      const key = line.slice(0, colonIdx).trim().toLowerCase();
      const value = line.slice(colonIdx + 1).trim();
      headers[key] = value;
    }

    const encapsulated = this.parseEncapsulatedHeader(headers['encapsulated']);
    const previewHeader = headers['preview'];
    let previewBytes: number | undefined;
    if (previewHeader !== undefined) {
      if (!/^\d+$/u.test(previewHeader.trim())) {
        throw new Error('ICAP_400: Invalid Preview header');
      }
      previewBytes = parseInt(previewHeader.trim(), 10);
    }

    // Parse Encapsulated HTTP parts and Body
    let httpHeaders: Record<string, string> | undefined;
    let httpMethod: string | undefined;
    let httpUri: string | undefined;
    let httpStatusCode: number | undefined;
    let httpStatusMessage: string | undefined;

    const bodyOffset =
      encapsulated.resBody !== undefined
        ? encapsulated.resBody
        : encapsulated.reqBody !== undefined
          ? encapsulated.reqBody
          : undefined;

    // Wait for encapsulated HTTP headers to arrive completely before parsing body
    if (encapsulated.resHdr !== undefined || encapsulated.reqHdr !== undefined) {
      const httpHeaderStart =
        encapsulated.resHdr !== undefined ? encapsulated.resHdr : encapsulated.reqHdr!;
      const httpHeaderEnd =
        bodyOffset !== undefined
          ? bodyOffset
          : encapsulated.nullBody !== undefined
            ? encapsulated.nullBody
            : remainingBuffer.length;

      if (httpHeaderEnd < httpHeaderStart) {
        throw new Error('ICAP_400: Invalid Encapsulated section ordering');
      }

      if (
        (bodyOffset !== undefined || encapsulated.nullBody !== undefined) &&
        remainingBuffer.length < httpHeaderEnd
      ) {
        // Incomplete encapsulated HTTP header section; wait for more TCP chunks
        return {
          method,
          uri,
          version,
          headers,
          encapsulated,
          ...(previewBytes !== undefined ? { previewBytes, isPreview: true } : {}),
          body: Buffer.alloc(0),
          isComplete: false,
        };
      }

      if (httpHeaderStart < remainingBuffer.length) {
        const httpHeaderText = remainingBuffer
          .slice(httpHeaderStart, Math.min(httpHeaderEnd, remainingBuffer.length))
          .toString('utf-8');

        const httpLines = httpHeaderText.split('\r\n');
        const firstHttpLine = httpLines[0]?.trim();

        if (firstHttpLine) {
          if (firstHttpLine.startsWith('HTTP/')) {
            const parts = firstHttpLine.split(/\s+/u);
            httpStatusCode = parseInt(parts[1] ?? '200', 10);
            httpStatusMessage = parts.slice(2).join(' ');
          } else {
            const parts = firstHttpLine.split(/\s+/u);
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

    // Decode ICAP chunked body
    let rawBody = Buffer.alloc(0);
    let isComplete = false;
    let isPreviewIof = false;

    if (method === 'OPTIONS' || encapsulated.nullBody !== undefined) {
      isComplete = true;
    } else if (bodyOffset !== undefined) {
      if (bodyOffset < remainingBuffer.length) {
        const chunkedBodyPart = remainingBuffer.slice(bodyOffset);
        const decoded = this.decodeIcapChunks(chunkedBodyPart);
        rawBody = Buffer.from(decoded.data);
        isComplete = decoded.isComplete;
        isPreviewIof = decoded.isPreviewIof ?? false;
      }
    } else {
      // No body section declared in Encapsulated header
      isComplete = true;
    }

    return {
      method,
      uri,
      version,
      headers,
      encapsulated,
      ...(previewBytes !== undefined ? { previewBytes, isPreview: true } : {}),
      ...(isPreviewIof ? { isPreviewIof: true } : {}),
      ...(httpHeaders !== undefined ? { httpHeaders } : {}),
      ...(httpMethod !== undefined ? { httpMethod } : {}),
      ...(httpUri !== undefined ? { httpUri } : {}),
      ...(httpStatusCode !== undefined ? { httpStatusCode } : {}),
      ...(httpStatusMessage !== undefined ? { httpStatusMessage } : {}),
      body: rawBody,
      isComplete,
    };
  }

  /**
   * Parses the Encapsulated header value: "req-hdr=0, res-hdr=120, res-body=250"
   */
  public static parseEncapsulatedHeader(headerValue?: string): EncapsulatedSection {
    const result: EncapsulatedSection = {};
    if (!headerValue) return result;

    const parts = headerValue.split(',');
    for (const part of parts) {
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
      switch (key.toLowerCase()) {
        case 'req-hdr':
          result.reqHdr = offset;
          break;
        case 'req-body':
          result.reqBody = offset;
          break;
        case 'res-hdr':
          result.resHdr = offset;
          break;
        case 'res-body':
          result.resBody = offset;
          break;
        case 'null-body':
          result.nullBody = offset;
          break;
      }
    }
    return result;
  }

  /**
   * Decodes ICAP chunked encoding (<hex-size>\r\n<data>\r\n... 0\r\n\r\n).
   * Supports multi-segment preview + post-100-Continue chunk concatenation when `consumeAllTerminators` is used.
   */
  public static decodeIcapChunks(chunkBuffer: Buffer): {
    data: Buffer;
    isComplete: boolean;
    isPreviewIof?: boolean;
  } {
    const chunks: Buffer[] = [];
    let offset = 0;
    let isComplete = false;
    let isPreviewIof = false;

    while (offset < chunkBuffer.length) {
      const newlineIndex = chunkBuffer.indexOf('\r\n', offset);
      if (newlineIndex === -1) {
        break;
      }

      const sizeLine = chunkBuffer.slice(offset, newlineIndex).toString('utf-8').trim();
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
        const terminatorEnd = newlineIndex + 4; // "0...\r\n\r\n"
        if (terminatorEnd > chunkBuffer.length) {
          // Wait for trailing \r\n of zero chunk
          break;
        }
        const extensions = semiParts
          .slice(1)
          .map((s) => s.trim().toLowerCase())
          .filter(Boolean);
        if (extensions.includes('ieof')) {
          isPreviewIof = true;
          isComplete = true;
          break;
        }
        // If there are additional chunks after a preview terminator (post 100-Continue), keep decoding!
        if (terminatorEnd < chunkBuffer.length) {
          offset = terminatorEnd;
          isComplete = false;
          continue;
        }
        isComplete = true;
        break;
      }

      const chunkDataStart = newlineIndex + 2;
      const chunkDataEnd = chunkDataStart + chunkSize;

      if (chunkDataEnd + 2 > chunkBuffer.length) {
        // Incomplete chunk or trailing CRLF not yet received; accumulate partial data for caller inspection
        if (chunkDataStart < chunkBuffer.length) {
          chunks.push(
            chunkBuffer.slice(chunkDataStart, Math.min(chunkDataEnd, chunkBuffer.length)),
          );
        }
        isComplete = false;
        break;
      }

      if (chunkBuffer[chunkDataEnd] !== 0x0d || chunkBuffer[chunkDataEnd + 1] !== 0x0a) {
        throw new Error('ICAP_400: Missing CRLF after chunk payload');
      }

      chunks.push(chunkBuffer.slice(chunkDataStart, chunkDataEnd));
      offset = chunkDataEnd + 2; // skip trailing \r\n
    }

    return {
      data: Buffer.concat(chunks),
      isComplete,
      ...(isPreviewIof ? { isPreviewIof: true } : {}),
    };
  }

  /**
   * Generates standard ICAP 200 OK response for OPTIONS method.
   */
  public static buildOptionsResponse(config?: IcapServerConfig): Buffer {
    const dateStr = new Date().toUTCString();
    const serviceName = this.sanitizeHeaderToken(config?.serviceName ?? 'sda-dlp');
    const previewSize = config?.previewSize ?? 2048;
    const maxConnections = config?.maxConnections ?? 100;

    const response = [
      'ICAP/1.0 200 OK',
      `Date: ${dateStr}`,
      'Server: SDA Network DLP ICAP Server/1.0',
      'Connection: close',
      'Methods: RESPMOD, REQMOD',
      `Service: SDA Enterprise Network Data Loss Prevention (${serviceName})`,
      'ISTag: "SDA-DLP-1.0.0"',
      `Max-Connections: ${maxConnections}`,
      'Options-TTL: 3600',
      `Preview: ${previewSize}`,
      'Allow: 204',
      'Encapsulated: null-body=0',
      '',
      '',
    ].join('\r\n');

    return Buffer.from(response, 'utf-8');
  }

  /**
   * Generates ICAP 204 No modifications response (clean payload pass-through).
   */
  public static build204Response(): Buffer {
    const dateStr = new Date().toUTCString();
    const response = [
      'ICAP/1.0 204 No modifications',
      `Date: ${dateStr}`,
      'Server: SDA Network DLP ICAP Server/1.0',
      'Connection: close',
      'ISTag: "SDA-DLP-1.0.0"',
      '',
      '',
    ].join('\r\n');

    return Buffer.from(response, 'utf-8');
  }

  /**
   * Generates ICAP 200 OK response encapsulating an HTTP 403 Forbidden block page.
   */
  public static buildBlockResponse(violations: DlpViolation[]): Buffer {
    const dateStr = new Date().toUTCString();
    const violationSummary = this.escapeHtml(
      violations.map((v) => `[${v.severity}] ${v.rule}: ${v.description}`).join('\n'),
    );
    const rawViolationCodes = violations.map((v) => v.type).join(', ');
    const safeHeaderViolationCodes = this.sanitizeHeaderToken(rawViolationCodes);
    const safeHtmlViolationCodes = this.escapeHtml(rawViolationCodes);

    const htmlBody = `<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="utf-8">
  <title>403 Cấm Truy Cập - SDA Network DLP</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f7f7f7; color: #222; margin: 0; padding: 40px; }
    .card { max-width: 640px; margin: 0 auto; background: #fff; border: 1px solid #ebebeb; border-radius: 16px; padding: 32px; box-shadow: 0 4px 20px rgba(0,0,0,0.06); }
    h1 { color: #C13515; font-size: 20px; margin-top: 0; display: flex; align-items: center; gap: 8px; }
    p { font-size: 13px; line-height: 1.6; color: #717171; }
    .alert-box { background: rgba(193, 53, 21, 0.08); border-left: 4px solid #C13515; padding: 12px 16px; border-radius: 8px; font-family: monospace; font-size: 12px; color: #C13515; margin: 16px 0; white-space: pre-wrap; }
    .badge { display: inline-block; font-weight: bold; color: #C13515; }
    .footer { font-size: 11px; color: #b0b0b0; border-top: 1px solid #ebebeb; padding-top: 16px; margin-top: 24px; }
  </style>
</head>
<body>
  <div class="card">
    <h1>🚨 TRUY CẬP BỊ TỪ CHỐI BỞI HỆ THỐNG NETWORK DLP</h1>
    <p>Dữ liệu truyền tải qua cổng Gateway biên mạng của cơ quan đã bị chặn do vi phạm chính sách bảo vệ dữ liệu mật:</p>
    <div class="alert-box">Phát hiện vi phạm chính sách an ninh:\n${violationSummary}</div>
    <p>Hành vi sao chép, trích xuất hoặc tuồn dữ liệu mật ra ngoài mạng cơ quan đã được ghi nhận vào chuỗi kiểm toán pháp chứng (Forensic Audit Trail) và thông báo tới sĩ quan an ninh SOC.</p>
    <div class="footer">SDA Enterprise Network Data Loss Prevention Gateway (RFC 3507 ICAP Server) &bull; Mã vi phạm: ${safeHtmlViolationCodes}</div>
  </div>
</body>
</html>`;

    const htmlBuffer = Buffer.from(htmlBody, 'utf-8');

    const httpResponseHeaders = [
      'HTTP/1.1 403 Forbidden',
      `Date: ${dateStr}`,
      'Server: SDA Network DLP Gateway/1.0',
      'Content-Type: text/html; charset=utf-8',
      `Content-Length: ${htmlBuffer.length}`,
      'X-DLP-Status: BLOCKED',
      `X-DLP-Violation: ${safeHeaderViolationCodes}`,
      '',
      '',
    ].join('\r\n');

    const httpHeaderBuffer = Buffer.from(httpResponseHeaders, 'utf-8');

    // Encode HTML body in ICAP chunked format
    const hexSize = htmlBuffer.length.toString(16);
    const chunkedBody = Buffer.concat([
      Buffer.from(`${hexSize}\r\n`, 'utf-8'),
      htmlBuffer,
      Buffer.from('\r\n0\r\n\r\n', 'utf-8'),
    ]);

    // Encapsulated header offsets: res-hdr starts at 0, res-body starts right after HTTP headers
    const resHdrOffset = 0;
    const resBodyOffset = httpHeaderBuffer.length;

    const icapHeaders = [
      'ICAP/1.0 200 OK',
      `Date: ${dateStr}`,
      'Server: SDA Network DLP ICAP Server/1.0',
      'Connection: close',
      'ISTag: "SDA-DLP-1.0.0"',
      `Encapsulated: res-hdr=${resHdrOffset}, res-body=${resBodyOffset}`,
      '',
      '',
    ].join('\r\n');

    return Buffer.concat([Buffer.from(icapHeaders, 'utf-8'), httpHeaderBuffer, chunkedBody]);
  }
}
