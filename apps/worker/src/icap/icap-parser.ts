import type {
  IcapMethod,
  IcapRequest,
  EncapsulatedSection,
  IcapServerConfig,
  DlpViolation,
} from './icap.types.js';

export class IcapParser {
  /**
   * Parses an incoming raw TCP buffer into a structured IcapRequest object according to RFC 3507.
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
      return null;
    }

    const requestLineParts = requestLine.trim().split(/\s+/u);
    if (requestLineParts.length < 3) {
      return null;
    }

    const method = requestLineParts[0]?.toUpperCase() as IcapMethod;
    const uri = requestLineParts[1] ?? '';
    const version = requestLineParts[2] ?? 'ICAP/1.0';

    if (method !== 'OPTIONS' && method !== 'RESPMOD' && method !== 'REQMOD') {
      return null;
    }

    const headers: Record<string, string> = {};
    for (let i = 1; i < lines.length; i++) {
      const line = lines[i]?.trim();
      if (!line) continue;
      const colonIdx = line.indexOf(':');
      if (colonIdx !== -1) {
        const key = line.slice(0, colonIdx).trim().toLowerCase();
        const value = line.slice(colonIdx + 1).trim();
        headers[key] = value;
      }
    }

    const encapsulated = this.parseEncapsulatedHeader(headers['encapsulated']);
    const previewHeader = headers['preview'];
    const previewBytes = previewHeader ? parseInt(previewHeader, 10) : undefined;

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

    // If HTTP headers exist, extract them from remainingBuffer
    if (encapsulated.resHdr !== undefined || encapsulated.reqHdr !== undefined) {
      const httpHeaderStart =
        encapsulated.resHdr !== undefined ? encapsulated.resHdr : encapsulated.reqHdr!;
      const httpHeaderEnd = bodyOffset !== undefined ? bodyOffset : remainingBuffer.length;

      if (httpHeaderStart < remainingBuffer.length) {
        const httpHeaderText = remainingBuffer
          .slice(httpHeaderStart, Math.min(httpHeaderEnd, remainingBuffer.length))
          .toString('utf-8');

        const httpLines = httpHeaderText.split('\r\n');
        const firstHttpLine = httpLines[0]?.trim();

        if (firstHttpLine) {
          if (firstHttpLine.startsWith('HTTP/')) {
            // Response line: HTTP/1.1 200 OK
            const parts = firstHttpLine.split(/\s+/u);
            httpStatusCode = parseInt(parts[1] ?? '200', 10);
            httpStatusMessage = parts.slice(2).join(' ');
          } else {
            // Request line: GET /path HTTP/1.1
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

    if (bodyOffset !== undefined && bodyOffset < remainingBuffer.length) {
      const chunkedBodyPart = remainingBuffer.slice(bodyOffset);
      const decoded = this.decodeIcapChunks(chunkedBodyPart);
      rawBody = Buffer.from(decoded.data);
      isComplete = decoded.isComplete;
    } else if (encapsulated.nullBody !== undefined) {
      isComplete = true;
    }

    return {
      method,
      uri,
      version,
      headers,
      encapsulated,
      ...(previewBytes !== undefined ? { previewBytes } : {}),
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
      const offset = parseInt(val.trim(), 10);
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
   * Decodes ICAP chunked encoding (<hex-size>\r\n<data>\r\n... 0\r\n\r\n)
   */
  public static decodeIcapChunks(chunkBuffer: Buffer): { data: Buffer; isComplete: boolean } {
    const chunks: Buffer[] = [];
    let offset = 0;
    let isComplete = false;

    while (offset < chunkBuffer.length) {
      const newlineIndex = chunkBuffer.indexOf('\r\n', offset);
      if (newlineIndex === -1) {
        break;
      }

      const sizeLine = chunkBuffer.slice(offset, newlineIndex).toString('utf-8').trim();
      // Handle preview chunk marker: "0; ieof"
      const hexSizeStr = sizeLine.split(';')[0]?.trim() ?? '0';
      const chunkSize = parseInt(hexSizeStr, 16);

      if (isNaN(chunkSize) || chunkSize < 0) {
        break;
      }

      if (chunkSize === 0) {
        isComplete = true;
        break;
      }

      const chunkDataStart = newlineIndex + 2;
      const chunkDataEnd = chunkDataStart + chunkSize;

      if (chunkDataEnd > chunkBuffer.length) {
        // Incomplete chunk received so far
        chunks.push(chunkBuffer.slice(chunkDataStart));
        break;
      }

      chunks.push(chunkBuffer.slice(chunkDataStart, chunkDataEnd));
      offset = chunkDataEnd + 2; // skip trailing \r\n
    }

    return {
      data: Buffer.concat(chunks),
      isComplete,
    };
  }

  /**
   * Generates standard ICAP 200 OK response for OPTIONS method.
   */
  public static buildOptionsResponse(config?: IcapServerConfig): Buffer {
    const dateStr = new Date().toUTCString();
    const serviceName = config?.serviceName ?? 'sda-dlp';
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
    const violationSummary = violations
      .map((v) => `[${v.severity}] ${v.rule}: ${v.description}`)
      .join('\n');
    const violationCodes = violations.map((v) => v.type).join(', ');

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
    <div class="footer">SDA Enterprise Network Data Loss Prevention Gateway (RFC 3507 ICAP Server) &bull; Mã vi phạm: ${violationCodes}</div>
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
      `X-DLP-Violation: ${violationCodes}`,
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
