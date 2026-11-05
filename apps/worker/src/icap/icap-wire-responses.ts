import type { IcapServerConfig, DlpViolation } from './icap.types.js';

/**
 * Algorithm / Thuật toán: Mã hóa thực thể ký tự đặc biệt HTML (HTML Entity Escaping) chống XSS
 * và khử độc ký tự xuống dòng CRLF trong trường header chống tấn công Response Splitting.
 */
export function escapeHtml(input: string): string {
  return input
    .replace(/&/gu, '&amp;')
    .replace(/</gu, '&lt;')
    .replace(/>/gu, '&gt;')
    .replace(/"/gu, '&quot;')
    .replace(/'/gu, '&#39;');
}

export function sanitizeHeaderToken(input: string): string {
  return input.replace(/[\r\n]+/gu, ' ').trim();
}

/**
 * Algorithm / Thuật toán: Tạo bản tin thương lượng năng lực dịch vụ ICAP `OPTIONS 200 OK` (RFC 3507 §4.10),
 * công bố phương thức hỗ trợ (`RESPMOD, REQMOD`), kích thước `Preview`, `Allow: 204`, `ISTag` và `Encapsulated: null-body=0`.
 */
export function buildOptionsResponse(config?: IcapServerConfig): Buffer {
  const dateStr = new Date().toUTCString();
  const serviceName = sanitizeHeaderToken(config?.serviceName ?? 'sda-dlp');
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
 * Algorithm / Thuật toán: Đóng gói phản hồi thông qua nhanh `ICAP/1.0 204 No modifications` (RFC 3507 §4.6)
 * báo cho cổng proxy/gateway giữ nguyên bản tin HTTP gốc khi nội dung vượt qua kiểm tra DLP sạch.
 */
export function build204Response(): Buffer {
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

export function buildContinueResponse(): Buffer {
  return Buffer.from('ICAP/1.0 100 Continue\r\n\r\n', 'utf-8');
}

export function buildProtocolErrorResponse(statusCode: 400 | 405 | 500): Buffer {
  const reason =
    statusCode === 405 ? 'Method Not Allowed' : statusCode === 400 ? 'Bad Request' : 'Server Error';
  return Buffer.from(`ICAP/1.0 ${statusCode} ${reason}\r\nConnection: close\r\n\r\n`, 'utf-8');
}

/**
 * Algorithm / Thuật toán: Đóng gói bản tin thay thế nội dung `ICAP/1.0 200 OK` chứa phản hồi chặn `HTTP/1.1 403 Forbidden`.
 * Cơ chế: Làm sạch mã vi phạm chống XSS/CRLF injection, mã hóa thân HTML theo khung hex-chunked `<hexLen>\r\n<html>\r\n0\r\n\r\n`
 * và tính toán chính xác cặp byte-offset `Encapsulated: res-hdr=0, res-body=<httpHeaderLength>`.
 */
export function buildBlockResponse(violations: DlpViolation[]): Buffer {
  const dateStr = new Date().toUTCString();
  const violationSummary = escapeHtml(
    violations.map((v) => `[${v.severity}] ${v.rule}: ${v.description}`).join('\n'),
  );
  const rawViolationCodes = violations.map((v) => v.type).join(', ');
  const safeHeaderViolationCodes = sanitizeHeaderToken(rawViolationCodes);
  const safeHtmlViolationCodes = escapeHtml(rawViolationCodes);

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
  const hexSize = htmlBuffer.length.toString(16);
  const chunkedBody = Buffer.concat([
    Buffer.from(`${hexSize}\r\n`, 'utf-8'),
    htmlBuffer,
    Buffer.from('\r\n0\r\n\r\n', 'utf-8'),
  ]);

  const icapHeaders = [
    'ICAP/1.0 200 OK',
    `Date: ${dateStr}`,
    'Server: SDA Network DLP ICAP Server/1.0',
    'Connection: close',
    'ISTag: "SDA-DLP-1.0.0"',
    `Encapsulated: res-hdr=0, res-body=${httpHeaderBuffer.length}`,
    '',
    '',
  ].join('\r\n');

  return Buffer.concat([Buffer.from(icapHeaders, 'utf-8'), httpHeaderBuffer, chunkedBody]);
}
