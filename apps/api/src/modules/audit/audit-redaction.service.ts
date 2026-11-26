import { isIP } from 'node:net';
import { Injectable } from '@nestjs/common';

/**
 * Thuật toán: Quét tuyến tính thay thế mã điều khiển ASCII/C1 (`0..31`, `127..159`) chống Log Injection / CRLF Forging.
 */
function stripControlCharacters(input: string, replaceWith = ' '): string {
  let output = '';
  for (let i = 0; i < input.length; i++) {
    const code = input.charCodeAt(i);
    if ((code >= 0 && code <= 31) || (code >= 127 && code <= 159)) {
      if (replaceWith) output += replaceWith;
    } else {
      output += input[i];
    }
  }
  return output;
}

function stripNonPrintableChars(input: string): string {
  let output = '';
  for (let i = 0; i < input.length; i++) {
    const code = input.charCodeAt(i);
    if ((code >= 0 && code <= 8) || code === 11 || code === 12 || (code >= 14 && code <= 31)) {
      continue;
    }
    output += input[i];
  }
  return output;
}

/**
 * Thuật toán: Cắt ngắn chuỗi bảo toàn biên cặp đại diện UTF-16 (`High Surrogate 0xD800..0xDBFF` / `Low Surrogate 0xDC00..0xDFFF`)
 * đảm bảo độ dài sau cắt (tính cả hậu tố) không vượt quá `maxLength` và không sinh ký tự mồ côi làm hỏng JCS RFC 8785 (BUG-111).
 */
function stripLoneSurrogates(input: string): string {
  let out = '';
  for (let i = 0; i < input.length; i++) {
    const code = input.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = i + 1 < input.length ? input.charCodeAt(i + 1) : 0;
      if (next >= 0xdc00 && next <= 0xdfff) {
        out += input[i]! + input[i + 1]!;
        i += 1;
      } else {
        out += '\uFFFD';
      }
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      out += '\uFFFD';
    } else {
      out += input[i]!;
    }
  }
  return out;
}

function truncateUtf16Safe(input: string, maxLength: number, suffix = '...'): string {
  if (input.length <= maxLength) return input;
  if (maxLength <= suffix.length) {
    let end = Math.max(0, maxLength);
    if (end > 0) {
      const prevCode = input.charCodeAt(end - 1);
      if (prevCode >= 0xd800 && prevCode <= 0xdbff) end -= 1;
    }
    return input.slice(0, end);
  }
  let cutIndex = maxLength - suffix.length;
  const boundaryCode = input.charCodeAt(cutIndex - 1);
  if (boundaryCode >= 0xd800 && boundaryCode <= 0xdbff) {
    cutIndex -= 1;
  }
  return `${input.slice(0, cutIndex)}${suffix}`;
}

/**
 * Thuật toán: Chuẩn hóa địa chỉ IPv4 / IPv6 về dạng chuẩn tắc RFC 5952 khớp 1-1 với hàm `inet_out` của PostgreSQL 18 (`BUG-060`).
 *   - IPv4: chuẩn hóa 4 octet thập phân bỏ số 0 đầu (`010.0.0.1` -> `10.0.0.1`).
 *   - IPv6: giải nén `::` và hậu tố IPv4 nhúng (`::ffff:127.0.0.1`) thành 8 từ 16-bit, rút gọn dải `0` liên tiếp dài nhất đầu tiên có độ dài `>= 2` thành `::` (không rút gọn 1 từ `0` đơn lẻ),
 *     in chữ thường thập lục phân bỏ số 0 đầu, và bảo toàn biểu diễn thập phân chấm cho địa chỉ IPv4-mapped / IPv4-compatible (`::ffff:127.0.0.1`, `::192.168.1.1`) khớp tuyệt đối `pg_inet_net_ntop_ipv6` (tuyệt đối không dùng `new URL()` biến `::ffff:127.0.0.1` thành `::ffff:7f00:1`).
 */
export function canonicalizePostgresInetAddress(rawIp: string): string | null {
  const version = isIP(rawIp);
  if (version === 0) return null;

  if (version === 4) {
    const parts = rawIp.split('.');
    if (parts.length !== 4) return null;
    const normalized = parts.map((p) => Number.parseInt(p, 10));
    if (normalized.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
    return normalized.join('.');
  }

  // IPv6 (version === 6)
  let working = rawIp.toLowerCase();
  let embeddedIpv4Words: [number, number] | null = null;

  const lastColon = working.lastIndexOf(':');
  if (lastColon !== -1 && working.slice(lastColon + 1).includes('.')) {
    const ipv4Tail = working.slice(lastColon + 1);
    if (isIP(ipv4Tail) !== 4) return null;
    const octets = ipv4Tail.split('.').map((o) => Number.parseInt(o, 10));
    embeddedIpv4Words = [
      ((octets[0]! << 8) | octets[1]!) >>> 0,
      ((octets[2]! << 8) | octets[3]!) >>> 0,
    ];
    working = `${working.slice(0, lastColon)}:0:0`;
  }

  const doubleColonParts = working.split('::');
  if (doubleColonParts.length > 2) return null;

  const parseHextets = (segment: string): number[] => {
    if (segment.length === 0) return [];
    return segment.split(':').map((h) => Number.parseInt(h, 16));
  };

  let words: number[];
  if (doubleColonParts.length === 2) {
    const left = parseHextets(doubleColonParts[0]!);
    const right = parseHextets(doubleColonParts[1]!);
    const missing = 8 - (left.length + right.length);
    if (missing < 1) return null;
    words = [...left, ...new Array<number>(missing).fill(0), ...right];
  } else {
    words = parseHextets(working);
  }

  if (words.length !== 8 || words.some((w) => !Number.isInteger(w) || w < 0 || w > 0xffff)) {
    return null;
  }

  if (embeddedIpv4Words) {
    words[6] = embeddedIpv4Words[0];
    words[7] = embeddedIpv4Words[1];
  }

  let bestBase = -1;
  let bestLen = 0;
  let curBase = -1;
  let curLen = 0;

  for (let i = 0; i < 8; i++) {
    if (words[i] === 0) {
      if (curBase === -1) {
        curBase = i;
        curLen = 1;
      } else {
        curLen += 1;
      }
    } else {
      if (curBase !== -1) {
        if (curLen >= 2 && curLen > bestLen) {
          bestBase = curBase;
          bestLen = curLen;
        }
        curBase = -1;
        curLen = 0;
      }
    }
  }
  if (curBase !== -1 && curLen >= 2 && curLen > bestLen) {
    bestBase = curBase;
    bestLen = curLen;
  }

  const useDottedIpv4Tail =
    bestBase === 0 &&
    (bestLen === 6 ||
      (bestLen === 5 && words[5] === 0xffff) ||
      (bestLen === 7 && words[7] !== 0x0001 && words[7] !== 0x0000));

  const chunks: string[] = [];
  for (let i = 0; i < 8; i++) {
    if (bestBase !== -1 && i >= bestBase && i < bestBase + bestLen) {
      if (i === bestBase) {
        chunks.push('');
      }
      continue;
    }
    if (i === 6 && useDottedIpv4Tail) {
      const w6 = words[6]!;
      const w7 = words[7]!;
      chunks.push(`${(w6 >> 8) & 0xff}.${w6 & 0xff}.${(w7 >> 8) & 0xff}.${w7 & 0xff}`);
      break;
    }
    chunks.push(words[i]!.toString(16));
  }

  if (bestBase === 0) {
    chunks.unshift('');
  }
  if (bestBase !== -1 && bestBase + bestLen === 8) {
    chunks.push('');
  }

  return chunks.join(':');
}

/**
 * Ensures that sensitive credentials, encryption keys, tokens, session cookies,
 * or plaintext document contents never leak into the audit trail.
 *
 * Adheres strictly to Principle 5:
 * "Không lưu password, raw token, cookie, DEK, KEK, plaintext tài liệu hoặc reason chứa dữ liệu quá nhạy cảm chưa lọc."
 */
@Injectable()
export class AuditRedactionService {
  /**
   * Keys that are strictly redacted if found anywhere in an audit payload (case-insensitive).
   */
  private readonly sensitiveKeyPatterns = new Set([
    'password',
    'passwordhash',
    'passphrase',
    'passcode',
    'secret',
    'rawtoken',
    'token',
    'accesstoken',
    'refreshtoken',
    'authtoken',
    'csrftoken',
    'resettoken',
    'sessiontoken',
    'bearertoken',
    'vaulttoken',
    'watermarktoken',
    'downloadticket',
    'ticket',
    'cookie',
    'cookies',
    'setcookie',
    'cookieheader',
    'authorization',
    'jwt',
    'apikey',
    'accesskey',
    'secretkey',
    'secretaccesskey',
    'clientsecret',
    'signingsecret',
    'sharedsecret',
    'webhooksecret',
    'hmackey',
    'dek',
    'kek',
    'masterkey',
    'encryptionkey',
    'encryptionkeyref',
    'key',
    'plaintext',
    'content',
    'filecontent',
    'filedata',
    'data',
    'buffer',
    'totpsecret',
    'totp',
    'otp',
    'hsmpin',
    'pin',
    'recoverycode',
    'recoverycodes',
    'backupcode',
    'mfasecret',
    'creditcard',
    'cvv',
    'ssn',
    'privatekey',
    'privatekeypem',
    'signingkey',
  ]);

  /**
   * Non-secret audit metadata keys explicitly exempt from suffix-based redaction.
   */
  private readonly safeMetadataKeys = new Set([
    'hmackeyversion',
    'keyversion',
    'signerkeyid',
    'tokenversion',
    'tokencount',
    'maxtokens',
    'passwordchangedat',
    'passwordresetrequired',
    'keyid',
    'keycount',
    'publickeyid',
  ]);

  /**
   * Patterns to detect secrets embedded within string fields.
   */
  private readonly jwtRegex = /ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+/g;
  private readonly bearerRegex = /Bearer\s+[A-Za-z0-9._~+/-]+=*/gi;
  private readonly cookieSecretRegex = /(sda_(?:access|refresh|csrf))=([^;\s]+)/gi;
  private readonly downloadTicketRegex = /DT-[0-9a-f]{64}/gi;
  private readonly watermarkTokenRegex = /WM-[0-9a-f]{12,64}/gi;

  /**
   * Normalizes and sanitizes user agent strings.
   * Strips non-printable/control characters and clamps length to max 255 characters.
   */
  sanitizeUserAgent(userAgent?: string | null): string | null {
    if (!userAgent) return null;
    const clean = stripControlCharacters(userAgent, ' ').trim();
    if (clean.length === 0) return null;
    return truncateUtf16Safe(clean, 255);
  }

  /**
   * Thuật toán: Chuẩn hóa và kiểm định địa chỉ IPv4/IPv6 theo RFC 5952 khớp 1-1 với `inet_out` của PostgreSQL (`BUG-060`).
   * Loại bỏ ký tự điều khiển, hậu tố zone index IPv6 (`%eth0`) và trả về `null` nếu chuỗi rỗng hoặc không phải địa chỉ IP hợp lệ.
   */
  sanitizeIp(ip?: string | null): string | null {
    if (!ip) return null;
    const clean = stripControlCharacters(ip, '').trim().split('%')[0]?.trim() ?? '';
    if (clean.length === 0 || clean.length > 45) return null;
    return canonicalizePostgresInetAddress(clean);
  }

  /**
   * Thuật toán: Che dấu mẫu nhạy cảm trong `reasonCode` / `reason` trước rồi mới kẹp trần tối đa `80` ký tự (`VARCHAR(80)`)
   * bảo toàn cặp đại diện UTF-16 để không bao giờ tràn cột `audit_logs.reason_code` (BUG-111).
   */
  sanitizeReason(reason?: string | null, maxLength = 80): string | null {
    if (!reason) return null;
    let sanitized = reason
      .replace(this.jwtRegex, '[REDACTED_JWT]')
      .replace(this.bearerRegex, 'Bearer [REDACTED]')
      .replace(this.cookieSecretRegex, '$1=[REDACTED_COOKIE]')
      .replace(this.downloadTicketRegex, '[REDACTED_TICKET]')
      .replace(this.watermarkTokenRegex, '[REDACTED_WM_TOKEN]');

    sanitized = stripControlCharacters(sanitized, ' ').trim();
    const effectiveMax = Math.max(4, Math.min(maxLength, 80));
    return truncateUtf16Safe(sanitized, effectiveMax);
  }

  /**
   * Recursively scrubs sensitive data from arbitrary audit detail structures.
   */
  sanitizeDetails(details?: Record<string, unknown> | null): Record<string, unknown> {
    if (!details || typeof details !== 'object') {
      return {};
    }

    return this.scrubValue(details, 0) as Record<string, unknown>;
  }

  /**
   * Thuật toán: Nhận diện tên khóa nhạy cảm chuẩn hóa O(1) kết hợp hậu tố phòng thủ (`*password*`, `*secret`, `*token`, `*key`, `*cookie`, `*credential`).
   */
  private isSensitiveKey(key: string): boolean {
    const normalized = key.toLowerCase().replace(/[^a-z0-9]/g, '');
    if (this.safeMetadataKeys.has(normalized)) {
      return false;
    }
    if (this.sensitiveKeyPatterns.has(normalized)) {
      return true;
    }
    return (
      normalized.includes('password') ||
      normalized.includes('passphrase') ||
      normalized.endsWith('secret') ||
      normalized.endsWith('token') ||
      normalized.endsWith('cookie') ||
      normalized.endsWith('cookies') ||
      normalized.endsWith('privatekey') ||
      normalized.endsWith('apikey') ||
      normalized.endsWith('hmackey') ||
      normalized.endsWith('encryptionkey') ||
      normalized.endsWith('encryptionkeyref') ||
      normalized.endsWith('credential') ||
      normalized.endsWith('credentials')
    );
  }

  /**
   * Thuật toán: Duyệt cây theo chiều sâu giới hạn bậc `depth <= 8` che dấu khóa và mẫu chuỗi nhạy cảm (Depth-Bounded DFS Redaction).
   * Cơ chế hoạt động: Cắt ngắn độ sâu tại mức 8 chống tấn công lồng đối tượng sâu (Deep-Nesting DoS), chuẩn hóa tên khóa
   * chữ thường bỏ ký tự phân cách để đối chiếu O(1) với `sensitiveKeyPatterns`, và quét biểu thức chính quy lọc JWT/Bearer/Ticket.
   */
  private scrubValue(val: unknown, depth: number): unknown {
    if (depth > 8) {
      return '[MAX_DEPTH_EXCEEDED]';
    }

    if (val === null || val === undefined) {
      return null;
    }

    if (typeof val === 'string') {
      return this.scrubString(val);
    }

    if (typeof val === 'bigint') {
      // CONFLICT-RESOLVED: Chuyển BigInt sang chuỗi thập phân tương thích chuẩn JCS RFC 8785 để Prisma JsonB không ném lỗi JSON.stringify.
      return val.toString();
    }

    if (typeof val === 'number' || typeof val === 'boolean') {
      return val;
    }

    if (val instanceof Date) {
      return val.toISOString();
    }

    if (Array.isArray(val)) {
      return val.map((item) => this.scrubValue(item, depth + 1));
    }

    if (typeof val === 'object') {
      const result: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(val as Record<string, unknown>)) {
        if (this.isSensitiveKey(k)) {
          result[k] = '[REDACTED]';
        } else {
          result[k] = this.scrubValue(v, depth + 1);
        }
      }
      return result;
    }

    return '[UNSUPPORTED_TYPE]';
  }

  private scrubString(str: string): string {
    // Avoid DoS from unbounded string sizes in audit details while preserving UTF-16 surrogate pairs (MED-02)
    let text = str;
    if (text.length > 4096) {
      text = truncateUtf16Safe(text, 4096, '...[TRUNCATED]');
    }
    text = stripLoneSurrogates(text);

    text = text
      .replace(this.jwtRegex, '[REDACTED_JWT]')
      .replace(this.bearerRegex, 'Bearer [REDACTED]')
      .replace(this.cookieSecretRegex, '$1=[REDACTED_COOKIE]')
      .replace(this.downloadTicketRegex, '[REDACTED_TICKET]')
      .replace(this.watermarkTokenRegex, '[REDACTED_WM_TOKEN]');

    return stripNonPrintableChars(text);
  }
}
