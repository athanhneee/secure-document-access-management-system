import { Injectable } from '@nestjs/common';

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
 * Dedicated Audit Redaction Service.
 *
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
    'passphrase',
    'secret',
    'rawtoken',
    'token',
    'accesstoken',
    'refreshtoken',
    'authtoken',
    'downloadticket',
    'ticket',
    'cookie',
    'cookies',
    'setcookie',
    'dek',
    'kek',
    'masterkey',
    'encryptionkey',
    'encryption_key_ref',
    'key',
    'plaintext',
    'content',
    'filecontent',
    'filedata',
    'data',
    'buffer',
    'totpsecret',
    'totp',
    'recoverycode',
    'mfasecret',
    'creditcard',
    'cvv',
    'ssn',
    'privatekey',
    'privatekeypem',
    'signingkey',
  ]);

  /**
   * Patterns to detect secrets embedded within string fields.
   */
  private readonly jwtRegex = /ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+/g;
  private readonly bearerRegex = /Bearer\s+[A-Za-z0-9._~+/-]+=*/gi;
  private readonly downloadTicketRegex = /DT-[0-9a-f]{64}/gi;
  private readonly watermarkTokenRegex = /WM-[0-9a-f]{16,64}/gi;

  /**
   * Normalizes and sanitizes user agent strings.
   * Strips non-printable/control characters and clamps length to max 255 characters.
   */
  sanitizeUserAgent(userAgent?: string | null): string | null {
    if (!userAgent) return null;
    const clean = stripControlCharacters(userAgent, ' ').trim();
    if (clean.length === 0) return null;
    return clean.length > 255 ? `${clean.substring(0, 252)}...` : clean;
  }

  /**
   * Sanitizes an IP address string.
   */
  sanitizeIp(ip?: string | null): string | null {
    if (!ip) return null;
    const clean = stripControlCharacters(ip, '').trim();
    return clean.length > 45 ? clean.substring(0, 45) : clean;
  }

  /**
   * Sanitizes reasonCode or reason strings.
   */
  sanitizeReason(reason?: string | null, maxLength = 255): string | null {
    if (!reason) return null;
    let sanitized = reason
      .replace(this.jwtRegex, '[REDACTED_JWT]')
      .replace(this.bearerRegex, 'Bearer [REDACTED]')
      .replace(this.downloadTicketRegex, '[REDACTED_TICKET]')
      .replace(this.watermarkTokenRegex, '[REDACTED_WM_TOKEN]');

    sanitized = stripControlCharacters(sanitized, ' ').trim();

    if (sanitized.length > maxLength) {
      sanitized = `${sanitized.substring(0, maxLength - 3)}...`;
    }
    return sanitized;
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

  private isSensitiveKey(key: string): boolean {
    const normalized = key.toLowerCase().replace(/[^a-z0-9]/g, '');
    return this.sensitiveKeyPatterns.has(normalized);
  }

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

    if (typeof val === 'number' || typeof val === 'boolean' || typeof val === 'bigint') {
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
    // Avoid DoS from unbounded string sizes in audit details
    let text = str;
    if (text.length > 4096) {
      text = `${text.substring(0, 4090)}...[TRUNCATED]`;
    }

    text = text
      .replace(this.jwtRegex, '[REDACTED_JWT]')
      .replace(this.bearerRegex, 'Bearer [REDACTED]')
      .replace(this.downloadTicketRegex, '[REDACTED_TICKET]')
      .replace(this.watermarkTokenRegex, '[REDACTED_WM_TOKEN]');

    return stripNonPrintableChars(text);
  }
}
