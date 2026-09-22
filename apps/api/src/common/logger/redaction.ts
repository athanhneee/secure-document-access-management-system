export const SENSITIVE_KEYS = new Set([
  'authorization',
  'cookie',
  'set-cookie',
  'password',
  'password_hash',
  'newpassword',
  'currentpassword',
  'token',
  'accesstoken',
  'refreshtoken',
  'watermark_token',
  'watermarktoken',
  'secret',
  'jwt',
  'encryptionkey',
  'encryption_key',
  'encryption_key_ref',
  'dek',
  'kek',
  'key',
  'filecontent',
  'buffer',
  'content',
]);

export function redactSensitiveData(data: unknown, depth = 0): unknown {
  if (depth > 10 || data === null || data === undefined) {
    return data;
  }

  if (typeof data !== 'object') {
    return data;
  }

  if (Array.isArray(data)) {
    return data.map((item) => redactSensitiveData(item, depth + 1));
  }

  if (Buffer.isBuffer(data)) {
    return '[REDACTED_BUFFER]';
  }

  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(data as Record<string, unknown>)) {
    const normalizedKey = key.toLowerCase().replace(/[-_]/g, '');
    const isSensitive =
      SENSITIVE_KEYS.has(normalizedKey) ||
      SENSITIVE_KEYS.has(key.toLowerCase()) ||
      normalizedKey.includes('password') ||
      normalizedKey.includes('token') ||
      normalizedKey.includes('secret') ||
      normalizedKey.includes('encryptionkey');

    if (isSensitive) {
      result[key] = '[REDACTED]';
    } else if (typeof value === 'object' && value !== null) {
      result[key] = redactSensitiveData(value, depth + 1);
    } else {
      result[key] = value;
    }
  }

  return result;
}
