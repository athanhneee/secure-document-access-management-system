/**
 * @module EnvStrictHelper
 * Thuật toán: Thẩm định bất biến an ninh Fail-Fast cho cả hai môi trường `production` và `staging`,
 * từ chối cấu hình số bước nhảy `TRUST_PROXY` (`^\d+$`) chống giả mạo tiêu đề `X-Forwarded-For`,
 * và phân giải dải proxy tin cậy (`false`, `loopback`, `linklocal`, `uniquelocal`, hoặc danh sách IP/CIDR tường minh).
 */
import { isIP } from 'node:net';
import { z } from 'zod';
import { cidrMatch, isValidCidr } from '../modules/abac/cidr.js';

const STRICT_TRUST_PROXY_PRESETS = new Set(['false', 'loopback', 'linklocal', 'uniquelocal']);

const TRUST_PROXY_PRESET_CIDRS: Readonly<Record<string, readonly string[]>> = {
  loopback: ['127.0.0.0/8', '::1/128'],
  linklocal: ['169.254.0.0/16', 'fe80::/10'],
  uniquelocal: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7'],
};

function isValidIpOrCidr(entry: string): boolean {
  const slashIndex = entry.indexOf('/');
  if (slashIndex < 0) return isIP(entry) !== 0;
  const host = entry.slice(0, slashIndex);
  const prefixRaw = entry.slice(slashIndex + 1);
  if (!/^\d+$/.test(prefixRaw)) return false;
  const version = isIP(host);
  if (version === 4) {
    const prefix = Number.parseInt(prefixRaw, 10);
    return prefix >= 0 && prefix <= 32;
  }
  if (version === 6) {
    const prefix = Number.parseInt(prefixRaw, 10);
    return prefix >= 0 && prefix <= 128;
  }
  return false;
}

export interface StrictEnvShape {
  NODE_ENV: 'development' | 'test' | 'staging' | 'production';
  TRUST_PROXY: string;
  ABAC_TRUSTED_NETWORK_CIDRS: string;
  STORAGE_MOCK: boolean;
  STORAGE_BUCKET_DOCUMENTS: string;
  STORAGE_BUCKET_QUARANTINE: string;
  STORAGE_BUCKET_DERIVATIVES: string;
  STORAGE_ACCESS_KEY: string;
  STORAGE_SECRET_KEY: string;
  AUTH_SIGNING_PRIVATE_KEY_PEM?: string | undefined;
  AUTH_SIGNING_PUBLIC_KEYS_JSON?: string | undefined;
  APP_ENCRYPTION_MASTER_KEY: string;
  DOCUMENT_AUDIT_HMAC_KEY: string;
  AUTH_AUDIT_HMAC_KEY: string;
  AUDIT_INTEGRITY_KEY: string;
  KMS_PROVIDER: 'local' | 'hsm-pkcs11' | 'vault' | 'aws-kms';
  VAULT_TOKEN: string;
  DATABASE_SSL_REJECT_UNAUTHORIZED: boolean;
}

/**
 * Thuật toán: Cưỡng chế các bất biến bảo mật bắt buộc cho cả `production` lẫn `staging` (`superRefine`).
 */
export function enforceStrictEnvironmentInvariants(
  value: StrictEnvShape,
  context: z.RefinementCtx,
): void {
  const docBucket = value.STORAGE_BUCKET_DOCUMENTS.trim();
  const quarantineBucket = value.STORAGE_BUCKET_QUARANTINE.trim();
  const derivativesBucket = value.STORAGE_BUCKET_DERIVATIVES.trim();
  if (quarantineBucket === docBucket || quarantineBucket === derivativesBucket) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['STORAGE_BUCKET_QUARANTINE'],
      message:
        'STORAGE_BUCKET_QUARANTINE must be isolated in a separate bucket from STORAGE_BUCKET_DOCUMENTS and STORAGE_BUCKET_DERIVATIVES.',
    });
  }

  const isStrictEnv = value.NODE_ENV === 'production' || value.NODE_ENV === 'staging';
  if (!isStrictEnv) {
    return;
  }

  if (value.STORAGE_MOCK) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['STORAGE_MOCK'],
      message: 'STORAGE_MOCK=true is strictly forbidden in staging and production environments.',
    });
  }

  if (!value.AUTH_SIGNING_PRIVATE_KEY_PEM || !value.AUTH_SIGNING_PUBLIC_KEYS_JSON) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['AUTH_SIGNING_PRIVATE_KEY_PEM'],
      message: `${value.NODE_ENV} requires externally managed Ed25519 signing keys.`,
    });
  }

  const forbiddenDefaults: Array<[keyof StrictEnvShape, string]> = [
    [
      'APP_ENCRYPTION_MASTER_KEY',
      'local-placeholder-not-for-real-encryption-000000000000000000000000',
    ],
    ['DOCUMENT_AUDIT_HMAC_KEY', 'local-only-document-audit-hmac-key-0000000000000000'],
    ['AUTH_AUDIT_HMAC_KEY', 'local-only-audit-hmac-key-not-for-production'],
    ['AUDIT_INTEGRITY_KEY', 'local-only-audit-integrity-hmac-key-0000000000000000'],
    ['STORAGE_ACCESS_KEY', 'local-placeholder-access-key'],
    ['STORAGE_SECRET_KEY', 'local-placeholder-not-a-secret'],
  ];

  for (const [field, placeholder] of forbiddenDefaults) {
    const current = String(value[field] ?? '');
    if (
      current === placeholder ||
      current.startsWith('local-only-') ||
      current.startsWith('local-placeholder-')
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: [field],
        message: `${String(field)} cannot use development placeholder secrets in ${value.NODE_ENV}.`,
      });
    }
  }

  if (value.KMS_PROVIDER === 'hsm-pkcs11' || value.KMS_PROVIDER === 'aws-kms') {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['KMS_PROVIDER'],
      message: `KMS_PROVIDER="${value.KMS_PROVIDER}" is a simulated adapter and cannot be used in ${value.NODE_ENV}; use "vault" or externally managed "local" master key.`,
    });
  }

  if (!value.DATABASE_SSL_REJECT_UNAUTHORIZED) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['DATABASE_SSL_REJECT_UNAUTHORIZED'],
      message: `CWE-295: Disabling DATABASE_SSL_REJECT_UNAUTHORIZED is forbidden in ${value.NODE_ENV}; configure DATABASE_CA_CERT instead.`,
    });
  }

  if (value.KMS_PROVIDER === 'vault' && value.VAULT_TOKEN === 'dev-mock-vault-token') {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['VAULT_TOKEN'],
      message: `${value.NODE_ENV} Vault KMS requires a non-placeholder VAULT_TOKEN.`,
    });
  }

  const normalizedTrustProxy = value.TRUST_PROXY.trim().toLowerCase();
  if (normalizedTrustProxy === 'true' || /^\d+$/.test(normalizedTrustProxy)) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['TRUST_PROXY'],
      message: `Wildcard or integer hop TRUST_PROXY="${value.TRUST_PROXY}" is forbidden in ${value.NODE_ENV} to prevent X-Forwarded-For spoofing; use "false", "loopback", "linklocal", "uniquelocal", or an explicit IP/CIDR list.`,
    });
  } else if (!STRICT_TRUST_PROXY_PRESETS.has(normalizedTrustProxy)) {
    const entries = value.TRUST_PROXY.split(',')
      .map((item) => item.trim())
      .filter(Boolean);
    const isAllowedEntry = (entry: string): boolean => {
      const lowered = entry.toLowerCase();
      return Object.hasOwn(TRUST_PROXY_PRESET_CIDRS, lowered) || isValidIpOrCidr(entry);
    };
    if (entries.length === 0 || !entries.every(isAllowedEntry)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['TRUST_PROXY'],
        message: `TRUST_PROXY in ${value.NODE_ENV} must be "false", "loopback", "linklocal", "uniquelocal", or a comma-separated list of valid IP/CIDR/preset entries.`,
      });
    }
  }

  const trustedCidrs = value.ABAC_TRUSTED_NETWORK_CIDRS.split(',')
    .map((cidr) => cidr.trim())
    .filter(Boolean);
  if (trustedCidrs.some((cidr) => !isValidCidr(cidr))) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['ABAC_TRUSTED_NETWORK_CIDRS'],
      message: `ABAC_TRUSTED_NETWORK_CIDRS in ${value.NODE_ENV} contains an invalid IP/CIDR entry.`,
    });
  } else if (trustedCidrs.some((cidr) => cidrMatch('127.0.0.1', cidr) || cidrMatch('::1', cidr))) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['ABAC_TRUSTED_NETWORK_CIDRS'],
      message: `Loopback-covering CIDRs (e.g. 127.0.0.0/8, ::1/128, 0.0.0.0/0, ::/0, ::ffff:127.0.0.1/128) are forbidden in ABAC_TRUSTED_NETWORK_CIDRS in ${value.NODE_ENV} to prevent reverse-proxy trustedNetwork bypass.`,
    });
  }
}

/**
 * Thuật toán: Phân giải cấu hình `trustProxy` cho Fastify từ chuỗi môi trường (`false`, `loopback`, `linklocal`, `uniquelocal`, số bước nhảy ở dev hoặc danh sách kết hợp preset/CIDR).
 */
export function resolveTrustProxyConfig(
  raw?: string,
): boolean | string[] | ((address: string, hop: number) => boolean) {
  const normalized = (raw ?? 'loopback').trim().toLowerCase();
  if (!normalized || normalized === 'false' || normalized === '0' || normalized === 'off') {
    return false;
  }
  const singlePreset = Object.hasOwn(TRUST_PROXY_PRESET_CIDRS, normalized)
    ? TRUST_PROXY_PRESET_CIDRS[normalized]
    : undefined;
  if (singlePreset) {
    return [...singlePreset];
  }
  if (normalized === 'true') {
    return true;
  }
  if (/^\d+$/.test(normalized)) {
    const maxHops = Number.parseInt(normalized, 10);
    return (_address: string, hop: number) => hop <= maxHops;
  }
  const resolved: string[] = [];
  for (const entry of (raw ?? '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean)) {
    const lowerEntry = entry.toLowerCase();
    const presetCidrs = Object.hasOwn(TRUST_PROXY_PRESET_CIDRS, lowerEntry)
      ? TRUST_PROXY_PRESET_CIDRS[lowerEntry]
      : undefined;
    if (presetCidrs) {
      resolved.push(...presetCidrs);
    } else {
      resolved.push(entry);
    }
  }
  return [...new Set(resolved)];
}

/**
 * Thuật toán: Ánh xạ các biến bí danh cấu hình thế hệ cũ sang tên chuẩn hiện hành.
 */
export function normalizeLegacyEnvAliases(
  rawEnv: Record<string, unknown>,
): Record<string, unknown> {
  const normalizedEnv: Record<string, unknown> = { ...rawEnv };
  if (!normalizedEnv['HOST'] && normalizedEnv['API_HOST']) {
    normalizedEnv['HOST'] = normalizedEnv['API_HOST'];
  }
  if (normalizedEnv['API_PORT']) {
    normalizedEnv['PORT'] = normalizedEnv['API_PORT'];
  }
  if (!normalizedEnv['AUTH_SIGNING_PRIVATE_KEY_PEM'] && normalizedEnv['JWT_PRIVATE_KEY']) {
    normalizedEnv['AUTH_SIGNING_PRIVATE_KEY_PEM'] = normalizedEnv['JWT_PRIVATE_KEY'];
  }
  if (!normalizedEnv['AUTH_SIGNING_PUBLIC_KEYS_JSON'] && normalizedEnv['JWT_PUBLIC_KEY']) {
    normalizedEnv['AUTH_SIGNING_PUBLIC_KEYS_JSON'] = JSON.stringify([
      {
        kid: String(normalizedEnv['AUTH_ACTIVE_KID'] ?? 'production-default'),
        publicKeyPem: String(normalizedEnv['JWT_PUBLIC_KEY']),
      },
    ]);
  }
  if (!normalizedEnv['APP_ENCRYPTION_MASTER_KEY'] && normalizedEnv['KMS_MASTER_KEY']) {
    normalizedEnv['APP_ENCRYPTION_MASTER_KEY'] = normalizedEnv['KMS_MASTER_KEY'];
  }
  if (!normalizedEnv['DOCUMENT_AUDIT_HMAC_KEY'] && normalizedEnv['AUDIT_HMAC_KEY']) {
    normalizedEnv['DOCUMENT_AUDIT_HMAC_KEY'] = normalizedEnv['AUDIT_HMAC_KEY'];
  }
  if (!normalizedEnv['AUTH_AUDIT_HMAC_KEY'] && normalizedEnv['AUDIT_HMAC_KEY']) {
    normalizedEnv['AUTH_AUDIT_HMAC_KEY'] = normalizedEnv['AUDIT_HMAC_KEY'];
  }
  if (!normalizedEnv['AUDIT_INTEGRITY_KEY'] && normalizedEnv['AUDIT_HMAC_KEY']) {
    normalizedEnv['AUDIT_INTEGRITY_KEY'] = normalizedEnv['AUDIT_HMAC_KEY'];
  }
  return normalizedEnv;
}
