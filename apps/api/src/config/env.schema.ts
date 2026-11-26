/**
 * @module EnvSchema
 * Thuật toán: Thẩm định kiểu tĩnh và cưỡng chế bất biến an ninh biến môi trường bằng Zod (`EnvSchema` + `validateEnv`).
 */
import { z } from 'zod';
import {
  enforceStrictEnvironmentInvariants,
  normalizeLegacyEnvAliases,
  resolveTrustProxyConfig,
} from './env-strict.helper.js';

export { resolveTrustProxyConfig };

/**
 * Thuật toán: Chuẩn hóa chuỗi rỗng/chỉ chứa khoảng trắng từ Docker Compose (`${VAR:-}`) sang `undefined`
 * để các biến tùy chọn không bị lỗi xác thực `.min(...)` lúc khởi động container production.
 */
const emptyStringToUndefined = (val: unknown): unknown =>
  typeof val === 'string' && val.trim() === '' ? undefined : val;

const optionalNonEmptyString = (minLength = 1) =>
  z.preprocess(emptyStringToUndefined, z.string().min(minLength).optional());

const optionalString = () => z.preprocess(emptyStringToUndefined, z.string().optional());

const defaultedNonEmptyString = (fallback: string, minLength = 1) =>
  z.preprocess(emptyStringToUndefined, z.string().min(minLength).default(fallback));

const defaultedCoercedInt = (fallback: number, min: number, max?: number) => {
  const base =
    max !== undefined
      ? z.coerce.number().int().min(min).max(max)
      : z.coerce.number().int().min(min);
  return z.preprocess(emptyStringToUndefined, base.default(fallback));
};

export const EnvSchema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'staging', 'production']).default('development'),
    HOST: defaultedNonEmptyString('127.0.0.1'),
    PORT: defaultedCoercedInt(3001, 1, 65535),
    TRUST_PROXY: defaultedNonEmptyString('loopback'),
    CORS_ALLOWED_ORIGINS: defaultedNonEmptyString('http://localhost:3000,http://127.0.0.1:3000'),
    DATABASE_URL: z.preprocess(
      emptyStringToUndefined,
      z
        .string()
        .min(1, 'DATABASE_URL is required')
        .default('postgresql://localhost:5432/secure_docs?schema=public'),
    ),
    DATABASE_SSL: z.preprocess((val) => val === 'true' || val === true, z.boolean()).default(false),
    DATABASE_SSL_REJECT_UNAUTHORIZED: z
      .preprocess(
        (val) => (val === undefined ? true : val !== 'false' && val !== false),
        z.boolean(),
      )
      .default(true),
    DATABASE_CA_CERT: optionalNonEmptyString(1),
    REDIS_URL: z.preprocess(
      emptyStringToUndefined,
      z.string().min(1, 'REDIS_URL is required').default('redis://localhost:6379/0'),
    ),
    REDLOCK_CLUSTER_NODES: optionalString(),
    REDLOCK_RETRY_COUNT: defaultedCoercedInt(10, 0),
    REDLOCK_RETRY_DELAY_MS: defaultedCoercedInt(100, 10),
    REDLOCK_RETRY_JITTER_MS: defaultedCoercedInt(50, 0),
    REDLOCK_DEFAULT_TTL_MS: defaultedCoercedInt(5000, 500),
    REDLOCK_FAIL_CLOSED: z
      .preprocess(
        (val) => (val === undefined ? true : val !== 'false' && val !== false),
        z.boolean(),
      )
      .default(true),
    ABAC_TRUSTED_NETWORK_CIDRS: defaultedNonEmptyString('127.0.0.0/8,::1/128'),
    STORAGE_MOCK: z.preprocess((val) => val === 'true' || val === true, z.boolean()).default(false),
    STORAGE_ENDPOINT: defaultedNonEmptyString('127.0.0.1'),
    STORAGE_PORT: defaultedCoercedInt(9000, 1, 65535),
    STORAGE_REGION: defaultedNonEmptyString('us-east-1'),
    STORAGE_ACCESS_KEY: defaultedNonEmptyString('local-placeholder-access-key'),
    STORAGE_SECRET_KEY: defaultedNonEmptyString('local-placeholder-not-a-secret'),
    STORAGE_BUCKET_DOCUMENTS: defaultedNonEmptyString('secure-documents'),
    STORAGE_BUCKET_QUARANTINE: defaultedNonEmptyString('secure-quarantine'),
    STORAGE_BUCKET_DERIVATIVES: defaultedNonEmptyString('secure-derivatives'),
    STORAGE_USE_SSL: z
      .preprocess((val) => val === 'true' || val === true, z.boolean())
      .default(false),
    CLAMAV_HOST: defaultedNonEmptyString('127.0.0.1'),
    CLAMAV_PORT: defaultedCoercedInt(3310, 1, 65535),
    GOTENBERG_URL: defaultedNonEmptyString('http://127.0.0.1:3003'),
    GOTENBERG_ENABLED: z.preprocess(
      (val) =>
        val === undefined || val === null || (typeof val === 'string' && val.trim() === '')
          ? undefined
          : val === 'true' || val === true,
      z.boolean().default(true),
    ),
    UPLOAD_MAX_FILE_SIZE_BYTES: defaultedCoercedInt(52_428_800, 1024),
    ZIP_MAX_TOTAL_UNCOMPRESSED_SIZE: defaultedCoercedInt(209_715_200, 1024),
    ZIP_MAX_ENTRIES: defaultedCoercedInt(1000, 1),
    ZIP_MAX_DEPTH: defaultedCoercedInt(5, 1),
    ZIP_MAX_COMPRESSION_RATIO: z.preprocess(
      emptyStringToUndefined,
      z.coerce.number().min(1).default(20),
    ),
    DOCUMENT_AUDIT_HMAC_KEY: defaultedNonEmptyString(
      'local-only-document-audit-hmac-key-0000000000000000',
      32,
    ),
    LOG_LEVEL: z.preprocess(
      emptyStringToUndefined,
      z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),
    ),
    APP_ENCRYPTION_MASTER_KEY: z.preprocess(
      emptyStringToUndefined,
      z
        .string()
        .min(32, 'APP_ENCRYPTION_MASTER_KEY must be at least 32 characters')
        .default('local-placeholder-not-for-real-encryption-000000000000000000000000'),
    ),
    KMS_PROVIDER: z.preprocess(
      emptyStringToUndefined,
      z.enum(['local', 'hsm-pkcs11', 'vault', 'aws-kms']).default('local'),
    ),
    HSM_PIN: defaultedNonEmptyString('000000'),
    HSM_SLOT_INDEX: defaultedCoercedInt(0, 0),
    HSM_KEY_LABEL: defaultedNonEmptyString('SDA-MASTER-KEK-v1'),
    HSM_MODULE_PATH: optionalString(),
    VAULT_ADDR: defaultedNonEmptyString('http://127.0.0.1:8200'),
    VAULT_TOKEN: defaultedNonEmptyString('dev-mock-vault-token'),
    VAULT_KEY_NAME: defaultedNonEmptyString('sda-document-kek'),
    VAULT_TRANSIT_MOUNT: defaultedNonEmptyString('transit'),
    AWS_KMS_KEY_ID: defaultedNonEmptyString('alias/sda-master-kek'),
    AWS_KMS_REGION: defaultedNonEmptyString('us-east-1'),
    AUTH_ISSUER: defaultedNonEmptyString('secure-document-access-api', 3),
    AUTH_AUDIENCE: defaultedNonEmptyString('secure-document-access-web', 3),
    AUTH_ACTIVE_KID: z.preprocess(
      emptyStringToUndefined,
      z.string().min(1).default('development-ephemeral'),
    ),
    AUTH_SIGNING_PRIVATE_KEY_PEM: optionalNonEmptyString(1),
    AUTH_SIGNING_PUBLIC_KEYS_JSON: optionalNonEmptyString(2),
    AUTH_ACCESS_TTL_SECONDS: defaultedCoercedInt(300, 60, 900),
    AUTH_REFRESH_TTL_SECONDS: defaultedCoercedInt(604_800, 3600, 2_592_000),
    AUTH_SESSION_IDLE_TTL_SECONDS: defaultedCoercedInt(28_800, 300, 604_800),
    AUTH_SESSION_TOUCH_INTERVAL_SECONDS: defaultedCoercedInt(60, 10, 900),
    AUTH_MAX_CONCURRENT_SESSIONS: defaultedCoercedInt(10, 1, 100),
    AUTH_RESET_TTL_SECONDS: defaultedCoercedInt(900, 300, 3600),
    AUTH_AUDIT_HMAC_KEY: defaultedNonEmptyString(
      'local-only-audit-hmac-key-not-for-production',
      32,
    ),
    SMTP_HOST: defaultedNonEmptyString('127.0.0.1'),
    SMTP_PORT: defaultedCoercedInt(1025, 1, 65535),
    SMTP_SECURE: z.preprocess((val) => val === 'true' || val === true, z.boolean()).default(false),
    SMTP_USER: optionalNonEmptyString(1),
    SMTP_PASS: optionalNonEmptyString(1),
    SMTP_FROM: z.preprocess(
      emptyStringToUndefined,
      z.string().email().default('no-reply@secure-docs.internal'),
    ),
    PASSWORD_RESET_BASE_URL: z.preprocess(
      emptyStringToUndefined,
      z.string().url().default('http://localhost:3000/reset-password'),
    ),
    GRANT_MAX_DURATION_DAYS: defaultedCoercedInt(30, 1, 90),
    GRANT_EXPIRY_INTERVAL_MS: defaultedCoercedInt(60_000, 10_000, 300_000),
    DOWNLOAD_TICKET_TTL_SECONDS: defaultedCoercedInt(60, 10, 300),
    DERIVATIVE_TTL_MINUTES: defaultedCoercedInt(60, 5, 1440),
    AUDIT_INTEGRITY_KEY: defaultedNonEmptyString(
      'local-only-audit-integrity-hmac-key-0000000000000000',
      32,
    ),
    AUDIT_KEY_ROTATION_JSON: optionalString(),
    AUDIT_VERIFY_INTERVAL_MS: defaultedCoercedInt(300_000, 10_000, 3_600_000),
    WEBAUTHN_RP_NAME: defaultedNonEmptyString('Secure Document Access'),
    WEBAUTHN_RP_ID: defaultedNonEmptyString('localhost'),
    WEBAUTHN_ORIGINS: defaultedNonEmptyString('http://localhost:3000,http://127.0.0.1:3000'),
    METRICS_SCRAPE_TOKEN: optionalNonEmptyString(16),
    EXPORT_STORAGE_DIR: optionalNonEmptyString(1),
    EXPORT_ENCRYPTION_KEY: optionalNonEmptyString(32),
  })
  .superRefine(enforceStrictEnvironmentInvariants);

export type EnvConfig = z.infer<typeof EnvSchema>;

/**
 * Thuật toán: Chuẩn hóa bí danh biến môi trường tương thích ngược và thẩm định lược đồ Zod toàn cục.
 */
export function validateEnv(rawEnv: Record<string, unknown> = process.env): EnvConfig {
  const normalizedEnv = normalizeLegacyEnvAliases(rawEnv);
  const result = EnvSchema.safeParse(normalizedEnv);
  if (!result.success) {
    const formatted = result.error.issues
      .map((issue) => ` - ${issue.path.join('.')}: ${issue.message}`)
      .join('\n');
    throw new Error(
      `FATAL: Environment configuration validation failed. Missing or invalid required variables:\n${formatted}`,
    );
  }
  return result.data;
}
