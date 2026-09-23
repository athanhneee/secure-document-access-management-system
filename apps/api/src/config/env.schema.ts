import { z } from 'zod';

export const EnvSchema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    HOST: z.string().default('127.0.0.1'),
    PORT: z.coerce.number().int().min(1).max(65535).default(3001),
    CORS_ALLOWED_ORIGINS: z.string().default('http://localhost:3000,http://127.0.0.1:3000'),
    DATABASE_URL: z
      .string()
      .min(1, 'DATABASE_URL is required')
      .default('postgresql://localhost:5432/secure_docs?schema=public'),
    REDIS_URL: z.string().min(1, 'REDIS_URL is required').default('redis://localhost:6379/0'),
    ABAC_TRUSTED_NETWORK_CIDRS: z.string().default('127.0.0.0/8,::1/128'),
    STORAGE_ENDPOINT: z.string().default('127.0.0.1'),
    STORAGE_PORT: z.coerce.number().int().min(1).max(65535).default(9000),
    STORAGE_ACCESS_KEY: z.string().default('local-placeholder-access-key'),
    STORAGE_SECRET_KEY: z.string().default('local-placeholder-not-a-secret'),
    STORAGE_BUCKET_DOCUMENTS: z.string().default('secure-documents'),
    STORAGE_BUCKET_QUARANTINE: z.string().default('secure-quarantine'),
    STORAGE_BUCKET_DERIVATIVES: z.string().default('secure-derivatives'),
    STORAGE_USE_SSL: z
      .preprocess((val) => val === 'true' || val === true, z.boolean())
      .default(false),
    CLAMAV_HOST: z.string().default('127.0.0.1'),
    CLAMAV_PORT: z.coerce.number().int().min(1).max(65535).default(3310),
    UPLOAD_MAX_FILE_SIZE_BYTES: z.coerce.number().int().min(1024).default(52_428_800),
    ZIP_MAX_TOTAL_UNCOMPRESSED_SIZE: z.coerce.number().int().min(1024).default(209_715_200),
    ZIP_MAX_ENTRIES: z.coerce.number().int().min(1).default(1000),
    ZIP_MAX_DEPTH: z.coerce.number().int().min(1).default(5),
    ZIP_MAX_COMPRESSION_RATIO: z.coerce.number().min(1).default(20),
    DOCUMENT_AUDIT_HMAC_KEY: z
      .string()
      .min(32)
      .default('local-only-document-audit-hmac-key-0000000000000000'),
    LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),
    APP_ENCRYPTION_MASTER_KEY: z
      .string()
      .min(32, 'APP_ENCRYPTION_MASTER_KEY must be at least 32 characters')
      .default('local-placeholder-not-for-real-encryption-000000000000000000000000'),
    AUTH_ISSUER: z.string().min(3).default('secure-document-access-api'),
    AUTH_AUDIENCE: z.string().min(3).default('secure-document-access-web'),
    AUTH_ACTIVE_KID: z.string().min(1).default('development-ephemeral'),
    AUTH_SIGNING_PRIVATE_KEY_PEM: z.string().min(1).optional(),
    AUTH_SIGNING_PUBLIC_KEYS_JSON: z.string().min(2).optional(),
    AUTH_ACCESS_TTL_SECONDS: z.coerce.number().int().min(60).max(900).default(300),
    AUTH_REFRESH_TTL_SECONDS: z.coerce.number().int().min(3600).max(2_592_000).default(604_800),
    AUTH_RESET_TTL_SECONDS: z.coerce.number().int().min(300).max(3600).default(900),
    AUTH_AUDIT_HMAC_KEY: z.string().min(32).default('local-only-audit-hmac-key-not-for-production'),
    SMTP_HOST: z.string().default('127.0.0.1'),
    SMTP_PORT: z.coerce.number().int().min(1).max(65535).default(1025),
    SMTP_SECURE: z.preprocess((val) => val === 'true' || val === true, z.boolean()).default(false),
    SMTP_FROM: z.string().email().default('no-reply@secure-docs.internal'),
    PASSWORD_RESET_BASE_URL: z.string().url().default('http://localhost:3000/reset-password'),
    GRANT_MAX_DURATION_DAYS: z.coerce.number().int().min(1).max(90).default(30),
    GRANT_EXPIRY_INTERVAL_MS: z.coerce.number().int().min(10_000).max(300_000).default(60_000),
    DOWNLOAD_TICKET_TTL_SECONDS: z.coerce.number().int().min(10).max(300).default(60),
    DERIVATIVE_TTL_MINUTES: z.coerce.number().int().min(5).max(1440).default(60),
  })
  .superRefine((value, context) => {
    if (
      value.NODE_ENV === 'production' &&
      (!value.AUTH_SIGNING_PRIVATE_KEY_PEM || !value.AUTH_SIGNING_PUBLIC_KEYS_JSON)
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['AUTH_SIGNING_PRIVATE_KEY_PEM'],
        message: 'Production requires externally managed Ed25519 signing keys.',
      });
    }
  });

export type EnvConfig = z.infer<typeof EnvSchema>;

export function validateEnv(rawEnv: Record<string, unknown> = process.env): EnvConfig {
  const result = EnvSchema.safeParse(rawEnv);
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
