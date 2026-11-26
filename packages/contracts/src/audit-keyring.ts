// CONFLICT-RESOLVED: Hợp nhất bộ quản lý vòng khóa HMAC kiểm toán (AUDIT_KEY_ROTATION_JSON) dùng chung giữa API (audit-writer.service.ts, audit-chain-helper.ts, audit-verifier.service.ts, audit.service.ts) và Worker (audit-verification-job.ts, grant-expiry-job.ts), loại bỏ việc gắn cứng khóa phiên bản 1.

export interface AuditKeyRing {
  readonly primaryKey: string;
  readonly activeVersion: number;
  readonly activeKey: string;
  readonly keysByVersion: ReadonlyMap<number, string>;
  getKey(version?: number | null): string;
}

/**
 * Algorithm: Versioned Cryptographic Key-Ring Resolution.
 * Seeds key version `1` with `primaryKey`, merges validated `AUDIT_KEY_ROTATION_JSON` entries
 * (`version > 0`, `key.length >= 32`), selects the highest integer version as `activeVersion`
 * for newly appended records, and provides constant-time map lookup `getKey(version)` with
 * safe fallback to `primaryKey` for historical verification.
 */
export function buildAuditKeyRing(
  primaryKey: string,
  rotationJson?: string | null,
  onParseWarning?: (error: unknown) => void,
): AuditKeyRing {
  const keys = new Map<number, string>();
  keys.set(1, primaryKey);

  if (typeof rotationJson === 'string' && rotationJson.trim().length > 0) {
    try {
      const parsed = JSON.parse(rotationJson) as unknown;
      if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) {
        for (const [ver, key] of Object.entries(parsed as Record<string, unknown>)) {
          const versionNo = Number(ver);
          if (
            Number.isInteger(versionNo) &&
            versionNo > 0 &&
            typeof key === 'string' &&
            key.length >= 32
          ) {
            keys.set(versionNo, key);
          }
        }
      }
    } catch (error) {
      onParseWarning?.(error);
    }
  }

  let activeVersion = 1;
  for (const versionNo of keys.keys()) {
    if (versionNo > activeVersion) {
      activeVersion = versionNo;
    }
  }

  const activeKey = keys.get(activeVersion) ?? primaryKey;

  return {
    primaryKey,
    activeVersion,
    activeKey,
    keysByVersion: keys,
    getKey(version?: number | null): string {
      const normalized =
        typeof version === 'number' && Number.isInteger(version) && version > 0 ? version : 1;
      const resolved = keys.get(normalized);
      if (resolved !== undefined) {
        return resolved;
      }
      if (normalized >= 2) {
        throw new Error(
          `Missing audit HMAC key configuration for version ${normalized} in AUDIT_KEY_ROTATION_JSON.`,
        );
      }
      return primaryKey;
    },
  };
}

/**
 * Algorithm: Deterministic Signer Key Identifier Formatting.
 * Encodes integer HMAC key version `v` into the canonical anchor tag `integrity-key-v<version>`.
 */
export function formatSignerKeyId(version: number): string {
  const normalized = Number.isInteger(version) && version > 0 ? version : 1;
  return `integrity-key-v${normalized}`;
}

/**
 * Algorithm: Signer Key Version Extraction.
 * Parses trailing version digits from `signer_key_id` (e.g. `integrity-key-v2` -> `2`),
 * defaulting to version `1` for legacy or unversioned anchor identifiers.
 */
export function parseSignerKeyVersion(signerKeyId?: string | null): number {
  if (typeof signerKeyId !== 'string' || signerKeyId.length === 0) {
    return 1;
  }
  const match = /(?:^|[-_])v(\d+)$/i.exec(signerKeyId.trim());
  if (!match?.[1]) {
    return 1;
  }
  const parsed = Number.parseInt(match[1], 10);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : 1;
}

export const AUDIT_HMAC_ENV_PRIORITY = [
  'AUDIT_INTEGRITY_KEY',
  'DOCUMENT_AUDIT_HMAC_KEY',
  'AUTH_AUDIT_HMAC_KEY',
  'AUDIT_HMAC_KEY',
] as const;

export type AuditHmacEnvKey = (typeof AUDIT_HMAC_ENV_PRIORITY)[number];

export const DEFAULT_DEV_AUDIT_HMAC_KEY = 'local-only-audit-integrity-hmac-key-0000000000000000';
export const LOCAL_DEV_AUDIT_INTEGRITY_KEY = DEFAULT_DEV_AUDIT_HMAC_KEY;

const ZOD_DEV_PLACEHOLDER_AUDIT_KEYS: ReadonlySet<string> = new Set<string>([
  DEFAULT_DEV_AUDIT_HMAC_KEY,
  'local-only-document-audit-hmac-key-0000000000000000',
  'local-only-audit-hmac-key-not-for-production',
]);

function isDisallowedStrictSecret(secret: string | undefined): boolean {
  if (!secret || secret.length < 32) return true;
  const lower = secret.toLowerCase();
  return (
    secret.includes('local-only-') ||
    secret.includes('local-placeholder-') ||
    lower.includes('change-me')
  );
}

/**
 * Thuật toán: Phân giải thống nhất khóa gốc HMAC kiểm toán giữa `@sda/api` và `@sda/worker` (`BUG-065`).
 * - Duyệt theo thứ tự ưu tiên bất biến: `AUDIT_INTEGRITY_KEY` -> `DOCUMENT_AUDIT_HMAC_KEY` -> `AUTH_AUDIT_HMAC_KEY` -> `AUDIT_HMAC_KEY`,
 *   cắt khoảng trắng `.trim()` và bỏ qua chuỗi rỗng `""` (khắc phục lỗi toán tử `??` nuốt khóa kế tiếp khi biến mang `""`).
 * - Ưu tiên khóa do người vận hành cấu hình thực tế hơn các hằng giữ chỗ `local-only-*` của Zod dev schema.
 * - Khóa chặt Fail-Fast trên `production` và `staging` nếu khóa thiếu, ngắn hơn 32 ký tự hoặc chứa mẫu giữ chỗ (`local-only-` / `change-me`).
 */
export function resolvePrimaryAuditHmacKeyFromGetter(
  readKey: (key: AuditHmacEnvKey) => string | undefined,
  nodeEnv?: string | null,
): string {
  const normalizedEnv = (nodeEnv ?? '').trim().toLowerCase();
  const isStrictEnv = normalizedEnv === 'production' || normalizedEnv === 'staging';

  const nonEmptyCandidates: string[] = [];
  for (const envKey of AUDIT_HMAC_ENV_PRIORITY) {
    const raw = readKey(envKey);
    if (typeof raw === 'string') {
      const trimmed = raw.trim();
      if (trimmed.length > 0) {
        nonEmptyCandidates.push(trimmed);
      }
    }
  }

  const explicitCandidate = nonEmptyCandidates.find(
    (val) => !ZOD_DEV_PLACEHOLDER_AUDIT_KEYS.has(val),
  );
  const selected = explicitCandidate ?? nonEmptyCandidates[0];

  if (isStrictEnv) {
    if (isDisallowedStrictSecret(selected)) {
      throw new Error(
        'AUDIT_INTEGRITY_KEY (or DOCUMENT_AUDIT_HMAC_KEY / AUTH_AUDIT_HMAC_KEY / AUDIT_HMAC_KEY, >= 32 random non-placeholder chars) is mandatory in production and staging.',
      );
    }
    return selected!;
  }

  return selected ?? DEFAULT_DEV_AUDIT_HMAC_KEY;
}

/**
 * Thuật toán: Phân giải khóa gốc HMAC kiểm toán trực tiếp từ bản đồ biến môi trường `process.env` (`BUG-065`).
 */
export function resolvePrimaryAuditHmacKeyFromEnv(
  env: Readonly<Record<string, string | undefined>> = typeof process !== 'undefined'
    ? process.env
    : {},
): string {
  return resolvePrimaryAuditHmacKeyFromGetter((key) => env[key], env['NODE_ENV']);
}

export const EXPORT_AT_REST_HKDF_SALT = 'sda-export-at-rest-salt-v1';
export const EXPORT_AT_REST_HKDF_INFO = 'sda-export-artifact-aes-256-gcm';
export const DEFAULT_DEV_EXPORT_ENCRYPTION_IKM =
  'sda-local-dev-deterministic-export-at-rest-ikm-v1';
export const LOCAL_DEV_EXPORT_ENCRYPTION_IKM = DEFAULT_DEV_EXPORT_ENCRYPTION_IKM;

/**
 * Thuật toán: Phân giải vật liệu khóa gốc (IKM) tất định cho mã hóa tệp xuất `.dat` giữa `@sda/api` và `@sda/worker` (`BUG-066`).
 * - Triệt tiêu hoàn toàn `randomBytes(32)` cục bộ mỗi tiến trình khiến API không giải mã được tệp `.dat` do Worker tạo trong môi trường dev/test.
 * - Trên `production`/`staging`: cưỡng chế Fail-Fast nếu thiếu cả `EXPORT_ENCRYPTION_KEY` lẫn `AUDIT_INTEGRITY_KEY`, độ dài `< 32`, hoặc chứa chuỗi giữ chỗ.
 * - Trên `development`/`test`: dùng khóa cấu hình thực nếu có, ngược lại dẫn xuất tất định từ hằng `DEFAULT_DEV_EXPORT_ENCRYPTION_IKM` đồng nhất đa tiến trình.
 */
export function resolveExportEncryptionIkm(
  env: Readonly<Record<string, string | undefined>> = typeof process !== 'undefined'
    ? process.env
    : {},
): string {
  const explicitExportKey = env['EXPORT_ENCRYPTION_KEY']?.trim() || undefined;
  const fallbackAuditKey = env['AUDIT_INTEGRITY_KEY']?.trim() || undefined;
  const configured =
    explicitExportKey ||
    (fallbackAuditKey && !ZOD_DEV_PLACEHOLDER_AUDIT_KEYS.has(fallbackAuditKey)
      ? fallbackAuditKey
      : undefined) ||
    fallbackAuditKey;

  const nodeEnv = (env['NODE_ENV'] ?? '').trim().toLowerCase();
  if (nodeEnv === 'production' || nodeEnv === 'staging') {
    if (isDisallowedStrictSecret(configured)) {
      throw new Error(
        'EXPORT_ENCRYPTION_KEY (or AUDIT_INTEGRITY_KEY, >= 32 random non-placeholder chars) is mandatory for export encryption in production and staging.',
      );
    }
    return configured!;
  }

  if (configured && !ZOD_DEV_PLACEHOLDER_AUDIT_KEYS.has(configured)) {
    return configured;
  }
  return DEFAULT_DEV_EXPORT_ENCRYPTION_IKM;
}
