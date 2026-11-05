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
      return keys.get(normalized) ?? primaryKey;
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
