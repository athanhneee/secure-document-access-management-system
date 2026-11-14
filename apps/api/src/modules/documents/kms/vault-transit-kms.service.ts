/**
 * Module: HashiCorp Vault Transit Engine KMS Service
 * Thuật toán: Bọc/Giải Bọc Khóa DEK 256-bit Qua Vault Transit Engine Hỗ Trợ Xoay Vòng Tên Khóa (`Key Rotation`).
 *   1. Khi bọc khóa (`wrapKey`), gửi yêu cầu HTTP POST tới `/v1/<mount>/encrypt/<encodedKeyName>` kèm `context` (AAD base64 nếu có).
 *   2. Khi giải bọc (`unwrapKey`), phân tích động tên khóa từ `keyRef` (`vault-kms:<key>:v<ver>`, `vault:<key>:v<ver>`, `transit/<key>`, `<key>:v<ver>`),
 *      tự động lùi về `this.keyName` khi `keyRef` không chứa tên khóa (như `vault:v1`), đảm bảo các tài liệu mã hóa bằng khóa cũ vẫn giải mã trơn tru sau khi xoay vòng KEK.
 *   3. Tuân thủ Fail-Closed nghiêm ngặt trong môi trường thực tế; chỉ cho phép mô phỏng HKDF+AES-256-GCM khi cấu hình `dev-mock-vault-token` ngoài Production.
 */
import { Injectable, Logger } from '@nestjs/common';
import crypto from 'node:crypto';
import { AppConfigService } from '../../../config/config.service.js';
import { KmsService, splitCombinedKeyRef, type KmsWrapResult } from './kms.types.js';
import { unwrapDekWithAes256Gcm, wrapDekWithAes256Gcm } from './aws-envelope-kms.service.js';

/**
 * Thuật toán: Trích xuất tên khóa Transit từ `keyRef` phục vụ xoay vòng khóa KEK không gián đoạn.
 */
export function parseVaultKeyNameFromRef(keyRef: string, defaultKeyName: string): string {
  const trimmed = keyRef.trim();
  if (
    !trimmed ||
    trimmed.startsWith('local-kms:') ||
    trimmed.startsWith('aws-kms:') ||
    trimmed.startsWith('hsm-pkcs11:') ||
    (/^[a-z0-9-]+-kms:/iu.test(trimmed) && !trimmed.startsWith('vault-kms:'))
  ) {
    throw new Error(`Unsupported KMS keyRef format: ${keyRef}`);
  }

  let rest = trimmed;
  if (rest.startsWith('vault-kms:')) {
    rest = rest.slice('vault-kms:'.length);
  } else if (rest.startsWith('vault:')) {
    rest = rest.slice('vault:'.length);
  } else if (rest.startsWith('transit/')) {
    rest = rest.slice('transit/'.length);
  } else if (!/^[^:\s]+:v\d+$/u.test(rest)) {
    throw new Error(`Unsupported KMS keyRef format: ${keyRef}`);
  }

  const withoutVersion = rest.replace(/:v\d+$/u, '').trim();
  if (!withoutVersion || /^v\d+$/u.test(withoutVersion)) {
    return defaultKeyName;
  }
  return withoutVersion;
}

function encodeVaultContextBase64(aad?: Buffer | string): string | undefined {
  if (aad === undefined) return undefined;
  const buf = Buffer.isBuffer(aad) ? aad : Buffer.from(aad, 'utf8');
  return buf.length > 0 ? buf.toString('base64') : undefined;
}

@Injectable()
export class VaultTransitKmsService implements KmsService {
  private readonly logger = new Logger(VaultTransitKmsService.name);
  readonly vaultAddr: string;
  readonly vaultToken: string;
  readonly keyName: string;
  readonly transitMount: string;
  private readonly masterKey: string;
  private readonly fallbackKek: Buffer;
  private readonly allowDevFallback: boolean;
  private readonly isProduction: boolean;

  constructor(config: AppConfigService) {
    this.isProduction = config.get('NODE_ENV') === 'production';
    this.vaultAddr = config.get('VAULT_ADDR') ?? 'http://127.0.0.1:8200';
    this.vaultToken = config.get('VAULT_TOKEN') ?? '';
    this.keyName = config.get('VAULT_KEY_NAME') ?? 'sda-document-kek';
    this.transitMount = config.get('VAULT_TRANSIT_MOUNT') ?? 'transit';
    this.allowDevFallback = !this.isProduction && this.vaultToken === 'dev-mock-vault-token';
    if (
      this.isProduction &&
      config.get('KMS_PROVIDER') === 'vault' &&
      (!this.vaultToken || this.vaultToken === 'dev-mock-vault-token')
    ) {
      throw new Error('VAULT_TOKEN must be configured with a non-mock token in production.');
    }

    this.masterKey = config.get('APP_ENCRYPTION_MASTER_KEY');
    this.fallbackKek = this.deriveDevFallbackKek(this.keyName);
    this.logger.log(
      `Vault Transit KMS service initialized (mount: ${this.transitMount}, key: ${this.keyName})`,
    );
  }

  get keyRef(): string {
    return `vault-kms:${this.keyName}`;
  }

  private deriveDevFallbackKek(targetKeyName: string): Buffer {
    return Buffer.from(
      crypto.hkdfSync(
        'sha256',
        Buffer.from(this.masterKey, 'utf8'),
        Buffer.from('VAULT-TRANSIT-SALT', 'utf8'),
        Buffer.from(`VAULT:${targetKeyName}`, 'utf8'),
        32,
      ),
    );
  }

  /**
   * Thuật toán: Bọc khóa DEK 256-bit qua Vault Transit HTTP API (`/v1/<mount>/encrypt/<keyName>`) với cơ chế Fail-Closed.
   */
  async wrapKey(plaintextDek: Buffer, aad?: Buffer | string): Promise<KmsWrapResult> {
    if (plaintextDek.length !== 32) {
      throw new Error('DEK must be exactly 32 bytes (256 bits).');
    }
    if (!this.vaultToken || (this.isProduction && this.vaultToken === 'dev-mock-vault-token')) {
      throw new Error('Vault Transit KMS token is missing or invalid.');
    }

    const contextB64 = encodeVaultContextBase64(aad);
    try {
      const endpoint = `${this.vaultAddr.replace(/\/+$/, '')}/v1/${encodeURIComponent(this.transitMount)}/encrypt/${encodeURIComponent(this.keyName)}`;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 2_000);

      try {
        const bodyPayload: Record<string, string> = {
          plaintext: plaintextDek.toString('base64'),
        };
        if (contextB64) bodyPayload['context'] = contextB64;

        const response = await fetch(endpoint, {
          method: 'POST',
          headers: {
            'X-Vault-Token': this.vaultToken,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(bodyPayload),
          signal: controller.signal,
        });

        if (response.ok) {
          const json = (await response.json()) as { data?: { ciphertext?: string } };
          if (json.data?.ciphertext) {
            const wrappedDek = Buffer.from(json.data.ciphertext, 'utf8').toString('base64url');
            const keyRef = this.keyRef;
            return { wrappedDek, keyRef, combinedRef: `${keyRef}:${wrappedDek}` };
          }
        }
        if (!this.allowDevFallback) {
          throw new Error(
            `Vault Transit KMS wrapKey failed with HTTP ${response.status} — refusing insecure software fallback.`,
          );
        }
      } finally {
        clearTimeout(timer);
      }
    } catch (err) {
      if (!this.allowDevFallback) {
        throw err instanceof Error
          ? err
          : new Error('Vault Transit KMS wrapKey failed — refusing insecure software fallback.');
      }
    }

    return wrapDekWithAes256Gcm(plaintextDek, this.fallbackKek, this.keyRef);
  }

  /**
   * Thuật toán: Giải bọc DEK qua Vault Transit HTTP API (`/v1/<mount>/decrypt/<resolvedKeyName>`) hỗ trợ khóa đã xoay vòng trong `keyRef`.
   */
  async unwrapKey(wrappedDek: string, keyRef: string, aad?: Buffer | string): Promise<Buffer> {
    const resolvedKeyName = parseVaultKeyNameFromRef(keyRef, this.keyName);
    if (!this.vaultToken || (this.isProduction && this.vaultToken === 'dev-mock-vault-token')) {
      throw new Error('Vault Transit KMS token is missing or invalid.');
    }

    const payload = Buffer.from(wrappedDek, 'base64url');
    const rawString = payload.toString('utf8');
    const contextB64 = encodeVaultContextBase64(aad);

    if (rawString.startsWith('vault:v')) {
      try {
        const endpoint = `${this.vaultAddr.replace(/\/+$/, '')}/v1/${encodeURIComponent(this.transitMount)}/decrypt/${encodeURIComponent(resolvedKeyName)}`;
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 2_000);

        try {
          const bodyPayload: Record<string, string> = { ciphertext: rawString };
          if (contextB64) bodyPayload['context'] = contextB64;

          const response = await fetch(endpoint, {
            method: 'POST',
            headers: {
              'X-Vault-Token': this.vaultToken,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(bodyPayload),
            signal: controller.signal,
          });

          if (response.ok) {
            const json = (await response.json()) as { data?: { plaintext?: string } };
            if (json.data?.plaintext) {
              return Buffer.from(json.data.plaintext, 'base64');
            }
          }
          throw new Error(
            `Vault Transit KMS unwrapKey failed with HTTP ${response.status} — refusing local fallback.`,
          );
        } finally {
          clearTimeout(timer);
        }
      } catch (err) {
        throw err instanceof Error
          ? err
          : new Error('Vault Transit KMS unwrapKey failed — refusing local fallback.');
      }
    }

    if (!this.allowDevFallback) {
      throw new Error(
        'Vault Transit KMS refused software-emulated wrapped DEK in non-mock configuration.',
      );
    }

    const kek =
      resolvedKeyName === this.keyName
        ? this.fallbackKek
        : this.deriveDevFallbackKek(resolvedKeyName);
    try {
      return unwrapDekWithAes256Gcm(
        wrappedDek,
        kek,
        'Failed to unwrap DEK via Vault: authentication tag mismatch or corrupted key data.',
      );
    } finally {
      if (kek !== this.fallbackKek) {
        kek.fill(0);
      }
    }
  }

  async unwrapCombinedRef(combinedRef: string, aad?: Buffer | string): Promise<Buffer> {
    const { keyRef, wrappedDek } = splitCombinedKeyRef(combinedRef);
    return this.unwrapKey(wrappedDek, keyRef, aad);
  }
}
