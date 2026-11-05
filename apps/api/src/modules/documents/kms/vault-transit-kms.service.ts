/**
 * Module: HashiCorp Vault Transit Engine KMS Service
 * Algorithm: Wraps/unwraps 256-bit DEKs via Vault Transit HTTP API (`/v1/<mount>/encrypt|decrypt/<key>`)
 *   with strict fail-closed behavior in non-mock environments and explicit dev-mock AES-256-GCM fallback.
 */
import { Injectable, Logger } from '@nestjs/common';
import crypto from 'node:crypto';
import { AppConfigService } from '../../../config/config.service.js';
import { KmsService, splitCombinedKeyRef, type KmsWrapResult } from './kms.types.js';
import { unwrapDekWithAes256Gcm, wrapDekWithAes256Gcm } from './aws-envelope-kms.service.js';

@Injectable()
export class VaultTransitKmsService implements KmsService {
  private readonly logger = new Logger(VaultTransitKmsService.name);
  readonly vaultAddr: string;
  readonly vaultToken: string;
  readonly keyName: string;
  readonly transitMount: string;
  private readonly fallbackKek: Buffer;
  private readonly allowDevFallback: boolean;
  private readonly isProduction: boolean;

  constructor(config: AppConfigService) {
    this.isProduction = config.get('NODE_ENV') === 'production';
    this.vaultAddr = config.get('VAULT_ADDR') ?? 'http://127.0.0.1:8200';
    // CONFLICT-RESOLVED: Gỡ bỏ token mặc định gắn cứng `'dev-mock-vault-token'` và chặn chạy cấu hình giả lập trong Production (HIGH-09).
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

    const masterKey = config.get('APP_ENCRYPTION_MASTER_KEY');
    this.fallbackKek = Buffer.from(
      crypto.hkdfSync(
        'sha256',
        Buffer.from(masterKey, 'utf8'),
        Buffer.from('VAULT-TRANSIT-SALT', 'utf8'),
        Buffer.from(`VAULT:${this.keyName}`, 'utf8'),
        32,
      ),
    );
    this.logger.log(
      `Vault Transit KMS service initialized (mount: ${this.transitMount}, key: ${this.keyName})`,
    );
  }

  get keyRef(): string {
    return `vault-kms:${this.keyName}`;
  }

  /**
   * Algorithm: Vault Transit HTTP Encrypt with Fail-Closed Guard
   */
  async wrapKey(plaintextDek: Buffer): Promise<KmsWrapResult> {
    if (plaintextDek.length !== 32) {
      throw new Error('DEK must be exactly 32 bytes (256 bits).');
    }
    if (!this.vaultToken || (this.isProduction && this.vaultToken === 'dev-mock-vault-token')) {
      throw new Error('Vault Transit KMS token is missing or invalid.');
    }

    try {
      const endpoint = `${this.vaultAddr.replace(/\/+$/, '')}/v1/${this.transitMount}/encrypt/${this.keyName}`;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 2_000);

      try {
        const response = await fetch(endpoint, {
          method: 'POST',
          headers: {
            'X-Vault-Token': this.vaultToken,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ plaintext: plaintextDek.toString('base64') }),
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
   * Algorithm: Vault Transit HTTP Decrypt (`vault:v*` Ciphertext Dispatch)
   */
  async unwrapKey(wrappedDek: string, keyRef: string): Promise<Buffer> {
    if (!keyRef.startsWith('vault-kms:')) {
      throw new Error(`Unsupported KMS keyRef format: ${keyRef}`);
    }
    if (!this.vaultToken || (this.isProduction && this.vaultToken === 'dev-mock-vault-token')) {
      throw new Error('Vault Transit KMS token is missing or invalid.');
    }

    const payload = Buffer.from(wrappedDek, 'base64url');
    const rawString = payload.toString('utf8');

    if (rawString.startsWith('vault:v')) {
      try {
        const endpoint = `${this.vaultAddr.replace(/\/+$/, '')}/v1/${this.transitMount}/decrypt/${this.keyName}`;
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 2_000);

        try {
          const response = await fetch(endpoint, {
            method: 'POST',
            headers: {
              'X-Vault-Token': this.vaultToken,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({ ciphertext: rawString }),
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

    return unwrapDekWithAes256Gcm(
      wrappedDek,
      this.fallbackKek,
      'Failed to unwrap DEK via Vault: authentication tag mismatch or corrupted key data.',
    );
  }

  async unwrapCombinedRef(combinedRef: string): Promise<Buffer> {
    const { keyRef, wrappedDek } = splitCombinedKeyRef(combinedRef);
    return this.unwrapKey(wrappedDek, keyRef);
  }
}
