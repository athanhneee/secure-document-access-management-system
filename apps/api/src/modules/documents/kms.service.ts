import { Injectable } from '@nestjs/common';
import crypto from 'node:crypto';
import { AppConfigService } from '../../config/config.service.js';

export interface KmsWrapResult {
  wrappedDek: string;
  keyRef: string;
  combinedRef: string;
}

export interface KmsService {
  wrapKey(plaintextDek: Buffer): Promise<KmsWrapResult>;
  unwrapKey(wrappedDek: string, keyRef: string): Promise<Buffer>;
  unwrapCombinedRef(combinedRef: string): Promise<Buffer>;
}

@Injectable()
export class LocalKmsService implements KmsService {
  private readonly kek: Buffer;
  private readonly activeKeyRef = 'local-kms:v1';

  constructor(config: AppConfigService) {
    const masterKey = config.get('APP_ENCRYPTION_MASTER_KEY');
    // Derive 256-bit KEK via HKDF-SHA256 (RFC 5869)
    this.kek = Buffer.from(
      crypto.hkdfSync(
        'sha256',
        Buffer.from(masterKey, 'utf8'),
        Buffer.alloc(0),
        Buffer.from('SDA-KMS-KEK-v1', 'utf8'),
        32,
      ),
    );
  }

  /**
   * Wraps a 256-bit DEK using AES-256-GCM and the derived KEK.
   * Generates a fresh unique 96-bit IV for every wrap operation.
   */
  async wrapKey(plaintextDek: Buffer): Promise<KmsWrapResult> {
    if (plaintextDek.length !== 32) {
      throw new Error('DEK must be exactly 32 bytes (256 bits).');
    }

    const iv = crypto.randomBytes(12); // 96-bit IV
    const cipher = crypto.createCipheriv('aes-256-gcm', this.kek, iv);
    const encryptedDek = Buffer.concat([cipher.update(plaintextDek), cipher.final()]);
    const tag = cipher.getAuthTag(); // 128-bit tag

    // Serialized format: IV (12B) + Tag (16B) + Ciphertext (32B) = 60B
    const wrappedPayload = Buffer.concat([iv, tag, encryptedDek]);
    const wrappedDek = wrappedPayload.toString('base64url');
    const combinedRef = `${this.activeKeyRef}:${wrappedDek}`;

    return {
      wrappedDek,
      keyRef: this.activeKeyRef,
      combinedRef,
    };
  }

  /**
   * Unwraps a wrapped DEK given the wrapped string and keyRef.
   */
  async unwrapKey(wrappedDek: string, keyRef: string): Promise<Buffer> {
    if (!keyRef.startsWith('local-kms:')) {
      throw new Error(`Unsupported KMS keyRef format: ${keyRef}`);
    }

    const payload = Buffer.from(wrappedDek, 'base64url');
    if (payload.length < 28) {
      throw new Error('Invalid wrapped DEK payload length.');
    }

    const iv = payload.subarray(0, 12);
    const tag = payload.subarray(12, 28);
    const ciphertext = payload.subarray(28);

    const decipher = crypto.createDecipheriv('aes-256-gcm', this.kek, iv);
    decipher.setAuthTag(tag);

    try {
      const decryptedDek = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      if (decryptedDek.length !== 32) {
        throw new Error('Decrypted DEK length is invalid.');
      }
      return decryptedDek;
    } catch {
      throw new Error('Failed to unwrap DEK: authentication tag mismatch or corrupted key data.');
    }
  }

  /**
   * Helper to unwrap from stored combined reference: 'local-kms:v1:<base64url>'
   */
  async unwrapCombinedRef(combinedRef: string): Promise<Buffer> {
    const colonIndex = combinedRef.lastIndexOf(':');
    if (colonIndex <= 0) {
      throw new Error('Invalid combined encryption key reference format.');
    }

    const keyRef = combinedRef.substring(0, colonIndex);
    const wrappedDek = combinedRef.substring(colonIndex + 1);
    return this.unwrapKey(wrappedDek, keyRef);
  }
}
