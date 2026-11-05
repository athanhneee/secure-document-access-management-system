/**
 * Module: Local Software Envelope KMS Service
 * Algorithm: Derives a domain-separated 256-bit KEK via HKDF-SHA256 (RFC 5869) from the master key
 *   and wraps/unwraps 256-bit DEKs with AES-256-GCM (`local-kms:v1:<payload>`).
 */
import { Injectable } from '@nestjs/common';
import crypto from 'node:crypto';
import { AppConfigService } from '../../../config/config.service.js';
import { KmsService, splitCombinedKeyRef, type KmsWrapResult } from './kms.types.js';
import { unwrapDekWithAes256Gcm, wrapDekWithAes256Gcm } from './aws-envelope-kms.service.js';

@Injectable()
export class LocalKmsService implements KmsService {
  protected readonly kek: Buffer;
  protected readonly activeKeyRef = 'local-kms:v1';

  constructor(config: AppConfigService) {
    const masterKey = config.get('APP_ENCRYPTION_MASTER_KEY');
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
   * Algorithm: Local HKDF-KEK AES-256-GCM DEK Wrap
   */
  async wrapKey(plaintextDek: Buffer): Promise<KmsWrapResult> {
    return wrapDekWithAes256Gcm(plaintextDek, this.kek, this.activeKeyRef);
  }

  /**
   * Algorithm: Local HKDF-KEK AES-256-GCM DEK Unwrap
   */
  async unwrapKey(wrappedDek: string, keyRef: string): Promise<Buffer> {
    if (!keyRef.startsWith('local-kms:')) {
      throw new Error(`Unsupported KMS keyRef format: ${keyRef}`);
    }
    return unwrapDekWithAes256Gcm(
      wrappedDek,
      this.kek,
      'Failed to unwrap DEK: authentication tag mismatch or corrupted key data.',
    );
  }

  async unwrapCombinedRef(combinedRef: string): Promise<Buffer> {
    const { keyRef, wrappedDek } = splitCombinedKeyRef(combinedRef);
    return this.unwrapKey(wrappedDek, keyRef);
  }
}
