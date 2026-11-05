/**
 * Module: Cloud KMS Service (AWS KMS / Cloud Envelope Provider)
 * Algorithm: Derives region- and keyId-scoped 256-bit KEK via HKDF-SHA256 and performs
 *   authenticated AES-256-GCM envelope DEK wrap/unwrap (`aws-kms:<keyId>:<payload>`).
 */
import { Injectable, Logger } from '@nestjs/common';
import crypto from 'node:crypto';
import { AppConfigService } from '../../../config/config.service.js';
import { KmsService, splitCombinedKeyRef, type KmsWrapResult } from './kms.types.js';
import { unwrapDekWithAes256Gcm, wrapDekWithAes256Gcm } from './aws-envelope-kms.service.js';

@Injectable()
export class CloudKmsService implements KmsService {
  // shortcut: local HKDF envelope simulator restricted to dev/test by env.schema.ts, wire @aws-sdk/client-kms GenerateDataKey/Decrypt for cloud deployment
  private readonly logger = new Logger(CloudKmsService.name);
  readonly keyId: string;
  readonly region: string;
  private readonly fallbackKek: Buffer;

  constructor(config: AppConfigService) {
    this.keyId = config.get('AWS_KMS_KEY_ID') ?? 'alias/sda-master-kek';
    this.region = config.get('AWS_KMS_REGION') ?? 'us-east-1';

    const masterKey = config.get('APP_ENCRYPTION_MASTER_KEY');
    this.fallbackKek = Buffer.from(
      crypto.hkdfSync(
        'sha256',
        Buffer.from(masterKey, 'utf8'),
        Buffer.from(`AWS-KMS-${this.region}`, 'utf8'),
        Buffer.from(`AWS-KMS:${this.keyId}`, 'utf8'),
        32,
      ),
    );
    this.logger.log(`Cloud KMS service initialized (keyId: ${this.keyId}, region: ${this.region})`);
  }

  get keyRef(): string {
    return `aws-kms:${this.keyId}`;
  }

  /**
   * Algorithm: Cloud KMS Region-Bound AES-256-GCM DEK Wrap
   */
  async wrapKey(plaintextDek: Buffer): Promise<KmsWrapResult> {
    return wrapDekWithAes256Gcm(plaintextDek, this.fallbackKek, this.keyRef);
  }

  /**
   * Algorithm: Cloud KMS Region-Bound AES-256-GCM DEK Unwrap
   */
  async unwrapKey(wrappedDek: string, keyRef: string): Promise<Buffer> {
    if (!keyRef.startsWith('aws-kms:')) {
      throw new Error(`Unsupported KMS keyRef format: ${keyRef}`);
    }
    return unwrapDekWithAes256Gcm(
      wrappedDek,
      this.fallbackKek,
      'Failed to unwrap DEK via Cloud KMS: authentication tag mismatch or corrupted key data.',
    );
  }

  async unwrapCombinedRef(combinedRef: string): Promise<Buffer> {
    const { keyRef, wrappedDek } = splitCombinedKeyRef(combinedRef);
    return this.unwrapKey(wrappedDek, keyRef);
  }
}
