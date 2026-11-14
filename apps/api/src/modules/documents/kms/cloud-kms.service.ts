/**
 * Module: Cloud KMS Service (AWS KMS / Cloud Envelope Provider)
 * Thuật toán: Dẫn Xuất Khóa Bọc Theo Vùng/KeyId Bằng HKDF-SHA256 & Mã Hóa Phong Bì AES-256-GCM Có Chốt Chặn Production.
 *   1. Ngăn chặn tuyệt đối việc chạy bộ mô phỏng phần mềm Cloud KMS trong môi trường `production`.
 *   2. Dẫn xuất khóa KEK 256-bit cách ly theo miền `region` và `keyId` để bọc/giải bọc DEK định dạng `aws-kms:<keyId>:<payload>` trong môi trường kiểm thử/phát triển.
 */
import { Injectable, Logger } from '@nestjs/common';
import crypto from 'node:crypto';
import { AppConfigService } from '../../../config/config.service.js';
import { KmsService, splitCombinedKeyRef, type KmsWrapResult } from './kms.types.js';
import { unwrapDekWithAes256Gcm, wrapDekWithAes256Gcm } from './aws-envelope-kms.service.js';

@Injectable()
export class CloudKmsService implements KmsService {
  private readonly logger = new Logger(CloudKmsService.name);
  readonly keyId: string;
  readonly region: string;
  private readonly isProduction: boolean;
  private readonly fallbackKek: Buffer;

  constructor(config: AppConfigService) {
    this.isProduction = config.get('NODE_ENV') === 'production';
    this.keyId = config.get('AWS_KMS_KEY_ID') ?? 'alias/sda-master-kek';
    this.region = config.get('AWS_KMS_REGION') ?? 'us-east-1';
    if (this.isProduction && config.get('KMS_PROVIDER') === 'aws-kms') {
      throw new Error(
        'Software Cloud KMS simulator is prohibited in production; wire real AWS KMS SDK.',
      );
    }

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
   * Thuật toán: Bọc khóa DEK 256-bit bằng AES-256-GCM gắn miền `region` và `keyId` của Cloud KMS.
   */
  async wrapKey(plaintextDek: Buffer): Promise<KmsWrapResult> {
    if (this.isProduction) {
      throw new Error('Software Cloud KMS simulator cannot wrap keys in production.');
    }
    return wrapDekWithAes256Gcm(plaintextDek, this.fallbackKek, this.keyRef);
  }

  /**
   * Thuật toán: Giải bọc và xác thực thẻ GCM của DEK từ tham chiếu `aws-kms:<keyId>`.
   */
  async unwrapKey(wrappedDek: string, keyRef: string): Promise<Buffer> {
    if (this.isProduction) {
      throw new Error('Software Cloud KMS simulator cannot unwrap keys in production.');
    }
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
