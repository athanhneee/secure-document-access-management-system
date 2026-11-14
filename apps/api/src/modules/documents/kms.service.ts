/**
 * Module: Unified Multi-Provider Envelope KMS Orchestrator
 * Thuật toán: Bộ Điều Phối Khóa Phong Bì Đa Nhà Cung Cấp (`local`, `hsm-pkcs11`, `vault`, `aws-kms`) & Xoay Vòng Khóa Không Gián Đoạn.
 *   1. Định tuyến thao tác bọc khóa (`wrapKey`) tới nhà cung cấp đang kích hoạt trong cấu hình.
 *   2. Định tuyến giải bọc (`unwrapKey`) theo tiền tố `keyRef` (hỗ trợ cả `vault-kms:*`, `vault:*`, `transit/*`, `<keyName>:v<ver>`) để tương thích ngược sau khi xoay vòng KEK.
 *   3. Trong `rotateKeyRef`, luôn xóa trắng vùng nhớ DEK bản rõ bằng `decryptedDek.fill(0)` trong khối `finally`.
 */
import { Injectable } from '@nestjs/common';
import { AppConfigService } from '../../config/config.service.js';
import {
  KmsService,
  splitCombinedKeyRef,
  type KmsProviderType,
  type KmsWrapResult,
} from './kms/kms.types.js';
import { LocalKmsService } from './kms/local-envelope-kms.service.js';
import { HsmPkcs11KmsService } from './kms/hsm-pkcs11-kms.service.js';
import {
  VaultTransitKmsService,
  parseVaultKeyNameFromRef,
} from './kms/vault-transit-kms.service.js';
import { CloudKmsService } from './kms/cloud-kms.service.js';

export {
  CloudKmsService,
  HsmPkcs11KmsService,
  KmsService,
  LocalKmsService,
  VaultTransitKmsService,
  parseVaultKeyNameFromRef,
  type KmsProviderType,
  type KmsWrapResult,
};

@Injectable()
export class UnifiedKmsService extends LocalKmsService {
  private readonly activeProvider: KmsProviderType;
  readonly hsmProvider: HsmPkcs11KmsService;
  readonly vaultProvider: VaultTransitKmsService;
  readonly cloudProvider: CloudKmsService;

  constructor(config: AppConfigService) {
    super(config);
    this.activeProvider = (config.get('KMS_PROVIDER') as KmsProviderType) || 'local';
    this.hsmProvider = new HsmPkcs11KmsService(config);
    this.vaultProvider = new VaultTransitKmsService(config);
    this.cloudProvider = new CloudKmsService(config);
  }

  get provider(): KmsProviderType {
    return this.activeProvider;
  }

  /**
   * Thuật toán: Định tuyến bọc khóa DEK tới nhà cung cấp KMS đang kích hoạt.
   */
  override async wrapKey(plaintextDek: Buffer, aad?: Buffer | string): Promise<KmsWrapResult> {
    switch (this.activeProvider) {
      case 'hsm-pkcs11':
        return await this.hsmProvider.wrapKey(plaintextDek);
      case 'vault':
        return await this.vaultProvider.wrapKey(plaintextDek, aad);
      case 'aws-kms':
        return await this.cloudProvider.wrapKey(plaintextDek);
      case 'local':
      default:
        return await super.wrapKey(plaintextDek);
    }
  }

  /**
   * Thuật toán: Định tuyến giải bọc DEK theo tiền tố `keyRef` hỗ trợ đa nhà cung cấp và khóa Vault đã xoay vòng.
   */
  override async unwrapKey(
    wrappedDek: string,
    keyRef: string,
    aad?: Buffer | string,
  ): Promise<Buffer> {
    if (keyRef.startsWith('local-kms:')) {
      return await super.unwrapKey(wrappedDek, keyRef);
    }
    if (keyRef.startsWith('hsm-pkcs11:')) {
      return await this.hsmProvider.unwrapKey(wrappedDek, keyRef);
    }
    if (keyRef.startsWith('aws-kms:')) {
      return await this.cloudProvider.unwrapKey(wrappedDek, keyRef);
    }
    if (
      keyRef.startsWith('vault-kms:') ||
      keyRef.startsWith('vault:') ||
      keyRef.startsWith('transit/') ||
      /^[^:\s]+:v\d+$/u.test(keyRef)
    ) {
      return await this.vaultProvider.unwrapKey(wrappedDek, keyRef, aad);
    }
    throw new Error(`Unsupported KMS keyRef format: ${keyRef}`);
  }

  override async unwrapCombinedRef(combinedRef: string, aad?: Buffer | string): Promise<Buffer> {
    const { keyRef, wrappedDek } = splitCombinedKeyRef(combinedRef);
    return this.unwrapKey(wrappedDek, keyRef, aad);
  }

  /**
   * Thuật toán: Xoay vòng tham chiếu khóa phong bì không gián đoạn kèm xóa trắng DEK bản rõ trong `finally`.
   */
  async rotateKeyRef(
    combinedRef: string,
    targetProvider: KmsProviderType = this.activeProvider,
  ): Promise<KmsWrapResult> {
    const decryptedDek = await this.unwrapCombinedRef(combinedRef);
    try {
      switch (targetProvider) {
        case 'hsm-pkcs11':
          return await this.hsmProvider.wrapKey(decryptedDek);
        case 'vault':
          return await this.vaultProvider.wrapKey(decryptedDek);
        case 'aws-kms':
          return await this.cloudProvider.wrapKey(decryptedDek);
        case 'local':
        default:
          return await super.wrapKey(decryptedDek);
      }
    } finally {
      decryptedDek.fill(0);
    }
  }
}
