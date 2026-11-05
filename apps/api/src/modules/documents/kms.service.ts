/**
 * Module: Unified Multi-Provider Envelope KMS Orchestrator
 * Algorithm: Dynamically routes DEK wrap operations to the configured active KMS provider (`local`,
 *   `hsm-pkcs11`, `vault`, `aws-kms`), dispatches unwrap operations by `keyRef` prefix for backward
 *   compatibility, and executes zero-downtime DEK re-wrapping with mandatory plaintext zeroization.
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
import { VaultTransitKmsService } from './kms/vault-transit-kms.service.js';
import { CloudKmsService } from './kms/cloud-kms.service.js';

export {
  CloudKmsService,
  HsmPkcs11KmsService,
  KmsService,
  LocalKmsService,
  VaultTransitKmsService,
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
   * Algorithm: Active-Provider Envelope DEK Wrap Router
   */
  override async wrapKey(plaintextDek: Buffer): Promise<KmsWrapResult> {
    switch (this.activeProvider) {
      case 'hsm-pkcs11':
        return await this.hsmProvider.wrapKey(plaintextDek);
      case 'vault':
        return await this.vaultProvider.wrapKey(plaintextDek);
      case 'aws-kms':
        return await this.cloudProvider.wrapKey(plaintextDek);
      case 'local':
      default:
        return await super.wrapKey(plaintextDek);
    }
  }

  /**
   * Algorithm: Prefix-Directed Multi-Provider DEK Unwrap Router
   */
  override async unwrapKey(wrappedDek: string, keyRef: string): Promise<Buffer> {
    if (keyRef.startsWith('local-kms:')) {
      return await super.unwrapKey(wrappedDek, keyRef);
    }
    if (keyRef.startsWith('hsm-pkcs11:')) {
      return await this.hsmProvider.unwrapKey(wrappedDek, keyRef);
    }
    if (keyRef.startsWith('vault-kms:')) {
      return await this.vaultProvider.unwrapKey(wrappedDek, keyRef);
    }
    if (keyRef.startsWith('aws-kms:')) {
      return await this.cloudProvider.unwrapKey(wrappedDek, keyRef);
    }
    throw new Error(`Unsupported KMS keyRef format: ${keyRef}`);
  }

  override async unwrapCombinedRef(combinedRef: string): Promise<Buffer> {
    const { keyRef, wrappedDek } = splitCombinedKeyRef(combinedRef);
    return this.unwrapKey(wrappedDek, keyRef);
  }

  /**
   * Algorithm: Zero-Downtime Cross-Provider Envelope Key Rotation
   * Unwraps DEK into transient memory, re-wraps under `targetProvider`, and zeroes plaintext DEK bytes in `finally`.
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
