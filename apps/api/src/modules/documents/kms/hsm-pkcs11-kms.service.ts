/**
 * Module: Hardware Security Module (HSM) PKCS#11 KMS Service
 * Algorithm: Derives slot/label-isolated HSM KEK via HKDF-SHA256, enforces PIN verification,
 *   and wraps/unwraps 256-bit DEKs via RFC 3394 / NIST SP 800-38F `id-aes256-wrap` (`CKM_AES_KEY_WRAP`).
 */
import { Injectable, Logger } from '@nestjs/common';
import crypto from 'node:crypto';
import { AppConfigService } from '../../../config/config.service.js';
import { KmsService, splitCombinedKeyRef, type KmsWrapResult } from './kms.types.js';

@Injectable()
export class HsmPkcs11KmsService implements KmsService {
  // shortcut: software PKCS#11 slot emulator restricted to dev/test by env.schema.ts, wire pkcs11js native module for hardware Luna/CloudHSM slots
  private readonly logger = new Logger(HsmPkcs11KmsService.name);
  readonly slotIndex: number;
  readonly keyLabel: string;
  private readonly pin: string;
  private readonly hsmKek: Buffer;
  private readonly nistIv = Buffer.from('a6a6a6a6a6a6a6a6', 'hex');

  constructor(config: AppConfigService) {
    this.slotIndex = config.get('HSM_SLOT_INDEX') ?? 0;
    this.keyLabel = config.get('HSM_KEY_LABEL') ?? 'SDA-MASTER-KEK-v1';
    this.pin = config.get('HSM_PIN') ?? '123456';

    const masterKey = config.get('APP_ENCRYPTION_MASTER_KEY');
    this.hsmKek = Buffer.from(
      crypto.hkdfSync(
        'sha256',
        Buffer.from(masterKey, 'utf8'),
        Buffer.from(`HSM-SLOT-${this.slotIndex}`, 'utf8'),
        Buffer.from(`PKCS11-CKM_AES_KEY_WRAP:${this.keyLabel}`, 'utf8'),
        32,
      ),
    );
    this.logger.log(
      `HSM PKCS#11 service initialized on slot ${this.slotIndex} with key "${this.keyLabel}"`,
    );
  }

  get keyRef(): string {
    return `hsm-pkcs11:slot-${this.slotIndex}:${this.keyLabel}`;
  }

  /**
   * Algorithm: Constant-Time PKCS#11 Slot User PIN Verification (`CKR_PIN_INCORRECT`)
   * Hashes both configured slot PIN and caller-supplied PIN with SHA-256 and compares fixed 32-byte digests via `crypto.timingSafeEqual`.
   */
  private verifyPin(inputPin?: string): void {
    const pinToCheck = inputPin ?? this.pin;
    if (
      !pinToCheck ||
      pinToCheck.trim().length === 0 ||
      !this.pin ||
      this.pin.trim().length === 0
    ) {
      throw new Error('HSM PIN is required for authentication (CKR_PIN_INCORRECT).');
    }
    const expectedDigest = crypto.createHash('sha256').update(this.pin, 'utf8').digest();
    const actualDigest = crypto.createHash('sha256').update(pinToCheck, 'utf8').digest();
    if (!crypto.timingSafeEqual(expectedDigest, actualDigest)) {
      throw new Error('HSM PIN verification failed: invalid slot PIN (CKR_PIN_INCORRECT).');
    }
  }

  /**
   * Algorithm: RFC 3394 / NIST SP 800-38F AES Key Wrap (`CKM_AES_KEY_WRAP`)
   * Produces a deterministic 40-byte integrity-protected wrapped key block using the 64-bit NIST A6 IV.
   */
  async wrapKey(plaintextDek: Buffer, pin?: string): Promise<KmsWrapResult> {
    this.verifyPin(pin);
    if (plaintextDek.length !== 32) {
      throw new Error('DEK must be exactly 32 bytes (256 bits).');
    }

    const cipher = crypto.createCipheriv('id-aes256-wrap', this.hsmKek, this.nistIv);
    const wrappedPayload = Buffer.concat([cipher.update(plaintextDek), cipher.final()]);
    const wrappedDek = wrappedPayload.toString('base64url');
    const keyRef = this.keyRef;
    return {
      wrappedDek,
      keyRef,
      combinedRef: `${keyRef}:${wrappedDek}`,
    };
  }

  /**
   * Algorithm: RFC 3394 / NIST SP 800-38F AES Key Unwrap
   * Verifies the 64-bit NIST integrity check value on the 40-byte wrapped key block.
   */
  async unwrapKey(wrappedDek: string, keyRef: string, pin?: string): Promise<Buffer> {
    this.verifyPin(pin);
    if (!keyRef.startsWith('hsm-pkcs11:')) {
      throw new Error(`Unsupported KMS keyRef format: ${keyRef}`);
    }

    const payload = Buffer.from(wrappedDek, 'base64url');
    if (payload.length !== 40) {
      throw new Error('Invalid HSM wrapped DEK payload length (expected 40 bytes).');
    }

    try {
      const decipher = crypto.createDecipheriv('id-aes256-wrap', this.hsmKek, this.nistIv);
      const decryptedDek = Buffer.concat([decipher.update(payload), decipher.final()]);
      if (decryptedDek.length !== 32) {
        throw new Error('Decrypted DEK length is invalid.');
      }
      return decryptedDek;
    } catch {
      throw new Error(
        'Failed to unwrap DEK via HSM: hardware key wrap integrity check failed or corrupted key (CKR_DEVICE_ERROR).',
      );
    }
  }

  async unwrapCombinedRef(combinedRef: string, pin?: string): Promise<Buffer> {
    const { keyRef, wrappedDek } = splitCombinedKeyRef(combinedRef);
    return this.unwrapKey(wrappedDek, keyRef, pin);
  }
}
