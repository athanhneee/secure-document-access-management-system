import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto';
import { Injectable } from '@nestjs/common';
import * as OTPAuth from 'otpauth';
import { AppConfigService } from '../../config/config.service.js';

@Injectable()
export class MfaService {
  private readonly encryptionKey: Buffer;
  private readonly recoveryPepper: Buffer;

  constructor(config: AppConfigService) {
    const master = config.get('APP_ENCRYPTION_MASTER_KEY');
    this.encryptionKey = createHash('sha256').update(`mfa-encryption:${master}`).digest();
    this.recoveryPepper = createHash('sha256').update(`mfa-recovery:${master}`).digest();
  }

  createEnrollment(accountName: string): { encryptedSecret: string; uri: string; secret: string } {
    const secret = new OTPAuth.Secret({ size: 32 });
    const totp = new OTPAuth.TOTP({
      issuer: 'Secure Document Access',
      label: accountName,
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      secret,
    });
    return {
      secret: secret.base32,
      encryptedSecret: this.encrypt(secret.base32),
      uri: totp.toString(),
    };
  }

  verifyTotp(encryptedSecret: string, token: string): boolean {
    if (!/^\d{6}$/.test(token)) return false;
    const totp = new OTPAuth.TOTP({
      issuer: 'Secure Document Access',
      label: 'verification',
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      secret: OTPAuth.Secret.fromBase32(this.decrypt(encryptedSecret)),
    });
    return totp.validate({ token, window: 1 }) !== null;
  }

  createRecoveryCodes(count = 10): { plaintext: string[]; hashes: string[] } {
    const plaintext = Array.from({ length: count }, () => randomBytes(16).toString('base64url'));
    return { plaintext, hashes: plaintext.map((code) => this.hashRecoveryCode(code)) };
  }

  consumeRecoveryCode(storedHashes: string[], candidate: string): string[] | null {
    const candidateHash = Buffer.from(this.hashRecoveryCode(candidate), 'hex');
    const index = storedHashes.findIndex((hash) => {
      const stored = Buffer.from(hash, 'hex');
      return stored.length === candidateHash.length && timingSafeEqual(stored, candidateHash);
    });
    if (index < 0) return null;
    return storedHashes.filter((_, current) => current !== index);
  }

  private hashRecoveryCode(code: string): string {
    return createHash('sha256')
      .update(this.recoveryPepper)
      .update(code.normalize('NFKC'), 'utf8')
      .digest('hex');
  }

  encrypt(value: string): string {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.encryptionKey, iv);
    const ciphertext = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), ciphertext]).toString('base64url');
  }

  decrypt(value: string): string {
    const packed = Buffer.from(value, 'base64url');
    if (packed.length < 29) throw new Error('Invalid encrypted MFA secret.');
    const decipher = createDecipheriv('aes-256-gcm', this.encryptionKey, packed.subarray(0, 12));
    decipher.setAuthTag(packed.subarray(12, 28));
    return Buffer.concat([decipher.update(packed.subarray(28)), decipher.final()]).toString('utf8');
  }

  encryptPayload<T>(payload: T): string {
    return this.encrypt(JSON.stringify(payload));
  }

  decryptPayload<T>(value: string): T {
    return JSON.parse(this.decrypt(value)) as T;
  }
}
