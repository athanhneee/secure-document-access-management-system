/**
 * @module MfaService
 * Thuật toán: Dịch vụ xác thực đa nhân tố chuẩn RFC 6238 TOTP chống phát lại phi chặn qua `HMAC-SHA256` + `DistributedStateService.claimOnce`,
 * mã hóa xác thực đối xứng AEAD AES-256-GCM và quản lý mã khôi phục một lần băm kèm Pepper phân tách miền.
 */
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto';
import { Injectable, Optional } from '@nestjs/common';
import * as OTPAuth from 'otpauth';
import { AppConfigService } from '../../config/config.service.js';
import { DistributedStateService } from '../concurrency/distributed-state.service.js';

const TOTP_REPLAY_WINDOW_TTL_MS = 90_000;

@Injectable()
export class MfaService {
  private readonly encryptionKey: Buffer;
  private readonly recoveryPepper: Buffer;
  private readonly replayHmacSecret: Buffer;
  private readonly stateStore: DistributedStateService;

  /**
   * Thuật toán: Dẫn xuất khóa con phân tách miền bằng SHA-256 (Domain-Separated SHA-256 Key Derivation).
   * Mục đích: Từ khóa chủ `APP_ENCRYPTION_MASTER_KEY`, tách biệt hoàn toàn khóa mã hóa bí mật TOTP (`mfa-encryption:`),
   * khóa pepper băm mã khôi phục (`mfa-recovery:`) và khóa HMAC chống phát lại (`mfa-totp-replay:`).
   */
  constructor(config: AppConfigService, @Optional() stateStore?: DistributedStateService) {
    const master = config.get('APP_ENCRYPTION_MASTER_KEY');
    this.encryptionKey = createHash('sha256').update(`mfa-encryption:${master}`).digest();
    this.recoveryPepper = createHash('sha256').update(`mfa-recovery:${master}`).digest();
    this.replayHmacSecret = createHash('sha256').update(`mfa-totp-replay:${master}`).digest();
    this.stateStore = stateStore ?? new DistributedStateService(config);
  }

  /**
   * Thuật toán: Khởi tạo hạt giống mật mã TOTP chuẩn RFC 6238 (256-bit Base32 Secret Enrollment).
   */
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

  /**
   * Thuật toán: Xác thực mã OTP theo thời gian chuẩn RFC 6238 §5.2 TOTP (cửa sổ ±1 chu kỳ 30s)
   * và tiêu thụ nguyên tử một lần bước thời gian qua `HMAC-SHA256(userId:stepCounter)` trên `DistributedStateService` (không chặn Event Loop).
   */
  async verifyTotp(
    encryptedSecret: string,
    token: string,
    userId?: bigint | string,
  ): Promise<boolean> {
    if (!/^\d{6}$/.test(token)) return false;
    const rawSecret = this.decrypt(encryptedSecret);
    const now = Date.now();
    const totp = new OTPAuth.TOTP({
      issuer: 'Secure Document Access',
      label: 'verification',
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      secret: OTPAuth.Secret.fromBase32(rawSecret),
    });
    const delta = totp.validate({ token, window: 1, timestamp: now });
    if (delta === null) return false;

    const stepCounter = Math.floor(now / 30_000) + delta;
    const subjectScope =
      userId !== undefined
        ? String(userId)
        : createHmac('sha256', this.replayHmacSecret).update(`secret:${rawSecret}`).digest('hex');
    const replayKey = createHmac('sha256', this.replayHmacSecret)
      .update(`${subjectScope}:${stepCounter}`)
      .digest('hex');

    return this.stateStore.claimOnce('totp-step', replayKey, TOTP_REPLAY_WINDOW_TTL_MS, {
      failClosedInProd: true,
    });
  }

  /**
   * Thuật toán: Sinh tập mã khôi phục dự phòng entropy cao (128-bit CSPRNG Base64URL Recovery Codes).
   */
  createRecoveryCodes(count = 10): { plaintext: string[]; hashes: string[] } {
    const plaintext = Array.from({ length: count }, () => randomBytes(16).toString('base64url'));
    return { plaintext, hashes: plaintext.map((code) => this.hashRecoveryCode(code)) };
  }

  /**
   * Thuật toán: Đối chiếu thời gian hằng số và tiêu thụ nguyên tử mã khôi phục một lần (Constant-Time Single-Use Consumption).
   */
  consumeRecoveryCode(storedHashes: string[], candidate: string): string[] | null {
    const candidateHash = Buffer.from(this.hashRecoveryCode(candidate), 'hex');
    const index = storedHashes.findIndex((hash) => {
      const stored = Buffer.from(hash, 'hex');
      return stored.length === candidateHash.length && timingSafeEqual(stored, candidateHash);
    });
    if (index < 0) return null;
    return storedHashes.filter((_, current) => current !== index);
  }

  /**
   * Thuật toán: Băm SHA-256 gắn Pepper bí mật sau chuẩn hóa tương đương Unicode NFKC.
   */
  private hashRecoveryCode(code: string): string {
    return createHash('sha256')
      .update(this.recoveryPepper)
      .update(code.normalize('NFKC'), 'utf8')
      .digest('hex');
  }

  /**
   * Thuật toán: Mã hóa xác thực đối xứng AEAD AES-256-GCM đóng gói nhị phân `[12B IV || 16B AuthTag || Ciphertext]`.
   */
  encrypt(value: string): string {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.encryptionKey, iv);
    const ciphertext = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), ciphertext]).toString('base64url');
  }

  /**
   * Thuật toán: Giải mã và xác minh toàn vẹn AEAD AES-256-GCM từ khung `[12B IV || 16B AuthTag || Ciphertext]`.
   */
  decrypt(value: string): string {
    const packed = Buffer.from(value, 'base64url');
    if (packed.length < 29) throw new Error('Invalid encrypted MFA secret.');
    const decipher = createDecipheriv('aes-256-gcm', this.encryptionKey, packed.subarray(0, 12), {
      authTagLength: 16,
    });
    decipher.setAuthTag(packed.subarray(12, 28));
    return Buffer.concat([decipher.update(packed.subarray(28)), decipher.final()]).toString('utf8');
  }

  /**
   * Thuật toán: Tuần tự hóa JSON kết hợp mã hóa xác thực AEAD AES-256-GCM cho trạng thái khóa WebAuthn.
   */
  encryptPayload<T>(payload: T): string {
    return this.encrypt(JSON.stringify(payload));
  }

  /**
   * Thuật toán: Giải mã xác thực AEAD AES-256-GCM và khôi phục cấu trúc đối tượng JSON.
   */
  decryptPayload<T>(value: string): T {
    return JSON.parse(this.decrypt(value)) as T;
  }
}
