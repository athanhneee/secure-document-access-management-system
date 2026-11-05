/**
 * @module MfaService
 * Dịch vụ xác thực đa nhân tố (Multi-Factor Authentication) chuẩn RFC 6238 TOTP,
 * mã hóa xác thực AES-256-GCM và quản lý mã khôi phục một lần băm kèm Pepper phân tách miền.
 */
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

  /**
   * Thuật toán: Dẫn xuất khóa con phân tách miền bằng SHA-256 (Domain-Separated SHA-256 Key Derivation).
   * Mục đích: Từ khóa chủ `APP_ENCRYPTION_MASTER_KEY`, tách biệt hoàn toàn khóa mã hóa bí mật TOTP
   * (`mfa-encryption:`) và khóa pepper băm mã khôi phục (`mfa-recovery:`) chống tấn công tái sử dụng khóa chéo miền.
   */
  constructor(config: AppConfigService) {
    const master = config.get('APP_ENCRYPTION_MASTER_KEY');
    this.encryptionKey = createHash('sha256').update(`mfa-encryption:${master}`).digest();
    this.recoveryPepper = createHash('sha256').update(`mfa-recovery:${master}`).digest();
  }

  /**
   * Thuật toán: Khởi tạo hạt giống mật mã TOTP chuẩn RFC 6238 (256-bit Base32 Secret Enrollment).
   * Cơ chế hoạt động: Sinh ngẫu nhiên 32 byte bí mật gốc, đóng gói URI `otpauth://totp/...` (HMAC-SHA1,
   * 6 chữ số, chu kỳ 30 giây) và mã hóa xác thực AES-256-GCM trước khi lưu xuống cơ sở dữ liệu.
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
   * Thuật toán: Xác thực mã OTP theo thời gian chuẩn RFC 6238 TOTP với cửa sổ lệch đồng hồ ±1 chu kỳ.
   * Cơ chế hoạt động: Giải mã xác thực bí mật Base32, tính giá trị HMAC-SHA1 cắt động (Dynamic Truncation)
   * trên bước thời gian 30 giây hiện tại cùng 2 bước lân cận (`window: 1`) để bù độ trễ đồng hồ client-server.
   */
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

  /**
   * Thuật toán: Sinh tập mã khôi phục dự phòng entropy cao (128-bit CSPRNG Base64URL Recovery Codes).
   * Cơ chế hoạt động: Tạo `count` mã ngẫu nhiên độc lập 16 byte qua CSPRNG và chỉ lưu bản băm một chiều.
   */
  createRecoveryCodes(count = 10): { plaintext: string[]; hashes: string[] } {
    const plaintext = Array.from({ length: count }, () => randomBytes(16).toString('base64url'));
    return { plaintext, hashes: plaintext.map((code) => this.hashRecoveryCode(code)) };
  }

  /**
   * Thuật toán: Đối chiếu thời gian hằng số và tiêu thụ nguyên tử mã khôi phục một lần (Constant-Time Single-Use Consumption).
   * Cơ chế hoạt động: Băm mã ứng viên kèm pepper, duyệt danh sách bằng `timingSafeEqual` để chống rò rỉ kênh kề
   * thời gian (timing side-channel), và trả về mảng mới đã loại bỏ phần tử vừa tiêu thụ.
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
   * Cơ chế hoạt động: Sinh IV ngẫu nhiên 96-bit cho mỗi lần mã hóa, thu thẻ xác thực Galois 128-bit (`AuthTag`)
   * và nối thành một khung nhị phân duy nhất mã hóa Base64URL an toàn cho lưu trữ.
   */
  encrypt(value: string): string {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.encryptionKey, iv);
    const ciphertext = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), ciphertext]).toString('base64url');
  }

  /**
   * Thuật toán: Giải mã và xác minh toàn vẹn AEAD AES-256-GCM từ khung `[12B IV || 16B AuthTag || Ciphertext]`.
   * Cơ chế hoạt động: Kiểm tra chiều dài tối thiểu 29 byte, tách 12 byte đầu làm IV, byte `[12..28)` làm thẻ GCM,
   * và gọi `decipher.final()` để xác thực tính toàn vẹn trước khi trả bản rõ UTF-8.
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
   * Thuật toán: Tuần tự hóa JSON kết hợp mã hóa xác thực AEAD AES-256-GCM cho trạng thái thử thách tạm thời.
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
