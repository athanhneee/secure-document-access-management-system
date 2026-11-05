/**
 * Module: Dịch vụ Mã hóa Tài liệu Phong bì Xác thực (Authenticated Envelope Document Encryption)
 * Thuật toán: Mã hóa đối xứng xác thực AES-256-GCM với khóa dữ liệu (DEK) 256-bit độc nhất cho từng phiên bản tệp,
 *   đóng gói khung nhị phân tự mô tả `SDAE v1` (33-byte header) và giải mã xác thực toàn vẹn trước khi xuất bản rõ.
 */
import { Injectable, Logger } from '@nestjs/common';
import crypto from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { LocalKmsService } from './kms.service.js';

export interface EncryptedDocumentResult {
  encryptedBuffer: Buffer;
  dekReference: string;
  sha256Hash: string;
  fileSizeBytes: number;
}

export interface DecryptedDocumentResult {
  tempFilePath: string;
  sha256Hash: string;
  fileSizeBytes: number;
  cleanup: () => Promise<void>;
}

// 4 bytes magic: 'SDAE' (Secure Document Access Encrypted)
const MAGIC_BYTES = Buffer.from([0x53, 0x44, 0x41, 0x45]);
const FORMAT_VERSION = 0x01; // 1 byte legacy envelope version
const FORMAT_VERSION_AAD = 0x02; // 1 byte context-bound AAD envelope version
const IV_LENGTH = 12; // 96 bits
const TAG_LENGTH = 16; // 128 bits
const HEADER_LENGTH = MAGIC_BYTES.length + 1 + IV_LENGTH + TAG_LENGTH; // 4 + 1 + 12 + 16 = 33 bytes

function encodeDocumentAad(aadContext: string): Buffer {
  return Buffer.from(`sda-doc-v2:${aadContext}`, 'utf8');
}

@Injectable()
export class DocumentEncryptionService {
  private readonly logger = new Logger(DocumentEncryptionService.name);

  constructor(private readonly kms: LocalKmsService) {}

  /**
   * Encrypts plaintext buffer using envelope encryption:
   * - Generates unique random 32-byte DEK (AES-256)
   * - Generates unique random 12-byte IV (96-bit)
   * - Encrypts using AES-256-GCM
   * - Wraps DEK using KMS interface
   * - Prepends 33-byte header: [Magic 4B][Ver 1B][IV 12B][Tag 16B][Ciphertext...]
   *
   * Thuật toán: Mã Hóa Phong Bì AES-256-GCM Độc Lập Theo Phiên Bản & Xóa Trắng Khóa Trong RAM
   * Mục đích: Đảm bảo tính bí mật và toàn vẹn của nội dung tài liệu lưu trữ trên Object Storage với khóa DEK riêng biệt.
   * Cơ chế hoạt động:
   *   - Băm kiểm tra SHA-256 bản rõ, sinh ngẫu nhiên mật mã DEK 32 byte và IV 12 byte mới hoàn toàn.
   *   - Thực thi `aes-256-gcm` thu bản mã và nhãn xác thực `tag` 16 byte, sau đó gọi KMS bọc DEK và ghi đè `dek.fill(0)` ngay lập tức.
   *   - Đóng gói định dạng nhị phân chuẩn 33 byte đầu: `[Magic 'SDAE' (4B) || Version 0x01 (1B) || IV (12B) || GCM Tag (16B) || Ciphertext]`.
   */
  async encryptBuffer(plaintext: Buffer, aadContext?: string): Promise<EncryptedDocumentResult> {
    const sha256Hash = crypto.createHash('sha256').update(plaintext).digest('hex');
    const fileSizeBytes = plaintext.length;

    // 1. Fresh random DEK (256-bit) and IV (96-bit)
    const dek = crypto.randomBytes(32);
    const iv = crypto.randomBytes(IV_LENGTH);
    const hasAad = typeof aadContext === 'string' && aadContext.length > 0;

    // 2. Encrypt plaintext
    const cipher = crypto.createCipheriv('aes-256-gcm', dek, iv);
    if (hasAad) {
      // CONFLICT-RESOLVED: Gắn ngữ cảnh AAD (`documentId`) vào thẻ xác thực AES-256-GCM để chặn tấn công hoán đổi bản mã giữa các tài liệu (HIGH-09).
      cipher.setAAD(encodeDocumentAad(aadContext));
    }
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();

    // 3. Wrap DEK via KMS
    const { combinedRef } = await this.kms.wrapKey(dek);

    // Zero out DEK memory buffer
    dek.fill(0);

    // 4. Construct encrypted binary format
    const header = Buffer.alloc(HEADER_LENGTH);
    MAGIC_BYTES.copy(header, 0);
    header.writeUInt8(hasAad ? FORMAT_VERSION_AAD : FORMAT_VERSION, 4);
    iv.copy(header, 5);
    tag.copy(header, 5 + IV_LENGTH);

    const encryptedBuffer = Buffer.concat([header, ciphertext]);

    return {
      encryptedBuffer,
      dekReference: combinedRef,
      sha256Hash,
      fileSizeBytes,
    };
  }

  /**
   * Decrypts encrypted document bytes into a private temporary file.
   * Requirement 9: No plaintext is emitted before GCM tag is verified.
   * If tag verification fails (e.g. 1 byte modified), the temp file is securely
   * unlinked and an authentication error is thrown.
   *
   * Thuật toán: Giải Mã Xác Thực Trước Khi Ghi (Verify-Before-Release Authenticated Decryption)
   * Mục đích: Khôi phục tài liệu ra tệp tạm cô lập quyền `0o600` chỉ sau khi xác minh chữ ký GCM hợp lệ 100%,
   *   tuyệt đối không phát tán dữ liệu giải mã dở dang nếu bản mã bị can thiệp dù chỉ 1 bit.
   * Cơ chế hoạt động:
   *   - Phân tích header 33 byte kiểm tra chữ ký `SDAE` và phiên bản định dạng `0x01`, tách `iv`, `tag`, `ciphertext`.
   *   - Giải bọc DEK qua KMS, nạp `tag` vào bộ giải mã `aes-256-gcm` và gọi `decipher.final()` trong bộ nhớ để xác thực toàn vẹn
   *     trước khi ghi xuống đĩa với chế độ phân quyền `0o600`.
   *   - Cung cấp hàm dọn dẹp `cleanup()` thực hiện ghi đè byte `0` lên đầu tệp trước khi `unlink` và xóa thư mục tạm riêng biệt;
   *     đồng thời luôn xóa trắng vùng nhớ `dek.fill(0)` ở cả nhánh thành công lẫn nhánh bắt lỗi.
   */
  async decryptToTempFile(
    encryptedData: Buffer,
    encryptionKeyRef: string,
    expectedAadContext?: string,
  ): Promise<DecryptedDocumentResult> {
    if (encryptedData.length < HEADER_LENGTH) {
      throw new Error('Encrypted payload is too small to contain valid header.');
    }

    // 1. Validate header
    const magic = encryptedData.subarray(0, 4);
    if (!magic.equals(MAGIC_BYTES)) {
      throw new Error('Invalid encrypted document format: magic bytes mismatch.');
    }

    const version = encryptedData.readUInt8(4);
    if (version !== FORMAT_VERSION && version !== FORMAT_VERSION_AAD) {
      throw new Error(`Unsupported encrypted document format version: ${version}`);
    }
    if (
      version === FORMAT_VERSION_AAD &&
      (!expectedAadContext || expectedAadContext.length === 0)
    ) {
      throw new Error(
        'Document decryption failed: Authentication tag verification failed or missing AAD context.',
      );
    }

    const iv = encryptedData.subarray(5, 5 + IV_LENGTH);
    const tag = encryptedData.subarray(5 + IV_LENGTH, HEADER_LENGTH);
    const ciphertext = encryptedData.subarray(HEADER_LENGTH);

    // 2. Unwrap DEK from KMS
    const dek = await this.kms.unwrapCombinedRef(encryptionKeyRef);

    // 3. Prepare private temporary file
    const tempDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'sda-dec-'));
    const tempFilePath = path.join(tempDir, `doc-${crypto.randomBytes(8).toString('hex')}.tmp`);

    const decipher = crypto.createDecipheriv('aes-256-gcm', dek, iv, {
      authTagLength: TAG_LENGTH,
    });
    if (version === FORMAT_VERSION_AAD && expectedAadContext) {
      decipher.setAAD(encodeDocumentAad(expectedAadContext));
    }
    decipher.setAuthTag(tag);

    const cleanup = async () => {
      try {
        if (fs.existsSync(tempFilePath)) {
          // Overwrite with zeroes before deleting for extra safety
          const stat = await fsp.stat(tempFilePath).catch(() => null);
          if (stat?.size) {
            await fsp
              .writeFile(tempFilePath, Buffer.alloc(Math.min(stat.size, 4096), 0))
              .catch(() => {});
          }
          await fsp.unlink(tempFilePath).catch(() => {});
        }
        if (fs.existsSync(tempDir)) {
          await fsp.rmdir(tempDir).catch(() => {});
        }
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        this.logger.warn(`Failed to clean up temp file ${tempFilePath}: ${msg}`);
      }
    };

    try {
      // Decrypt to buffer and verify tag BEFORE persisting or returning
      const decryptedChunk = decipher.update(ciphertext);
      const finalChunk = decipher.final(); // <--- Verifies GCM auth tag here!

      const plaintext = Buffer.concat([decryptedChunk, finalChunk]);

      // Write verified plaintext to temp file
      await fsp.writeFile(tempFilePath, plaintext, { mode: 0o600 });

      const sha256Hash = crypto.createHash('sha256').update(plaintext).digest('hex');
      const fileSizeBytes = plaintext.length;

      // Zero out DEK memory buffer
      dek.fill(0);

      return {
        tempFilePath,
        sha256Hash,
        fileSizeBytes,
        cleanup,
      };
    } catch {
      // If tag verification fails or any error occurs, zero out DEK and clean up temp immediately
      dek.fill(0);
      await cleanup();
      throw new Error(
        'Document decryption failed: Authentication tag verification failed or ciphertext tampered.',
      );
    }
  }
}
