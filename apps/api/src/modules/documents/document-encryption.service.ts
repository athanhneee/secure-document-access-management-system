/**
 * Module: Dịch vụ Mã hóa Tài liệu Phong bì Xác thực (Authenticated Envelope Document Encryption)
 * Thuật toán: Mã Hóa Đối Xứng Xác Thực AES-256-GCM Phong Bì (`SDAE v1/v2`) & Xóa Trắng Khóa DEK Bắt Buộc Trong `finally`.
 *   1. Sinh khóa DEK 256-bit ngẫu nhiên riêng biệt cho từng phiên bản tệp, mã hóa AES-256-GCM kèm AAD ngữ cảnh tài liệu (nếu có).
 *   2. Bọc cả quá trình mã hóa (`encryptBuffer`) và giải mã (`decryptToTempFile`) trong khối `try { ... } finally { dek.fill(0); }`
 *      để đảm bảo vùng nhớ DEK luôn bị xóa trắng về `0` kể cả khi KMS, GCM auth tag hoặc hệ thống tệp phát sinh ngoại lệ.
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

const MAGIC_BYTES = Buffer.from([0x53, 0x44, 0x41, 0x45]); // 'SDAE'
const FORMAT_VERSION = 0x01;
const FORMAT_VERSION_AAD = 0x02;
const IV_LENGTH = 12;
const TAG_LENGTH = 16;
const HEADER_LENGTH = MAGIC_BYTES.length + 1 + IV_LENGTH + TAG_LENGTH; // 33 bytes

function encodeDocumentAad(aadContext: string): Buffer {
  return Buffer.from(`sda-doc-v2:${aadContext}`, 'utf8');
}

@Injectable()
export class DocumentEncryptionService {
  private readonly logger = new Logger(DocumentEncryptionService.name);

  constructor(private readonly kms: LocalKmsService) {}

  /**
   * Thuật toán: Mã Hóa Phong Bì AES-256-GCM Độc Lập Theo Phiên Bản & Xóa Trắng Khóa Trong `finally`.
   * Đóng gói định dạng nhị phân 33 byte đầu: `[Magic 'SDAE' (4B) || Version (1B) || IV (12B) || GCM Tag (16B) || Ciphertext]`.
   */
  async encryptBuffer(plaintext: Buffer, aadContext?: string): Promise<EncryptedDocumentResult> {
    const sha256Hash = crypto.createHash('sha256').update(plaintext).digest('hex');
    const fileSizeBytes = plaintext.length;
    const dek = crypto.randomBytes(32);

    try {
      const iv = crypto.randomBytes(IV_LENGTH);
      const hasAad = typeof aadContext === 'string' && aadContext.length > 0;

      const cipher = crypto.createCipheriv('aes-256-gcm', dek, iv);
      if (hasAad) {
        cipher.setAAD(encodeDocumentAad(aadContext));
      }
      const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      const tag = cipher.getAuthTag();

      const { combinedRef } = await this.kms.wrapKey(dek);

      const header = Buffer.alloc(HEADER_LENGTH);
      MAGIC_BYTES.copy(header, 0);
      header.writeUInt8(hasAad ? FORMAT_VERSION_AAD : FORMAT_VERSION, 4);
      iv.copy(header, 5);
      tag.copy(header, 5 + IV_LENGTH);

      return {
        encryptedBuffer: Buffer.concat([header, ciphertext]),
        dekReference: combinedRef,
        sha256Hash,
        fileSizeBytes,
      };
    } finally {
      dek.fill(0);
    }
  }

  /**
   * Thuật toán: Giải Mã Xác Thực Trước Khi Ghi (`Verify-Before-Release`) & Xóa Trắng DEK Bắt Buộc Trong `finally`.
   * Xác minh chữ ký GCM 128-bit hoàn tất trong bộ nhớ trước khi ghi xuống tệp tạm quyền `0o600`,
   * đồng thời dọn dẹp tệp tạm và ghi đè `dek.fill(0)` trong mọi nhánh thành công hoặc ngoại lệ.
   */
  async decryptToTempFile(
    encryptedData: Buffer,
    encryptionKeyRef: string,
    expectedAadContext?: string,
  ): Promise<DecryptedDocumentResult> {
    if (encryptedData.length < HEADER_LENGTH) {
      throw new Error('Encrypted payload is too small to contain valid header.');
    }

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

    const dek = await this.kms.unwrapCombinedRef(encryptionKeyRef);
    let tempDir: string | null = null;
    let tempFilePath = '';

    const cleanup = async () => {
      try {
        if (tempFilePath && fs.existsSync(tempFilePath)) {
          const stat = await fsp.stat(tempFilePath).catch(() => null);
          if (stat?.size) {
            await fsp
              .writeFile(tempFilePath, Buffer.alloc(Math.min(stat.size, 4096), 0))
              .catch(() => {});
          }
          await fsp.unlink(tempFilePath).catch(() => {});
        }
        if (tempDir && fs.existsSync(tempDir)) {
          await fsp.rmdir(tempDir).catch(() => {});
        }
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        this.logger.warn(`Failed to clean up temp file ${tempFilePath}: ${msg}`);
      }
    };

    try {
      tempDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'sda-dec-'));
      tempFilePath = path.join(tempDir, `doc-${crypto.randomBytes(8).toString('hex')}.tmp`);

      const decipher = crypto.createDecipheriv('aes-256-gcm', dek, iv, {
        authTagLength: TAG_LENGTH,
      });
      if (version === FORMAT_VERSION_AAD && expectedAadContext) {
        decipher.setAAD(encodeDocumentAad(expectedAadContext));
      }
      decipher.setAuthTag(tag);

      const decryptedChunk = decipher.update(ciphertext);
      const finalChunk = decipher.final();
      const plaintext = Buffer.concat([decryptedChunk, finalChunk]);

      await fsp.writeFile(tempFilePath, plaintext, { mode: 0o600 });

      const sha256Hash = crypto.createHash('sha256').update(plaintext).digest('hex');
      const fileSizeBytes = plaintext.length;

      return {
        tempFilePath,
        sha256Hash,
        fileSizeBytes,
        cleanup,
      };
    } catch {
      await cleanup();
      throw new Error(
        'Document decryption failed: Authentication tag verification failed or ciphertext tampered.',
      );
    } finally {
      dek.fill(0);
    }
  }
}
