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
const FORMAT_VERSION = 0x01; // 1 byte version
const IV_LENGTH = 12; // 96 bits
const TAG_LENGTH = 16; // 128 bits
const HEADER_LENGTH = MAGIC_BYTES.length + 1 + IV_LENGTH + TAG_LENGTH; // 4 + 1 + 12 + 16 = 33 bytes

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
   */
  async encryptBuffer(plaintext: Buffer): Promise<EncryptedDocumentResult> {
    const sha256Hash = crypto.createHash('sha256').update(plaintext).digest('hex');
    const fileSizeBytes = plaintext.length;

    // 1. Fresh random DEK (256-bit) and IV (96-bit)
    const dek = crypto.randomBytes(32);
    const iv = crypto.randomBytes(IV_LENGTH);

    // 2. Encrypt plaintext
    const cipher = crypto.createCipheriv('aes-256-gcm', dek, iv);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();

    // 3. Wrap DEK via KMS
    const { combinedRef } = await this.kms.wrapKey(dek);

    // Zero out DEK memory buffer
    dek.fill(0);

    // 4. Construct encrypted binary format
    const header = Buffer.alloc(HEADER_LENGTH);
    MAGIC_BYTES.copy(header, 0);
    header.writeUInt8(FORMAT_VERSION, 4);
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
   */
  async decryptToTempFile(
    encryptedData: Buffer,
    encryptionKeyRef: string,
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
    if (version !== FORMAT_VERSION) {
      throw new Error(`Unsupported encrypted document format version: ${version}`);
    }

    const iv = encryptedData.subarray(5, 5 + IV_LENGTH);
    const tag = encryptedData.subarray(5 + IV_LENGTH, HEADER_LENGTH);
    const ciphertext = encryptedData.subarray(HEADER_LENGTH);

    // 2. Unwrap DEK from KMS
    const dek = await this.kms.unwrapCombinedRef(encryptionKeyRef);

    // 3. Prepare private temporary file
    const tempDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'sda-dec-'));
    const tempFilePath = path.join(tempDir, `doc-${crypto.randomBytes(8).toString('hex')}.tmp`);

    const decipher = crypto.createDecipheriv('aes-256-gcm', dek, iv);
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
