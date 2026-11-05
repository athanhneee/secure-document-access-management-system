/**
 * Module: AES-256-GCM Authenticated Envelope Key Wrap Primitives
 * Algorithm: Wraps and unwraps 256-bit Data Encryption Keys (DEKs) using NIST SP 800-38D AES-256-GCM
 *   with fresh 96-bit CSPRNG IVs and 128-bit authentication tags (`[IV (12B) || Tag (16B) || Ciphertext (32B)]`).
 */
import crypto from 'node:crypto';
import type { KmsWrapResult } from './kms.types.js';

/**
 * Algorithm: AES-256-GCM Envelope DEK Wrapping
 * Encrypts a 32-byte DEK under a 256-bit KEK with a random 12-byte IV and serializes `IV || AuthTag || Ciphertext` as base64url.
 */
export function wrapDekWithAes256Gcm(
  plaintextDek: Buffer,
  kek: Buffer,
  keyRef: string,
): KmsWrapResult {
  if (plaintextDek.length !== 32) {
    throw new Error('DEK must be exactly 32 bytes (256 bits).');
  }

  // CONFLICT-RESOLVED: Consolidated identical 60-byte [IV(12B) || Tag(16B) || Ciphertext(32B)] AES-256-GCM
  // DEK wrapping logic previously duplicated across LocalKmsService, VaultTransitKmsService, and CloudKmsService.
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', kek, iv);
  const encryptedDek = Buffer.concat([cipher.update(plaintextDek), cipher.final()]);
  const tag = cipher.getAuthTag();

  const wrappedDek = Buffer.concat([iv, tag, encryptedDek]).toString('base64url');
  return {
    wrappedDek,
    keyRef,
    combinedRef: `${keyRef}:${wrappedDek}`,
  };
}

/**
 * Algorithm: AES-256-GCM Authenticated Envelope DEK Unwrapping
 * Verifies the 128-bit GCM authentication tag before releasing the 32-byte plaintext DEK.
 */
export function unwrapDekWithAes256Gcm(
  wrappedDek: string,
  kek: Buffer,
  authMismatchMessage: string,
): Buffer {
  const payload = Buffer.from(wrappedDek, 'base64url');
  if (payload.length < 28) {
    throw new Error('Invalid wrapped DEK payload length.');
  }

  const iv = payload.subarray(0, 12);
  const tag = payload.subarray(12, 28);
  const ciphertext = payload.subarray(28);

  const decipher = crypto.createDecipheriv('aes-256-gcm', kek, iv);
  decipher.setAuthTag(tag);

  try {
    const decryptedDek = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    if (decryptedDek.length !== 32) {
      throw new Error('Decrypted DEK length is invalid.');
    }
    return decryptedDek;
  } catch {
    throw new Error(authMismatchMessage);
  }
}
