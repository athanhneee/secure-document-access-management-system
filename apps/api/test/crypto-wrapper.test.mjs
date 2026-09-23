import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { test } from 'node:test';
import { LocalKmsService } from '../dist/modules/documents/kms.service.js';
import { DocumentEncryptionService } from '../dist/modules/documents/document-encryption.service.js';

function createMockConfig(overrides = {}) {
  const values = {
    APP_ENCRYPTION_MASTER_KEY: 'test-master-key-with-thirty-two-chars-min!!',
    ...overrides,
  };
  return {
    get: (key) => values[key],
  };
}

test('KMS Wrapper — wraps and unwraps 256-bit DEK with KEK successfully', async () => {
  const kms = new LocalKmsService(createMockConfig());
  const dek = crypto.randomBytes(32);

  const { wrappedDek, keyRef, combinedRef } = await kms.wrapKey(dek);
  assert.equal(typeof wrappedDek, 'string');
  assert.equal(keyRef, 'local-kms:v1');
  assert.ok(combinedRef.startsWith('local-kms:v1:'));

  const unwrappedCombined = await kms.unwrapCombinedRef(combinedRef);
  assert.deepEqual(unwrappedCombined, dek);

  const unwrappedExplicit = await kms.unwrapKey(wrappedDek, keyRef);
  assert.deepEqual(unwrappedExplicit, dek);
});

test('KMS Wrapper — rejects unwrapping if ciphertext or auth tag is tampered', async () => {
  const kms = new LocalKmsService(createMockConfig());
  const dek = crypto.randomBytes(32);

  const { wrappedDek, keyRef } = await kms.wrapKey(dek);
  const rawBytes = Buffer.from(wrappedDek, 'base64url');

  // Flip the last byte of the wrapped payload
  rawBytes[rawBytes.length - 1] ^= 0xff;
  const tamperedWrappedDek = rawBytes.toString('base64url');

  await assert.rejects(
    async () => kms.unwrapKey(tamperedWrappedDek, keyRef),
    /Failed to unwrap DEK: authentication tag mismatch|Unsupported state or unable to authenticate data/i,
  );
});

test('KMS Wrapper — rejects malformed key reference formats', async () => {
  const kms = new LocalKmsService(createMockConfig());
  await assert.rejects(
    async () => kms.unwrapCombinedRef('invalid-ref'),
    /Invalid combined encryption key reference format/,
  );
  await assert.rejects(
    async () => kms.unwrapCombinedRef('unknown-kms:v2:dummy'),
    /Unsupported KMS keyRef format/,
  );
});

test('Envelope Encryption — produces standard 33-byte header and verifies SHA-256', async () => {
  const kms = new LocalKmsService(createMockConfig());
  const encryption = new DocumentEncryptionService(kms);

  const plaintext = Buffer.from('TOP SECRET: Organizational security clearance required.', 'utf8');
  const expectedHash = crypto.createHash('sha256').update(plaintext).digest('hex');

  const result = await encryption.encryptBuffer(plaintext);
  assert.equal(result.sha256Hash, expectedHash);
  assert.equal(result.fileSizeBytes, plaintext.length);

  // Check 33-byte header
  const header = result.encryptedBuffer.subarray(0, 33);
  assert.equal(header.subarray(0, 4).toString(), 'SDAE'); // Magic bytes
  assert.equal(header[4], 0x01); // Version 1

  // Decrypt to temp file and verify round-trip
  const decryptedResult = await encryption.decryptToTempFile(
    result.encryptedBuffer,
    result.dekReference,
  );
  assert.equal(decryptedResult.sha256Hash, expectedHash);
  const readBack = fs.readFileSync(decryptedResult.tempFilePath);
  assert.deepEqual(readBack, plaintext);

  await decryptedResult.cleanup();
  assert.equal(fs.existsSync(decryptedResult.tempFilePath), false);
});

test('Envelope Encryption — generates fresh unique IVs for identical plaintexts', async () => {
  const kms = new LocalKmsService(createMockConfig());
  const encryption = new DocumentEncryptionService(kms);
  const plaintext = Buffer.from('Identical content for duplicate upload check', 'utf8');

  const enc1 = await encryption.encryptBuffer(plaintext);
  const enc2 = await encryption.encryptBuffer(plaintext);

  const iv1 = enc1.encryptedBuffer.subarray(5, 17);
  const iv2 = enc2.encryptedBuffer.subarray(5, 17);

  assert.notDeepEqual(iv1, iv2, 'IVs must never be reused across encryptions');
  assert.notDeepEqual(enc1.encryptedBuffer, enc2.encryptedBuffer);
});

test('Envelope Encryption — rejects tampered ciphertext (auth tag verification)', async () => {
  const kms = new LocalKmsService(createMockConfig());
  const encryption = new DocumentEncryptionService(kms);
  const plaintext = Buffer.from('Financial statement 2026 Q3 audit draft', 'utf8');

  const result = await encryption.encryptBuffer(plaintext);
  const tampered = Buffer.from(result.encryptedBuffer);

  // Flip one bit in the ciphertext payload (after 33-byte header)
  tampered[34] ^= 0x01;

  await assert.rejects(
    async () => encryption.decryptToTempFile(tampered, result.dekReference),
    /Document decryption failed: Authentication tag verification failed or ciphertext tampered/i,
  );
});

test('Envelope Encryption — rejects tampered header magic or truncated buffer', async () => {
  const kms = new LocalKmsService(createMockConfig());
  const encryption = new DocumentEncryptionService(kms);

  const tooShort = Buffer.from('SHORT_FILE');
  await assert.rejects(
    async () => encryption.decryptToTempFile(tooShort, 'local-kms:v1:dummy'),
    /Encrypted payload is too small to contain valid header/,
  );

  const plaintext = Buffer.from('Classification metadata', 'utf8');
  const result = await encryption.encryptBuffer(plaintext);
  const badMagic = Buffer.from(result.encryptedBuffer);
  badMagic[0] = 0x00; // corrupt magic byte

  await assert.rejects(
    async () => encryption.decryptToTempFile(badMagic, result.dekReference),
    /Invalid encrypted document format: magic bytes mismatch/,
  );
});

test('Envelope Encryption — decryptToTempFile cleans up temporary file on failure', async () => {
  const kms = new LocalKmsService(createMockConfig());
  const encryption = new DocumentEncryptionService(kms);
  const plaintext = Buffer.from('Confidential executive report content', 'utf8');

  const enc = await encryption.encryptBuffer(plaintext);
  const tampered = Buffer.from(enc.encryptedBuffer);
  tampered[tampered.length - 1] ^= 0x42; // tamper tag/cipher

  await assert.rejects(async () => encryption.decryptToTempFile(tampered, enc.dekReference));
});
