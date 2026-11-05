import assert from 'node:assert/strict';
import { test } from 'node:test';
import crypto from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { ObjectStorageService } from '../dist/modules/documents/object-storage.service.js';
import { LocalKmsService } from '../dist/modules/documents/kms.service.js';
import { DocumentEncryptionService } from '../dist/modules/documents/document-encryption.service.js';
import { OrphanCompensationService } from '../dist/modules/documents/orphan-compensation.service.js';
import { createMockConfig } from './helpers/document-ingestion-mocks.mjs';

test('LocalKmsService: wraps and unwraps 256-bit DEK using AES-256-GCM and KEK without storing KEK in DB', async () => {
  const config = createMockConfig();
  const kms = new LocalKmsService(config);

  const rawDek = crypto.randomBytes(32);

  const wrapResult = await kms.wrapKey(rawDek);
  assert.equal(wrapResult.keyRef, 'local-kms:v1');
  assert.ok(wrapResult.wrappedDek.length > 40);
  assert.ok(wrapResult.combinedRef.startsWith('local-kms:v1:'));

  const unwrapped = await kms.unwrapCombinedRef(wrapResult.combinedRef);
  assert.equal(unwrapped.length, 32);
  assert.deepEqual(unwrapped, rawDek);

  const tamperedBytes = Buffer.from(wrapResult.wrappedDek, 'base64url');
  tamperedBytes[tamperedBytes.length - 1] ^= 0xff;
  const tamperedWrapped = tamperedBytes.toString('base64url');

  await assert.rejects(async () => {
    await kms.unwrapKey(tamperedWrapped, 'local-kms:v1');
  }, /authentication tag mismatch|corrupted/i);
});

test('DocumentEncryptionService: AES-256-GCM envelope encryption with 33-byte header and tag authentication', async () => {
  const config = createMockConfig();
  const kms = new LocalKmsService(config);
  const encryption = new DocumentEncryptionService(kms);

  const plaintext = Buffer.from('TOP SECRET: Strategic Defence Operational Blueprint 2026');
  const originalSha256 = crypto.createHash('sha256').update(plaintext).digest('hex');

  const encrypted = await encryption.encryptBuffer(plaintext);
  assert.equal(encrypted.sha256Hash, originalSha256);
  assert.equal(encrypted.encryptedBuffer.length, plaintext.length + 33);

  assert.equal(encrypted.encryptedBuffer.subarray(0, 4).toString('utf8'), 'SDAE');
  assert.equal(encrypted.encryptedBuffer.readUInt8(4), 0x01);

  const decrypted = await encryption.decryptToTempFile(
    encrypted.encryptedBuffer,
    encrypted.dekReference,
  );
  try {
    assert.equal(decrypted.sha256Hash, originalSha256);
    const readBack = await fsp.readFile(decrypted.tempFilePath);
    assert.deepEqual(readBack, plaintext);
  } finally {
    await decrypted.cleanup();
  }
  assert.equal(fs.existsSync(decrypted.tempFilePath), false);

  const encrypted2 = await encryption.encryptBuffer(plaintext);
  assert.notDeepEqual(encrypted.encryptedBuffer, encrypted2.encryptedBuffer);
  assert.notEqual(encrypted.dekReference, encrypted2.dekReference);

  const tampered = Buffer.from(encrypted.encryptedBuffer);
  tampered[34] ^= 0x01;

  await assert.rejects(async () => {
    await encryption.decryptToTempFile(tampered, encrypted.dekReference);
  }, /Authentication tag verification failed or ciphertext tampered/i);
});

test('OrphanCompensationService: rolls back tracked storage objects and deletes temporary files', async () => {
  const config = createMockConfig();
  const storage = new ObjectStorageService(config);
  const compensation = new OrphanCompensationService(storage);

  const session = compensation.createSession();

  const tempDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'sda-test-'));
  const tempFile = path.join(tempDir, 'test-file.tmp');
  await fsp.writeFile(tempFile, 'data');
  session.tempFilesToDelete.push(tempFile);
  session.tempFilesToDelete.push(tempDir);

  await storage.putObject(storage.quarantineBucket, 'quarantine/orphan-test', Buffer.from('data'));
  session.storageKeysToDelete.push({
    bucket: storage.quarantineBucket,
    key: 'quarantine/orphan-test',
  });

  assert.equal(
    await storage.objectExists(storage.quarantineBucket, 'quarantine/orphan-test'),
    true,
  );
  assert.equal(fs.existsSync(tempFile), true);

  await compensation.compensate(session);

  assert.equal(
    await storage.objectExists(storage.quarantineBucket, 'quarantine/orphan-test'),
    false,
  );
  assert.equal(fs.existsSync(tempFile), false);
  assert.equal(fs.existsSync(tempDir), false);
});
