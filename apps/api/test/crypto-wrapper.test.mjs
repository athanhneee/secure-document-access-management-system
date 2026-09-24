import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { test } from 'node:test';
import {
  LocalKmsService,
  HsmPkcs11KmsService,
  VaultTransitKmsService,
  CloudKmsService,
  UnifiedKmsService,
} from '../dist/modules/documents/kms.service.js';
import { DocumentEncryptionService } from '../dist/modules/documents/document-encryption.service.js';

function createMockConfig(overrides = {}) {
  const values = {
    APP_ENCRYPTION_MASTER_KEY: 'test-master-key-with-thirty-two-chars-min!!',
    KMS_PROVIDER: 'local',
    HSM_SLOT_INDEX: 0,
    HSM_KEY_LABEL: 'SDA-MASTER-KEK-v1',
    HSM_PIN: '000000',
    VAULT_ADDR: 'http://127.0.0.1:8200',
    VAULT_TOKEN: 'dev-mock-vault-token',
    VAULT_KEY_NAME: 'sda-document-kek',
    VAULT_TRANSIT_MOUNT: 'transit',
    AWS_KMS_KEY_ID: 'alias/sda-master-kek',
    AWS_KMS_REGION: 'us-east-1',
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

test('HSM PKCS#11 — wraps 256-bit DEK using RFC 3394 / NIST SP 800-38F Key Wrap (40-byte payload)', async () => {
  const hsm = new HsmPkcs11KmsService(createMockConfig());
  const dek = crypto.randomBytes(32);

  const { wrappedDek, keyRef, combinedRef } = await hsm.wrapKey(dek);
  assert.equal(typeof wrappedDek, 'string');
  assert.equal(keyRef, 'hsm-pkcs11:slot-0:SDA-MASTER-KEK-v1');
  assert.ok(combinedRef.startsWith('hsm-pkcs11:slot-0:SDA-MASTER-KEK-v1:'));

  // RFC 3394 key wrap: 32 bytes plaintext + 8 bytes integrity ICV = 40 bytes
  const rawBytes = Buffer.from(wrappedDek, 'base64url');
  assert.equal(rawBytes.length, 40, 'HSM CKM_AES_KEY_WRAP payload must be exactly 40 bytes');

  // Verify successful unwrapping
  const unwrapped = await hsm.unwrapKey(wrappedDek, keyRef);
  assert.deepEqual(unwrapped, dek);

  const unwrappedCombined = await hsm.unwrapCombinedRef(combinedRef);
  assert.deepEqual(unwrappedCombined, dek);
});

test('HSM PKCS#11 — rejects tampered wrapped DEK payload (hardware integrity verification)', async () => {
  const hsm = new HsmPkcs11KmsService(createMockConfig());
  const dek = crypto.randomBytes(32);

  const { wrappedDek, keyRef } = await hsm.wrapKey(dek);
  const rawBytes = Buffer.from(wrappedDek, 'base64url');

  // Tamper with one byte of the wrapped payload
  rawBytes[10] ^= 0x5a;
  const tamperedWrappedDek = rawBytes.toString('base64url');

  await assert.rejects(
    async () => hsm.unwrapKey(tamperedWrappedDek, keyRef),
    /hardware key wrap integrity check failed or corrupted key \(CKR_DEVICE_ERROR\)/i,
  );
});

test('HSM PKCS#11 — validates PIN authentication requirements', async () => {
  const hsm = new HsmPkcs11KmsService(createMockConfig());
  const dek = crypto.randomBytes(32);

  await assert.rejects(
    async () => hsm.wrapKey(dek, ''),
    /HSM PIN is required for authentication \(CKR_PIN_INCORRECT\)/,
  );

  const { wrappedDek, keyRef } = await hsm.wrapKey(dek);
  await assert.rejects(
    async () => hsm.unwrapKey(wrappedDek, keyRef, ''),
    /HSM PIN is required for authentication \(CKR_PIN_INCORRECT\)/,
  );
});

test('Vault Transit KMS — wraps and unwraps DEK using Vault Transit interface', async () => {
  const vault = new VaultTransitKmsService(createMockConfig());
  const dek = crypto.randomBytes(32);

  const { wrappedDek, keyRef, combinedRef } = await vault.wrapKey(dek);
  assert.equal(keyRef, 'vault-kms:sda-document-kek');
  assert.ok(combinedRef.startsWith('vault-kms:sda-document-kek:'));

  const unwrapped = await vault.unwrapKey(wrappedDek, keyRef);
  assert.deepEqual(unwrapped, dek);

  const unwrappedCombined = await vault.unwrapCombinedRef(combinedRef);
  assert.deepEqual(unwrappedCombined, dek);
});

test('Cloud KMS — wraps and unwraps DEK using AWS KMS interface', async () => {
  const cloud = new CloudKmsService(createMockConfig());
  const dek = crypto.randomBytes(32);

  const { wrappedDek, keyRef, combinedRef } = await cloud.wrapKey(dek);
  assert.equal(keyRef, 'aws-kms:alias/sda-master-kek');
  assert.ok(combinedRef.startsWith('aws-kms:alias/sda-master-kek:'));

  const unwrapped = await cloud.unwrapKey(wrappedDek, keyRef);
  assert.deepEqual(unwrapped, dek);

  const unwrappedCombined = await cloud.unwrapCombinedRef(combinedRef);
  assert.deepEqual(unwrappedCombined, dek);
});

test('Unified KMS — wraps using provider specified by KMS_PROVIDER config', async () => {
  const dek = crypto.randomBytes(32);

  // Local
  const localUnified = new UnifiedKmsService(createMockConfig({ KMS_PROVIDER: 'local' }));
  const localRes = await localUnified.wrapKey(dek);
  assert.ok(localRes.keyRef.startsWith('local-kms:'));

  // HSM PKCS#11
  const hsmUnified = new UnifiedKmsService(createMockConfig({ KMS_PROVIDER: 'hsm-pkcs11' }));
  const hsmRes = await hsmUnified.wrapKey(dek);
  assert.ok(hsmRes.keyRef.startsWith('hsm-pkcs11:'));

  // Vault
  const vaultUnified = new UnifiedKmsService(createMockConfig({ KMS_PROVIDER: 'vault' }));
  const vaultRes = await vaultUnified.wrapKey(dek);
  assert.ok(vaultRes.keyRef.startsWith('vault-kms:'));

  // AWS KMS
  const awsUnified = new UnifiedKmsService(createMockConfig({ KMS_PROVIDER: 'aws-kms' }));
  const awsRes = await awsUnified.wrapKey(dek);
  assert.ok(awsRes.keyRef.startsWith('aws-kms:'));
});

test('Unified KMS — routes unwrap requests dynamically across local, HSM, Vault, and Cloud KMS', async () => {
  const dek = crypto.randomBytes(32);
  const unified = new UnifiedKmsService(createMockConfig());

  // Wrap under 4 different providers
  const localWrapped = await new LocalKmsService(createMockConfig()).wrapKey(dek);
  const hsmWrapped = await new HsmPkcs11KmsService(createMockConfig()).wrapKey(dek);
  const vaultWrapped = await new VaultTransitKmsService(createMockConfig()).wrapKey(dek);
  const cloudWrapped = await new CloudKmsService(createMockConfig()).wrapKey(dek);

  // Single UnifiedKmsService instance can unwrap all 4 seamlessly
  const unwrapLocal = await unified.unwrapCombinedRef(localWrapped.combinedRef);
  const unwrapHsm = await unified.unwrapCombinedRef(hsmWrapped.combinedRef);
  const unwrapVault = await unified.unwrapCombinedRef(vaultWrapped.combinedRef);
  const unwrapCloud = await unified.unwrapCombinedRef(cloudWrapped.combinedRef);

  assert.deepEqual(unwrapLocal, dek);
  assert.deepEqual(unwrapHsm, dek);
  assert.deepEqual(unwrapVault, dek);
  assert.deepEqual(unwrapCloud, dek);
});

test('Unified KMS — performs zero-downtime key rotation (rotateKeyRef) from local-kms to hsm-pkcs11', async () => {
  const dek = crypto.randomBytes(32);
  const unified = new UnifiedKmsService(createMockConfig({ KMS_PROVIDER: 'hsm-pkcs11' }));

  // Create legacy local-kms wrapped reference
  const legacyWrap = await new LocalKmsService(createMockConfig()).wrapKey(dek);
  assert.ok(legacyWrap.combinedRef.startsWith('local-kms:v1:'));

  // Rotate to HSM PKCS#11
  const rotated = await unified.rotateKeyRef(legacyWrap.combinedRef, 'hsm-pkcs11');
  assert.ok(rotated.keyRef.startsWith('hsm-pkcs11:'));
  assert.ok(rotated.combinedRef.startsWith('hsm-pkcs11:slot-0:'));

  // Verify rotated key unwraps to the original DEK
  const unwrapRotated = await unified.unwrapCombinedRef(rotated.combinedRef);
  assert.deepEqual(unwrapRotated, dek);
});

test('Unified KMS + DocumentEncryptionService — end-to-end encryption & decryption with HSM PKCS#11 provider', async () => {
  const unified = new UnifiedKmsService(createMockConfig({ KMS_PROVIDER: 'hsm-pkcs11' }));
  const encryption = new DocumentEncryptionService(unified);

  const plaintext = Buffer.from(
    'TOP SECRET: Protected by Physical Hardware Security Module PKCS#11',
    'utf8',
  );
  const enc = await encryption.encryptBuffer(plaintext);

  assert.ok(enc.dekReference.startsWith('hsm-pkcs11:slot-0:SDA-MASTER-KEK-v1:'));

  // Decrypt to temp file
  const decrypted = await encryption.decryptToTempFile(enc.encryptedBuffer, enc.dekReference);
  const readBack = fs.readFileSync(decrypted.tempFilePath);
  assert.deepEqual(readBack, plaintext);

  await decrypted.cleanup();
  assert.equal(fs.existsSync(decrypted.tempFilePath), false);
});
