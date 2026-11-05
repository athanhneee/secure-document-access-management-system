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
import { createMockConfig } from './helpers/crypto-kms-mocks.mjs';

test('HSM PKCS#11 — wraps 256-bit DEK using RFC 3394 / NIST SP 800-38F Key Wrap (40-byte payload)', async () => {
  const hsm = new HsmPkcs11KmsService(createMockConfig());
  const dek = crypto.randomBytes(32);

  const { wrappedDek, keyRef, combinedRef } = await hsm.wrapKey(dek);
  assert.equal(typeof wrappedDek, 'string');
  assert.equal(keyRef, 'hsm-pkcs11:slot-0:SDA-MASTER-KEK-v1');
  assert.ok(combinedRef.startsWith('hsm-pkcs11:slot-0:SDA-MASTER-KEK-v1:'));

  const rawBytes = Buffer.from(wrappedDek, 'base64url');
  assert.equal(rawBytes.length, 40, 'HSM CKM_AES_KEY_WRAP payload must be exactly 40 bytes');

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

  const localUnified = new UnifiedKmsService(createMockConfig({ KMS_PROVIDER: 'local' }));
  const localRes = await localUnified.wrapKey(dek);
  assert.ok(localRes.keyRef.startsWith('local-kms:'));

  const hsmUnified = new UnifiedKmsService(createMockConfig({ KMS_PROVIDER: 'hsm-pkcs11' }));
  const hsmRes = await hsmUnified.wrapKey(dek);
  assert.ok(hsmRes.keyRef.startsWith('hsm-pkcs11:'));

  const vaultUnified = new UnifiedKmsService(createMockConfig({ KMS_PROVIDER: 'vault' }));
  const vaultRes = await vaultUnified.wrapKey(dek);
  assert.ok(vaultRes.keyRef.startsWith('vault-kms:'));

  const awsUnified = new UnifiedKmsService(createMockConfig({ KMS_PROVIDER: 'aws-kms' }));
  const awsRes = await awsUnified.wrapKey(dek);
  assert.ok(awsRes.keyRef.startsWith('aws-kms:'));
});

test('Unified KMS — routes unwrap requests dynamically across local, HSM, Vault, and Cloud KMS', async () => {
  const dek = crypto.randomBytes(32);
  const unified = new UnifiedKmsService(createMockConfig());

  const localWrapped = await new LocalKmsService(createMockConfig()).wrapKey(dek);
  const hsmWrapped = await new HsmPkcs11KmsService(createMockConfig()).wrapKey(dek);
  const vaultWrapped = await new VaultTransitKmsService(createMockConfig()).wrapKey(dek);
  const cloudWrapped = await new CloudKmsService(createMockConfig()).wrapKey(dek);

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

  const legacyWrap = await new LocalKmsService(createMockConfig()).wrapKey(dek);
  assert.ok(legacyWrap.combinedRef.startsWith('local-kms:v1:'));

  const rotated = await unified.rotateKeyRef(legacyWrap.combinedRef, 'hsm-pkcs11');
  assert.ok(rotated.keyRef.startsWith('hsm-pkcs11:'));
  assert.ok(rotated.combinedRef.startsWith('hsm-pkcs11:slot-0:'));

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

  const decrypted = await encryption.decryptToTempFile(enc.encryptedBuffer, enc.dekReference);
  const readBack = fs.readFileSync(decrypted.tempFilePath);
  assert.deepEqual(readBack, plaintext);

  await decrypted.cleanup();
  assert.equal(fs.existsSync(decrypted.tempFilePath), false);
});
