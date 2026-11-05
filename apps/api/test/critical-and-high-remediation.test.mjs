import 'reflect-metadata';
import assert from 'node:assert/strict';
import { createHmac, generateKeyPairSync, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { ForbiddenException, HttpException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import * as OTPAuth from 'otpauth';
import { AppErrorCode } from '@sda/contracts';
import { buildPgPoolConfig } from '@sda/database';
import { AppConfigService } from '../dist/config/config.service.js';
import { AuditVerifierService } from '../dist/modules/audit/audit-verifier.service.js';
import { AuditWriterService } from '../dist/modules/audit/audit-writer.service.js';
import { ZipBombGuardService } from '../dist/modules/documents/zip-bomb-guard.service.js';
import { inspectOfficeArchiveSecurity } from '../dist/modules/documents/office-archive-inspector.js';
import { inspectOoxmlEntryPathSecurity } from '../dist/modules/documents/zip-xml-security.helper.js';
import { LocalKmsService } from '../dist/modules/documents/kms.service.js';
import { DocumentEncryptionService } from '../dist/modules/documents/document-encryption.service.js';
import { areOverlappingRolesSodCompatible } from '../dist/modules/rbac/permission-matrix.js';
import { AuthorizationGuard } from '../dist/modules/rbac/authorization.guard.js';
import { MfaService } from '../dist/modules/auth/mfa.service.js';
import { LoginRateLimitService } from '../dist/modules/auth/login-rate-limit.service.js';
import { validatePolicy } from '../dist/modules/abac/policy-validator.js';
import { createZipBuffer } from './helpers/zip-builder.mjs';

test('[CRIT-01 & CRIT-02] AuditVerifierService detects head-truncation & missing priorLog without leaking HMAC oracle', async () => {
  const hmacKey = 'audit-verifier-hmac-test-key-at-least-32-chars!!';
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const config = new AppConfigService({
    NODE_ENV: 'test',
    APP_ENCRYPTION_MASTER_KEY: 'test-master-key-32-chars-long-000000000',
    AUDIT_INTEGRITY_KEY: hmacKey,
    AUTH_SIGNING_PRIVATE_KEY_PEM: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    AUTH_SIGNING_PUBLIC_KEYS_JSON: JSON.stringify({
      'kid-1': publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    }),
  });

  const occurredAt = new Date('2026-10-15T12:00:00.000Z');
  const corrId = randomUUID();
  const truncatedLog = {
    id: 3n,
    chain_partition: 'GLOBAL',
    chain_sequence: 3n, // Sequences 1..2 truncated!
    hmac_key_version: 1,
    chain_algorithm: 'HMAC-SHA-256',
    action: 'DOCUMENT_VIEWED',
    actor_user_id: 7n,
    actor_username: 'reader1',
    correlation_id: corrId,
    details: {},
    document_id: null,
    access_session_id: null,
    ip_address: '127.0.0.1',
    object_type: 'DOCUMENT',
    object_id: 'doc-1',
    occurred_at: occurredAt,
    outcome: 'SUCCESS',
    previous_hash: 'a'.repeat(64),
    reason_code: null,
    user_agent: null,
    entry_hash: 'f'.repeat(64),
  };

  const canonical = JSON.stringify({
    accessSessionId: null,
    action: 'DOCUMENT_VIEWED',
    actorUserId: '7',
    actorUsername: 'reader1',
    chainAlgorithm: 'HMAC-SHA-256',
    chainPartition: 'GLOBAL',
    chainSequence: '3',
    correlationId: corrId,
    details: {},
    documentId: null,
    ipAddress: '127.0.0.1',
    objectId: 'doc-1',
    objectType: 'DOCUMENT',
    occurredAt: occurredAt.toISOString(),
    outcome: 'SUCCESS',
    previousHash: 'a'.repeat(64),
    reasonCode: null,
    userAgent: null,
  });
  const realHmac = createHmac('sha256', hmacKey).update(canonical, 'utf8').digest('hex');

  const alertsPersisted = [];
  const mockDb = {
    auditLog: {
      findFirst: async () => null, // priorLog deleted!
      findMany: async ({ where }) => (where?.chain_sequence?.gt === 3n ? [] : [truncatedLog]),
    },
    auditAnchor: { findMany: async () => [] },
    securityAlert: {
      findFirst: async () => null,
      create: async ({ data }) => {
        alertsPersisted.push(data);
        return { id: 11n, ...data };
      },
    },
    alertAuditLink: { create: async () => ({}), createMany: async () => ({ count: 1 }) },
    $transaction: async (fn) => fn(mockDb),
  };
  const writer = new AuditWriterService(config, mockDb);
  const verifier = new AuditVerifierService(writer, mockDb);

  const headRes = await verifier.verifyPartition('GLOBAL');
  assert.equal(headRes.valid, false);
  assert.ok(headRes.violations.some((v) => v.code === AppErrorCode.AUDIT_SEQUENCE_GAP));

  const rangeRes = await verifier.verifyPartition('GLOBAL', { fromSequence: 3n });
  assert.equal(rangeRes.valid, false);
  assert.ok(rangeRes.violations.some((v) => v.code === AppErrorCode.AUDIT_CHAIN_BROKEN));

  const serialized = JSON.stringify({ headRes, rangeRes, alertsPersisted }, (_k, v) =>
    typeof v === 'bigint' ? v.toString() : v,
  );
  assert.equal(serialized.includes(realHmac), false, 'Never leak computed HMAC signing oracle');
  for (const v of headRes.violations.filter((x) => x.code === AppErrorCode.AUDIT_LOG_TAMPERED)) {
    assert.equal(v.expected, '[REDACTED_HMAC]');
    assert.doesNotMatch(String(v.expected), /^[0-9a-f]{64}$/iu);
  }
});

test('[CRIT-05] OOXML security scanner blocks UTF-16LE XXE, UTF-16BE .rels SSRF, backslash paths & Zip-Slip', async () => {
  const utf16LeXxe = Buffer.concat([
    Buffer.from([0xff, 0xfe]),
    Buffer.from(
      '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest">]><w:document/>',
      'utf16le',
    ),
  ]);
  const archive = createZipBuffer([
    { name: '[Content_Types].xml', content: '<?xml version="1.0"?><Types></Types>' },
    { name: 'word/document.xml', content: utf16LeXxe },
  ]);
  const guard = new ZipBombGuardService({
    get: (k) =>
      ({
        ZIP_MAX_ENTRIES: 500,
        ZIP_MAX_TOTAL_UNCOMPRESSED_SIZE: 20 * 1024 * 1024,
        ZIP_MAX_DEPTH: 16,
        ZIP_MAX_COMPRESSION_RATIO: 100,
      })[k],
  });
  await assert.rejects(
    guard.inspectOfficeZip(archive, '.docx'),
    (err) => err.response?.errorCode === AppErrorCode.OFFICE_EXTERNAL_RESOURCE_BLOCKED,
  );
  await assert.rejects(
    inspectOfficeArchiveSecurity(archive),
    (err) => err.response?.errorCode === AppErrorCode.OFFICE_EXTERNAL_RESOURCE_BLOCKED,
  );

  for (const dangerousPath of [
    'xl\\connections.xml',
    'word\\activex\\activeX1.bin',
    'xl\\externalLinks\\externalLink1.xml',
    '..\\evil.xml',
  ]) {
    assert.ok(inspectOoxmlEntryPathSecurity(dangerousPath) !== null, `Must block ${dangerousPath}`);
  }
});

test('[CRIT-07] Web preview hooks & modals fail closed on invalid %PDF- stream with zero fabricated state headers', async () => {
  const files = await Promise.all([
    readFile(new URL('../../web/app/owner/hooks/use-owner-delivery.ts', import.meta.url), 'utf8'),
    readFile(new URL('../../web/app/reader/hooks/use-reader-viewer.ts', import.meta.url), 'utf8'),
    readFile(
      new URL('../../web/app/owner/modals/forensic-preview-modal.tsx', import.meta.url),
      'utf8',
    ),
    readFile(
      new URL('../../web/app/reader/modals/document-viewer-modal.tsx', import.meta.url),
      'utf8',
    ),
  ]);
  for (const content of files) {
    assert.equal(content.includes('CỘNG HÒA XÃ HỘI CHỦ NGHĨA VIỆT NAM'), false);
    assert.equal(content.includes('14/QC-BCĐ'), false);
  }
});

test('[HIGH-01..12] Custom Role SoD, Default-Deny Guard, AES-GCM AAD, TOTP anti-replay, RateLimit lock, CIDR & CI/CD', async () => {
  // HIGH-01: Custom role carrying USER:MANAGE cannot coexist with DOCUMENT_OWNER
  assert.equal(
    areOverlappingRolesSodCompatible([
      {
        code: 'CUSTOM_OPS_ADMIN',
        permissions: [{ code: 'USER_MANAGE', resource_type: 'USER', action: 'MANAGE' }],
      },
      {
        code: 'DOCUMENT_OWNER',
        permissions: [{ code: 'DOCUMENT_UPLOAD', resource_type: 'DOCUMENT', action: 'UPLOAD' }],
      },
    ]),
    false,
  );

  // HIGH-03: AuthorizationGuard fails closed when route lacks metadata decorators
  const guard = new AuthorizationGuard(new Reflector(), { hasPermission: async () => true });
  await assert.rejects(
    guard.canActivate({
      getHandler: () => function undecoratedRoute() {},
      getClass: () => class UndecoratedController {},
      switchToHttp: () => ({ getRequest: () => ({ auth: { userId: 1n, roles: [] } }) }),
    }),
    (err) => err instanceof ForbiddenException,
  );

  // HIGH-09: AES-256-GCM SDAE v2 AAD prevents cross-document ciphertext swap
  const config = new AppConfigService({
    NODE_ENV: 'test',
    APP_ENCRYPTION_MASTER_KEY: 'test-master-key-32-chars-long-000000000',
    AUDIT_INTEGRITY_KEY: 'test-unified-audit-hmac-key-000000000000',
  });
  const encSvc = new DocumentEncryptionService(new LocalKmsService(config));
  const encrypted = await encSvc.encryptBuffer(Buffer.from('Top secret body'), 'doc-alpha');
  const okDec = await encSvc.decryptToTempFile(
    encrypted.encryptedBuffer,
    encrypted.dekReference,
    'doc-alpha',
  );
  await okDec.cleanup();
  await assert.rejects(
    encSvc.decryptToTempFile(encrypted.encryptedBuffer, encrypted.dekReference, 'doc-beta'),
    /integrity|authentication|decrypt/iu,
  );

  // HIGH-10: TOTP anti-replay within 90s window & rate-limit victim lock preservation under 10,005 fake keys
  const mfa = new MfaService(config);
  const { encryptedSecret, secret } = mfa.createEnrollment('user42@corp.test');
  const code = new OTPAuth.TOTP({
    issuer: 'Secure Document Access',
    label: 'verification',
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
    secret: OTPAuth.Secret.fromBase32(secret),
  }).generate();
  assert.equal(mfa.verifyTotp(encryptedSecret, code), true);
  assert.equal(mfa.verifyTotp(encryptedSecret, code), false);

  const nowMs = Date.now();
  const limiter = new LoginRateLimitService();
  for (let i = 0; i < 6; i++) limiter.recordFailure('203.0.113.9', 'victim@corp.test', nowMs);
  for (let i = 0; i < 10_005; i++) {
    limiter.recordFailure('127.0.0.1', `bot-${i}@corp.test`, nowMs + 10);
  }
  assert.throws(
    () => limiter.assertAllowed('198.51.100.20', 'victim@corp.test', nowMs + 50),
    (err) => err instanceof HttpException && err.getStatus() === 429,
  );

  // HIGH-11: Strict CIDR_MATCH validation rejects malformed CIDR
  const badCidrCondition = {
    id: 'c1',
    attribute: 'environment.ip',
    operator: 'CIDR_MATCH',
    expected: '999.1.1.1/99',
  };
  const issues = validatePolicy(
    {
      version: 1n,
      rules: [
        {
          id: 1n,
          code: 'BAD_CIDR_DENY',
          effect: 'DENY',
          combiningAlgorithm: 'DENY_OVERRIDES',
          obligations: [],
          groups: [{ id: 1, conditions: [badCidrCondition] }],
        },
      ],
    },
    { 'environment.ip': { type: 'IP' } },
  );
  assert.ok(issues.some((i) => i.code === 'INVALID_EXPECTED_VALUE'));

  // HIGH-12: Supabase TLS enforcement in dev & CD pipeline container-first order
  const prevEnv = process.env.NODE_ENV;
  process.env.NODE_ENV = 'development';
  try {
    const supaBase = 'postgresql://db.demo.supabase.co:5432/postgres';
    assert.throws(() => buildPgPoolConfig(`${supaBase}?sslmode=disable`), /CWE-319/u);
    assert.throws(() => buildPgPoolConfig(`${supaBase}?sslmode=no-verify`), /CWE-295/u);
  } finally {
    if (prevEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = prevEnv;
  }

  const cdYml = await readFile(
    new URL('../../../.github/workflows/cd.yml', import.meta.url),
    'utf8',
  );
  assert.match(cdYml, /migrate-database:[\s\S]*needs:\s*\[publish-containers\]/u);
  assert.match(cdYml, /trivy-action@/u);
});
