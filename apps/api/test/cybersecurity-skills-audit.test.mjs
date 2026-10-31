import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import zlib from 'node:zlib';
import { BadRequestException, ForbiddenException, NotFoundException } from '@nestjs/common';
import { PDFDocument, StandardFonts } from 'pdf-lib';

process.env.STORAGE_MOCK = 'true';
process.env.NODE_ENV = 'test';
process.env.DATABASE_URL = 'postgresql://localhost:5432/secure_docs?schema=public';
process.env.APP_ENCRYPTION_MASTER_KEY = 'test-master-key-32-chars-long-000000000';

import { AppConfigService } from '../dist/config/config.service.js';
import { AuthService } from '../dist/modules/auth/auth.service.js';
import { MfaService } from '../dist/modules/auth/mfa.service.js';
import { WebAuthnService } from '../dist/modules/auth/webauthn.service.js';
import { AccessGrantsService } from '../dist/modules/access-grants/access-grants.service.js';
import { DocumentsService } from '../dist/modules/documents/documents.service.js';
import { ZipBombGuardService } from '../dist/modules/documents/zip-bomb-guard.service.js';
import { WatermarkEngineService } from '../dist/modules/watermarks/watermark-engine.service.js';
import { WatermarksService } from '../dist/modules/watermarks/watermarks.service.js';
import { appendChainedAuditLog } from '../dist/modules/audit/audit-chain-helper.js';
import { AuditVerifierService } from '../dist/modules/audit/audit-verifier.service.js';
import { evaluatePolicy } from '../dist/modules/abac/policy-engine.js';
import { sanitizeCsvCell } from '../dist/modules/reports/csv-formula-sanitizer.js';

function createTestConfig(overrides = {}) {
  return new AppConfigService({
    NODE_ENV: 'test',
    APP_ENCRYPTION_MASTER_KEY: 'test-master-key-32-chars-long-000000000',
    AUDIT_INTEGRITY_KEY: 'test-unified-audit-hmac-key-000000000000',
    AUTH_ACCESS_TTL_SECONDS: 900,
    AUTH_REFRESH_TTL_SECONDS: 86400,
    AUTH_RESET_TTL_SECONDS: 1800,
    GRANT_MAX_DURATION_DAYS: 90,
    ZIP_MAX_TOTAL_UNCOMPRESSED_SIZE: 1_048_576,
    ZIP_MAX_ENTRIES: 50,
    ZIP_MAX_DEPTH: 5,
    ZIP_MAX_COMPRESSION_RATIO: 20,
    ...overrides,
  });
}

function createZipBuffer(entries, { spoofUncompressedZero = false } = {}) {
  const localHeaders = [];
  const centralHeaders = [];
  let offset = 0;

  for (const entry of entries) {
    const nameBuf = Buffer.from(entry.name, 'utf8');
    const content = Buffer.isBuffer(entry.content)
      ? entry.content
      : Buffer.from(entry.content, 'utf8');
    const crc = zlib.crc32(content);
    const declaredUncompressed = spoofUncompressedZero ? 1 : content.length;
    const compressedData = zlib.deflateRawSync(content);
    const compressedSize = compressedData.length;

    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0);
    lh.writeUInt16LE(20, 4);
    lh.writeUInt16LE(0, 6);
    lh.writeUInt16LE(8, 8);
    lh.writeUInt16LE(0, 10);
    lh.writeUInt16LE(0, 12);
    lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(compressedSize, 18);
    lh.writeUInt32LE(declaredUncompressed, 22);
    lh.writeUInt16LE(nameBuf.length, 26);
    lh.writeUInt16LE(0, 28);
    localHeaders.push(lh, nameBuf, compressedData);

    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0);
    ch.writeUInt16LE(20, 4);
    ch.writeUInt16LE(20, 6);
    ch.writeUInt16LE(0, 8);
    ch.writeUInt16LE(8, 10);
    ch.writeUInt16LE(0, 12);
    ch.writeUInt16LE(0, 14);
    ch.writeUInt32LE(crc, 16);
    ch.writeUInt32LE(compressedSize, 20);
    ch.writeUInt32LE(declaredUncompressed, 24);
    ch.writeUInt16LE(nameBuf.length, 28);
    ch.writeUInt16LE(0, 30);
    ch.writeUInt16LE(0, 32);
    ch.writeUInt16LE(0, 34);
    ch.writeUInt16LE(0, 36);
    ch.writeUInt32LE(0, 38);
    ch.writeUInt32LE(offset, 42);

    centralHeaders.push(ch, nameBuf);
    offset += 30 + nameBuf.length + compressedSize;
  }

  const centralDir = Buffer.concat(centralHeaders);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(centralDir.length, 12);
  eocd.writeUInt32LE(offset, 16);
  eocd.writeUInt16LE(0, 20);

  return Buffer.concat([...localHeaders, centralDir, eocd]);
}

// ── 1. Pre-MFA Enrollment Account Takeover Prevention ─────────────────────────

test('AuthService.beginMfaEnrollment blocks unverified pre-MFA session when active MFA already exists', async () => {
  const config = createTestConfig();
  const mfa = new MfaService(config);
  let auditRecorded = null;

  const mockRepository = {
    getActiveMfaMethods: async () => [{ id: 10n, encryptedSecret: 'enc', label: 'Primary TOTP' }],
    createMfaEnrollment: async () => {
      assert.fail('Should never create MFA enrollment when pre-MFA session already has active MFA');
    },
  };
  const mockAudit = {
    record: async (evt) => {
      auditRecorded = evt;
    },
  };

  const service = new AuthService(
    mockRepository,
    {},
    {},
    mfa,
    { assertAllowed: () => {}, recordFailure: () => 0, clearAccount: () => {} },
    mockAudit,
    {},
    config,
  );

  const preMfaPrincipal = {
    userId: 42n,
    username: 'admin.demo',
    sessionId: randomUUID(),
    roles: ['SYSTEM_ADMIN'],
    mfa: false,
    mfaPending: true,
    departmentId: 1n,
  };

  await assert.rejects(
    () =>
      service.beginMfaEnrollment(preMfaPrincipal, 'Attacker TOTP', {
        ip: '10.0.0.5',
        userAgent: 'Test',
        correlationId: randomUUID(),
      }),
    (err) => err instanceof ForbiddenException,
  );
  assert.ok(auditRecorded);
  assert.equal(auditRecorded.outcome, 'DENIED');
});

// ── 2. WebAuthn Challenge Replay Prevention ───────────────────────────────────

test('WebAuthnService.verifyChallengeToken rejects replayed challenge tokens', () => {
  const config = createTestConfig();
  const mfa = new MfaService(config);
  const webauthn = new WebAuthnService(mfa, config);

  const token = webauthn.createChallengeToken('random-challenge-abc-123', 99n);
  const extracted = webauthn.verifyChallengeToken(token, 99n);
  assert.equal(extracted, 'random-challenge-abc-123');

  assert.throws(
    () => webauthn.verifyChallengeToken(token, 99n),
    (err) => err instanceof BadRequestException && /already been used/i.test(err.message),
  );
});

// ── 3. Cross-Document grantId BOLA Prevention ─────────────────────────────────

test('AccessGrantsService.assertGrantValidForAccess blocks cross-document grantId BOLA', async () => {
  const config = createTestConfig();
  const docA = randomUUID();
  const docB = randomUUID();
  const grantId = randomUUID();
  const now = new Date();

  const mockDb = {
    accessGrant: {
      findUnique: async () => ({
        id: grantId,
        document_id: docA,
        principal_type: 'USER',
        principal_user_id: 7n,
        principal_role_id: null,
        status: 'ACTIVE',
        valid_from: new Date(now.getTime() - 60_000),
        valid_until: new Date(now.getTime() + 3_600_000),
        access_grant_permissions: [{ permission: 'VIEW' }],
        documents: {
          id: docA,
          status: 'ACTIVE',
          classification_history: [
            {
              classification_levels: {
                rank: 2,
                allow_download: true,
              },
            },
          ],
        },
      }),
    },
  };

  const service = new AccessGrantsService({}, {}, {}, {}, config, mockDb);

  await assert.rejects(
    () => service.assertGrantValidForAccess(grantId, 7n, 'VIEW', now, docB),
    (err) =>
      err instanceof ForbiddenException &&
      /does not belong to the requested document/i.test(JSON.stringify(err.getResponse())),
  );
});

// ── 4. DocumentsService.getDocumentById IDOR & SoD Prevention ─────────────────

test('DocumentsService.getDocumentById enforces D-BR11 (404 on unauthorized non-discoverable) and SoD (403 on pure AUDITOR)', async () => {
  const docId = randomUUID();
  const baseDocRow = {
    id: docId,
    document_code: 'DOC-SECRET-01',
    title: 'Strategic Blueprint',
    description: 'Confidential plan',
    owner_id: 100n,
    department_id: 10n,
    status: 'ACTIVE',
    discoverable: false,
    retention_until: null,
    archived_at: null,
    created_at: new Date(),
    updated_at: new Date(),
    current_version_id: null,
    users_documents_owner_idTousers: { username: 'owner.demo' },
    departments: { name: 'R&D' },
    document_versions_documents_current_version_idTodocument_versions: null,
    classification_history: [
      {
        id: 1n,
        classification_level_id: 3n,
        business_category_id: 2n,
        reason: 'Initial',
        classified_by: 100n,
        effective_from: new Date(),
        classification_levels: { code: 'SECRET', name: 'Secret', rank: 3 },
        business_categories: { code: 'RND', name: 'R&D' },
      },
    ],
  };

  const mockDb = {
    document: {
      findUnique: async () => baseDocRow,
    },
    userAttributeAssignment: {
      findFirst: async () => ({ attribute_options: { numeric_rank: 3 } }),
    },
    accessGrant: {
      findFirst: async () => null,
    },
    userRole: {
      findMany: async () => [],
    },
  };

  const mockAuthorization = {
    hasPermission: async () => false,
  };

  const service = new DocumentsService({}, mockAuthorization, {}, mockDb);

  // Pure AUDITOR violates SoD when attempting to read business document metadata directly
  await assert.rejects(
    () =>
      service.getDocumentById(docId, {
        userId: 50n,
        username: 'auditor.demo',
        sessionId: randomUUID(),
        roles: ['AUDITOR'],
        mfa: true,
        mfaPending: false,
        departmentId: 10n,
      }),
    (err) => err instanceof ForbiddenException,
  );

  // Unauthorized reader without grant on non-discoverable doc gets 404 (D-BR11 anti-enumeration)
  await assert.rejects(
    () =>
      service.getDocumentById(docId, {
        userId: 51n,
        username: 'reader.demo',
        sessionId: randomUUID(),
        roles: ['DOCUMENT_READER'],
        mfa: true,
        mfaPending: false,
        departmentId: 10n,
      }),
    (err) => err instanceof NotFoundException,
  );
});

// ── 5. Unified RFC 8785 Audit Chain Verification ──────────────────────────────

test('appendChainedAuditLog produces RFC 8785 canonical HMAC chains verified cleanly by AuditVerifierService', async () => {
  const hmacKey = 'test-unified-audit-hmac-key-000000000000';
  const storedLogs = [];

  const mockTx = {
    $executeRawUnsafe: async () => 1,
    $queryRawUnsafe: async () => {
      if (storedLogs.length === 0) return [];
      const last = storedLogs[storedLogs.length - 1];
      return [{ entry_hash: last.entry_hash, chain_sequence: last.chain_sequence }];
    },
    auditLog: {
      create: async ({ data }) => {
        const record = {
          id: BigInt(storedLogs.length + 1),
          ...data,
        };
        storedLogs.push(record);
        return record;
      },
    },
  };

  await appendChainedAuditLog(mockTx, {
    partition: 'DOCUMENT',
    hmacKey,
    action: 'DOCUMENT_CREATED',
    outcome: 'SUCCESS',
    objectType: 'DOCUMENT',
    objectId: randomUUID(),
    actorUserId: 10n,
    actorUsername: 'owner.demo',
    details: { title: 'Doc 1', authorizationBearer: 'secret-should-redact' },
    context: { ip: '10.10.1.5', userAgent: 'UnitTest/1.0', correlationId: randomUUID() },
  });

  await appendChainedAuditLog(mockTx, {
    partition: 'DOCUMENT',
    hmacKey,
    action: 'DOCUMENT_ACTIVATED',
    outcome: 'SUCCESS',
    objectType: 'DOCUMENT',
    objectId: randomUUID(),
    actorUserId: 10n,
    actorUsername: 'owner.demo',
    details: { status: 'ACTIVE' },
    context: { ip: '10.10.1.5', userAgent: 'UnitTest/1.0', correlationId: randomUUID() },
  });

  const createdAlerts = [];
  const createdLinks = [];
  const mockVerifierDb = {
    auditLog: {
      findMany: async () => storedLogs,
    },
    auditAnchor: {
      findMany: async () => [],
    },
    $transaction: async (fn) =>
      fn({
        securityAlert: {
          findFirst: async () => null,
          create: async ({ data }) => {
            createdAlerts.push(data);
            return data;
          },
        },
        alertAuditLink: {
          create: async ({ data }) => {
            createdLinks.push(data);
            return data;
          },
        },
      }),
  };

  const verifier = new AuditVerifierService({ getHmacKey: () => hmacKey }, mockVerifierDb);
  const report = await verifier.verifyPartition('DOCUMENT');

  assert.equal(report.valid, true);
  assert.equal(report.totalChecked, 2);
  assert.equal(report.violations.length, 0);

  // Tamper with first entry details and verify detection
  storedLogs[0].details = { title: 'Tampered Title' };
  const tamperedReport = await verifier.verifyPartition('DOCUMENT');
  assert.equal(tamperedReport.valid, false);
  assert.ok(tamperedReport.violations.length >= 1);
  assert.equal(createdAlerts.length, 1);
  assert.equal(createdLinks.length, 1);
});

// ── 6. ZipBombGuardService: XXE, External .rels SSRF, and Spoofed Size ────────

test('ZipBombGuardService blocks XXE DOCTYPE, external .rels TargetMode="External", and spoofed header size', async () => {
  const guard = new ZipBombGuardService(createTestConfig());

  const xxeDocx = createZipBuffer([
    { name: '[Content_Types].xml', content: '<?xml version="1.0"?><Types></Types>' },
    {
      name: 'word/document.xml',
      content:
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><w:document>&xxe;</w:document>',
    },
  ]);
  await assert.rejects(
    () => guard.inspectOfficeZip(xxeDocx, '.docx'),
    (err) => err instanceof BadRequestException,
  );

  const externalRelsDocx = createZipBuffer([
    { name: '[Content_Types].xml', content: '<?xml version="1.0"?><Types></Types>' },
    { name: 'word/document.xml', content: '<?xml version="1.0"?><w:document>Safe</w:document>' },
    {
      name: 'word/_rels/document.xml.rels',
      content:
        '<?xml version="1.0"?><Relationships><Relationship Id="rId1" Target="http://169.254.169.254/latest/meta-data" TargetMode="External"/></Relationships>',
    },
  ]);
  await assert.rejects(
    () => guard.inspectOfficeZip(externalRelsDocx, '.docx'),
    (err) => err instanceof BadRequestException,
  );

  const spoofedBomb = createZipBuffer(
    [
      { name: '[Content_Types].xml', content: '<?xml version="1.0"?><Types></Types>' },
      { name: 'word/document.xml', content: 'A'.repeat(4096) },
    ],
    { spoofUncompressedZero: true },
  );
  await assert.rejects(
    () => guard.inspectOfficeZip(spoofedBomb, '.docx', { maxTotalUncompressedSize: 1024 }),
    (err) => err instanceof BadRequestException,
  );
});

// ── 7. Watermark Vietnamese Diacritics & Visible Watermark Policy ─────────────

test('WatermarkEngineService renders Vietnamese diacritics cleanly and WatermarksService blocks disabling visibility', async () => {
  const pdfDoc = await PDFDocument.create();
  const page = pdfDoc.addPage([600, 800]);
  const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
  page.drawText('Top Secret Test PDF', { x: 50, y: 700, size: 16, font });
  const rawPdfBytes = Buffer.from(await pdfDoc.save());

  const engine = new WatermarkEngineService({});
  const wmConfig = {
    id: 1n,
    template_text: '{{fullName}} - {{documentCode}} - {{token}}',
    opacity_percent: 30,
    rotation_degrees: -45,
    font_size: 24,
    color_hex: '#808080',
    include_qr_code: true,
    is_visible: true,
  };

  const watermarked = await engine.applyWatermarkToPdf(
    rawPdfBytes,
    {
      id: 12n,
      username: 'nguyenvandoc',
      fullName: 'Nguyễn Văn Đọc — Phòng Kỹ Thuật Đặc Biệt',
      employeeCode: 'NV-009',
    },
    {
      id: randomUUID(),
      documentCode: 'TL-ĐẶC-BIỆT-01',
      title: 'Báo cáo mật',
      classificationName: 'TUYỆT MẬT',
      requireWatermark: true,
    },
    wmConfig,
  );

  assert.ok(watermarked.watermarkedBuffer.subarray(0, 5).toString('ascii') === '%PDF-');
  assert.equal(watermarked.pageCount, 1);

  const watermarksService = new WatermarksService({});
  await assert.rejects(
    () => watermarksService.updateConfig(1n, { isVisible: false }),
    (err) => err instanceof BadRequestException,
  );
  await assert.rejects(
    () => watermarksService.updateConfig(1n, { opacityPercent: 2 }),
    (err) => err instanceof BadRequestException,
  );
});

// ── 8. ABAC IPv4-mapped IPv6 CIDR Matching & CSV Formula Sanitization ─────────

test('evaluatePolicy matches IPv4-mapped IPv6 addresses against IPv4 CIDR and sanitizeCsvCell neutralizes pipe/whitespace formulas', () => {
  const nowIso = new Date().toISOString();
  const policy = {
    version: 'v1',
    requiredAttributes: ['environment.ip'],
    rules: [
      {
        id: '1',
        code: 'CORP-NET-PERMIT',
        effect: 'PERMIT',
        priority: 10,
        targetResource: 'DOCUMENT',
        targetAction: 'VIEW',
        combiningAlgorithm: 'DENY_OVERRIDES',
        validFrom: new Date(Date.now() - 60_000).toISOString(),
        validTo: null,
        obligations: [],
        groups: [
          {
            id: 1,
            conditions: [
              {
                id: 'c1',
                attribute: 'environment.ip',
                operator: 'CIDR_MATCH',
                expected: '10.10.0.0/16',
              },
            ],
          },
        ],
      },
    ],
  };

  const evalResult = evaluatePolicy(policy, {
    action: 'VIEW',
    resourceType: 'DOCUMENT',
    subject: {
      clearanceRank: 3,
      departmentId: '1',
      employmentStatus: 'ACTIVE',
      projects: [],
    },
    resource: {
      classificationRank: 2,
      ownerId: '10',
      departmentId: '1',
      category: 'GEN',
      status: 'ACTIVE',
    },
    environment: {
      currentTime: nowIso,
      ip: '::ffff:10.10.42.19',
      trustedNetwork: true,
      deviceTrust: true,
      mfa: true,
      riskScore: 0,
    },
  });

  assert.equal(evalResult.decision, 'PERMIT');

  assert.equal(sanitizeCsvCell('|cmd|/c calc'), "'|cmd|/c calc");
  assert.equal(sanitizeCsvCell('   =SUM(A1:A2)'), "'   =SUM(A1:A2)");
  assert.equal(sanitizeCsvCell('\n=HYPERLINK("http://evil")'), '\'\n=HYPERLINK("http://evil")');
  assert.equal(sanitizeCsvCell('Safe Normal Cell'), 'Safe Normal Cell');
});
