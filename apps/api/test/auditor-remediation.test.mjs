/**
 * @module ApiAuditorRemediationTests
 * Thuật toán: Bộ kiểm thử hồi quy Backend cho toàn bộ phát hiện kiểm toán `qa.auditor`:
 *   - Che dấu khóa bí mật (`encryption_key_ref`, `passwordHash`, `csrfToken`, `WM-` 12-hex, cookie `sda_*`) mà giữ nguyên siêu dữ liệu hợp lệ (`hmacKeyVersion`, `signerKeyId`).
 *   - Lọc ngày cuối bao gồm toàn bộ ngày `23:59:59.999Z`, chặn `from > to`, tìm `action`/`actorUsername` chuỗi con không phân biệt hoa/thường.
 *   - Phân quyền Custom Role + phạm vi phòng ban (`visibleDepartmentIds`) + Audit-of-Audit (`AUDIT_CHAIN_VERIFIED`, `AUDIT_LOG_EXPORTED`).
 *   - Chống bỏ sót dữ liệu bị xóa hoặc điểm neo lịch sử giả mạo trước điểm neo `K` trong `AuditVerifierService`.
 *   - Fail-fast khóa mã hóa export trên `production`/`staging` và cấu hình CORS `exposedHeaders`.
 */
import 'reflect-metadata';
import assert from 'node:assert/strict';
import { createHmac, randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { AuditRedactionService } from '../dist/modules/audit/audit-redaction.service.js';
import {
  applyAuditFilterAllowlist,
  parseAuditDateBound,
} from '../dist/modules/audit/audit-export.helper.js';
import { AuditService } from '../dist/modules/audit/audit.service.js';
import { AuditVerifierService } from '../dist/modules/audit/audit-verifier.service.js';
import { buildAuditLogExportWhere } from '../dist/modules/reports/export-where-builders.helper.js';
import { encryptExportArtifactBuffer } from '../dist/modules/reports/export-disk-cipher.helper.js';
import { createAuditWriterHarness } from './helpers/audit-trail-mocks.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

test('AuditRedactionService redacts encryption_key_ref, token/credential variants, 12-hex WM tokens & cookies while preserving metadata', () => {
  const redactor = new AuditRedactionService();
  const scrubbed = redactor.sanitizeDetails({
    encryption_key_ref: 'kms://vault/key-001',
    passwordHash: '$argon2id$v=19$secret',
    csrfToken: 'csrf-raw-999',
    resetToken: 'reset-raw-888',
    sessionToken: 'sess-raw-777',
    apiKey: 'sk-live-123456',
    authorization: 'Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig',
    jwt: 'eyJhbGciOiJIUzI1NiJ9.payload.sig',
    watermarkToken: 'WM-abcdef123456',
    hmacKey: 'hmac-secret-key',
    vaultToken: 'hvs.vault-token',
    nested: {
      clientSecret: 'super-secret',
      shortWmInText: 'Traced token WM-2e59958fa6c7 in leaked pdf',
      cookieLeak: 'Header sda_access=eyJabc.def.ghi; sda_refresh=raw123',
    },
    hmacKeyVersion: 2,
    signerKeyId: 'integrity-key-v2',
    keyVersion: 2,
    tokenCount: 4,
  });

  for (const key of [
    'encryption_key_ref',
    'passwordHash',
    'csrfToken',
    'resetToken',
    'sessionToken',
    'apiKey',
    'authorization',
    'jwt',
    'watermarkToken',
    'hmacKey',
    'vaultToken',
  ]) {
    assert.equal(scrubbed[key], '[REDACTED]', `Expected ${key} to be redacted`);
  }

  assert.equal(scrubbed.nested.clientSecret, '[REDACTED]');
  assert.equal(scrubbed.nested.shortWmInText, 'Traced token [REDACTED_WM_TOKEN] in leaked pdf');
  assert.ok(scrubbed.nested.cookieLeak.includes('sda_access=[REDACTED_COOKIE]'));
  assert.ok(scrubbed.nested.cookieLeak.includes('sda_refresh=[REDACTED_COOKIE]'));

  // Legitimate non-secret audit metadata must stay intact
  assert.equal(scrubbed.hmacKeyVersion, 2);
  assert.equal(scrubbed.signerKeyId, 'integrity-key-v2');
  assert.equal(scrubbed.keyVersion, 2);
  assert.equal(scrubbed.tokenCount, 4);
});

test('applyAuditFilterAllowlist expands date-only to end-of-day, rejects reversed range, and uses case-insensitive partial action/actor search', () => {
  const start = parseAuditDateBound('2026-11-25', false);
  const end = parseAuditDateBound('2026-11-25', true);
  assert.equal(start.toISOString(), '2026-11-25T00:00:00.000Z');
  assert.equal(end.toISOString(), '2026-11-25T23:59:59.999Z');

  const where = {};
  applyAuditFilterAllowlist(where, {
    action: 'login',
    actorUsername: 'qa.auditor',
    chainPartition: 'AUTH',
    from: '2026-11-25',
    to: '2026-11-25',
  });

  assert.deepEqual(where.action, { contains: 'login', mode: 'insensitive' });
  assert.deepEqual(where.actor_username, { contains: 'qa.auditor', mode: 'insensitive' });
  assert.equal(where.chain_partition, 'AUTH');
  assert.equal(where.occurred_at.gte.toISOString(), '2026-11-25T00:00:00.000Z');
  assert.equal(where.occurred_at.lte.toISOString(), '2026-11-25T23:59:59.999Z');

  assert.throws(
    () => applyAuditFilterAllowlist({}, { from: '2026-11-26', to: '2026-11-25' }),
    (err) => err?.status === 400,
  );

  const exportWhere = buildAuditLogExportWhere({
    fromDate: start,
    toDate: end,
    effectiveDepartmentIds: null,
    actorUserId: null,
    actorUsername: 'qa.auditor',
    documentId: null,
    action: 'grant',
    outcome: 'SUCCESS',
    chainPartition: 'DOCUMENT',
    severity: null,
    status: null,
    alertType: null,
    incidentCode: null,
    serviceName: null,
    limit: 100,
  });
  assert.deepEqual(exportWhere.action, { contains: 'grant', mode: 'insensitive' });
  assert.deepEqual(exportWhere.actor_username, { contains: 'qa.auditor', mode: 'insensitive' });
});

test('AuditService supports Custom Role RBAC with department scoping and records Audit-of-Audit for verifyChain & exportAuditLogs', async () => {
  const writtenAuditEvents = [];
  let capturedWhere = null;

  const mockWriter = {
    writeLog: async (ev) => {
      writtenAuditEvents.push(ev);
      return { id: 99n, entry_hash: 'h', chain_partition: 'AUDIT', chain_sequence: 1n };
    },
  };
  const mockVerifier = {
    verifyPartition: async (partition) => ({
      partition,
      valid: true,
      totalChecked: 4,
      anchorsChecked: 1,
      resumedFromAnchorSequence: '2',
      violations: [],
    }),
    verifyAllPartitions: async () => ({
      AUTH: {
        partition: 'AUTH',
        valid: true,
        totalChecked: 2,
        anchorsChecked: 0,
        violations: [],
      },
    }),
  };
  const mockDb = {
    auditLog: {
      count: async ({ where }) => {
        capturedWhere = where;
        return 1;
      },
      findMany: async () => [],
    },
  };
  const mockAuthz = {
    hasPermission: async (_principal, resource, action) =>
      resource === 'AUDIT_LOG' && (action === 'VIEW' || action === 'EXPORT'),
    visibleDepartmentIds: async () => [10n, 20n],
  };

  const service = new AuditService(mockWriter, mockVerifier, mockDb, mockAuthz);
  const customAuditor = {
    userId: 77n,
    username: 'custom.compliance',
    roles: ['COMPLIANCE_DEPT_AUDITOR'],
    sessionId: randomUUID(),
    mfa: true,
  };

  const queryRes = await service.queryAuditLogs(customAuditor, {
    page: 1,
    pageSize: 20,
    sort: 'occurred_at',
    order: 'desc',
  });
  assert.equal(queryRes.pagination.total, 1);
  assert.deepEqual(capturedWhere.OR, [
    { users: { department_id: { in: [10n, 20n] } } },
    { documents: { department_id: { in: [10n, 20n] } } },
  ]);

  const verifySingle = await service.verifyChain(customAuditor, { chainPartition: 'AUTH' });
  assert.equal(verifySingle.valid, true);
  assert.equal(verifySingle.resumedFromAnchorSequence, '2');

  await service.exportAuditLogs(customAuditor, { format: 'JSON', limit: 100 });
  assert.deepEqual(
    writtenAuditEvents.map((e) => e.action),
    ['AUDIT_CHAIN_VERIFIED', 'AUDIT_LOG_EXPORTED'],
  );

  // Empty visibleDepartmentIds must fail closed with 0 rows
  const emptyScopeService = new AuditService(mockWriter, mockVerifier, mockDb, {
    hasPermission: async () => true,
    visibleDepartmentIds: async () => [],
  });
  const emptyRes = await emptyScopeService.queryAuditLogs(customAuditor, {
    page: 1,
    pageSize: 20,
    sort: 'occurred_at',
    order: 'desc',
  });
  assert.equal(emptyRes.pagination.total, 0);
  assert.deepEqual(emptyRes.data, []);
});

test('AuditVerifierService falls back to full scan when rows before anchor K are deleted or prior anchor signature is tampered', async () => {
  const { config, writer, logs, mockTx } = createAuditWriterHarness();
  const ctx = { ip: '127.0.0.1', correlationId: randomUUID() };
  for (const act of ['E1', 'E2', 'E3']) {
    await writer.record(
      { action: act, outcome: 'SUCCESS', objectType: 'DOC', chainPartition: 'P2' },
      ctx,
      mockTx,
    );
  }
  const key = config.get('AUDIT_INTEGRITY_KEY');
  const validAnchor2Sig = createHmac('sha256', key)
    .update(`P2:2:${logs[1].entry_hash}`)
    .digest('hex');

  // Case 1: Row #1 deleted before anchor #2 (count(lte: 2n) === 1 !== 2)
  const deletedRowLogs = [logs[1], logs[2]];
  const verifierDeletedRow = new AuditVerifierService(writer, {
    auditAnchor: {
      findMany: async () => [
        {
          chain_partition: 'P2',
          anchor_sequence: 2n,
          entry_hash: logs[1].entry_hash,
          signature: validAnchor2Sig,
          signer_key_id: 'v1',
          status: 'VALID',
        },
      ],
    },
    auditLog: {
      count: async () => 1,
      findFirst: async ({ where }) =>
        deletedRowLogs.find((l) => l.chain_sequence === where.chain_sequence) ?? null,
      findMany: async ({ where }) =>
        deletedRowLogs.filter((l) =>
          where.chain_sequence?.gt ? l.chain_sequence > where.chain_sequence.gt : true,
        ),
    },
    securityAlert: { findFirst: async () => null, create: async ({ data }) => data },
    alertAuditLink: { create: async () => ({}) },
    $transaction: async (fn) =>
      fn({
        securityAlert: { findFirst: async () => null, create: async ({ data }) => data },
        alertAuditLink: { create: async () => ({}) },
      }),
  });

  const deletedRes = await verifierDeletedRow.verifyPartition('P2');
  assert.equal(deletedRes.valid, false);
  assert.ok(deletedRes.violations.some((v) => v.code === 'AUDIT_SEQUENCE_GAP'));

  // Case 2: Historical anchor #1 tampered while anchor #2 is valid
  const verifierTamperedPrior = new AuditVerifierService(writer, {
    auditAnchor: {
      findMany: async () => [
        {
          chain_partition: 'P2',
          anchor_sequence: 1n,
          entry_hash: logs[0].entry_hash,
          signature: 'deadbeef'.repeat(8),
          signer_key_id: 'v1',
          status: 'VALID',
        },
        {
          chain_partition: 'P2',
          anchor_sequence: 2n,
          entry_hash: logs[1].entry_hash,
          signature: validAnchor2Sig,
          signer_key_id: 'v1',
          status: 'VALID',
        },
      ],
    },
    auditLog: {
      count: async () => 2,
      findFirst: async ({ where }) =>
        logs.find((l) => l.chain_sequence === where.chain_sequence) ?? null,
      findMany: async ({ where }) =>
        logs.filter((l) =>
          where.chain_sequence?.gt ? l.chain_sequence > where.chain_sequence.gt : true,
        ),
    },
    securityAlert: { findFirst: async () => null, create: async ({ data }) => data },
    alertAuditLink: { create: async () => ({}) },
    $transaction: async (fn) =>
      fn({
        securityAlert: { findFirst: async () => null, create: async ({ data }) => data },
        alertAuditLink: { create: async () => ({}) },
      }),
  });

  const priorRes = await verifierTamperedPrior.verifyPartition('P2');
  assert.equal(priorRes.valid, false);
  assert.ok(priorRes.violations.some((v) => v.code === 'AUDIT_ANCHOR_MISMATCH'));
});

test('Export disk cipher fails fast without configured key in production/staging & CORS exposes Content-Disposition', () => {
  const saved = {
    NODE_ENV: process.env.NODE_ENV,
    EXPORT_ENCRYPTION_KEY: process.env.EXPORT_ENCRYPTION_KEY,
    AUDIT_INTEGRITY_KEY: process.env.AUDIT_INTEGRITY_KEY,
  };
  try {
    process.env.NODE_ENV = 'staging';
    delete process.env.EXPORT_ENCRYPTION_KEY;
    delete process.env.AUDIT_INTEGRITY_KEY;
    assert.throws(
      () => encryptExportArtifactBuffer(randomUUID(), Buffer.from('test')),
      /EXPORT_ENCRYPTION_KEY/,
    );
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }

  const appSource = fs.readFileSync(path.resolve(__dirname, '../src/application.ts'), 'utf8');
  assert.match(appSource, /exposedHeaders:\s*\[[^\]]*Content-Disposition/);
  assert.match(appSource, /exposedHeaders:\s*\[[^\]]*X-Total-Pages/);
});
