import 'reflect-metadata';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { BadRequestException, ForbiddenException } from '@nestjs/common';
import { DatabaseConflictError } from '@sda/database';
import { AppConfigService } from '../dist/config/config.service.js';
import { CsrfService } from '../dist/modules/auth/csrf.service.js';
import { buildPepSubjectAttributes } from '../dist/modules/documents/pep-context-builder.js';
import { DocumentPepService } from '../dist/modules/documents/document-pep.service.js';
import { AuditService } from '../dist/modules/audit/audit.service.js';
import { AuditRedactionService } from '../dist/modules/audit/audit-redaction.service.js';
import { AuditWriterService } from '../dist/modules/audit/audit-writer.service.js';
import { HealthController } from '../dist/modules/system-health/health.controller.js';
import { HealthService } from '../dist/modules/system-health/health.service.js';
import { SYSTEM_ROLE_PERMISSION_MATRIX } from '../dist/modules/rbac/permission-matrix.js';

/**
 * Thuật toán: Tạo mock CSDL cho cổng PEP để kiểm chứng truy vấn `option_id: null` và tuần tự hóa `documentVersionId` sang chuỗi (CRIT-01).
 */
function createPepMockDb(capturedQueries) {
  const docId = randomUUID();
  const verId = 9007199254740995n;
  const grantId = randomUUID();
  return {
    docId,
    verId,
    grantId,
    db: {
      document: {
        findUnique: async () => ({
          id: docId,
          title: 'Hồ sơ Chiến lược',
          document_code: 'DOC-PEP-01',
          owner_id: 10n,
          department_id: 1n,
          status: 'ACTIVE',
          current_version_id: verId,
          current_version: { id: verId, version_no: 1, scan_status: 'CLEAN' },
          classification_history: [
            {
              effective_to: null,
              classification_levels: {
                id: 2n,
                code: 'INTERNAL',
                rank: 2,
                allow_download: true,
                require_watermark: true,
              },
              business_categories: { id: 3n, code: 'OPS' },
            },
          ],
        }),
      },
      user: {
        findUnique: async () => ({ id: 20n, department_id: 1n, status: 'ACTIVE' }),
      },
      userAttributeAssignment: {
        findFirst: async () => ({
          attribute_definitions: { is_active: true },
          attribute_options: { numeric_rank: 3, is_active: true },
        }),
        findMany: async (args) => {
          capturedQueries.push(args);
          return [{ value_text: 'PROJ-ALPHA' }];
        },
      },
      accessSession: {
        create: async ({ data }) => ({ id: data.id }),
      },
    },
  };
}

test('[CRIT-01] buildPepSubjectAttributes queries option_id: null and DocumentPepService returns string documentVersionId', async () => {
  const capturedQueries = [];
  const { docId, verId, grantId, db } = createPepMockDb(capturedQueries);

  const attrs = await buildPepSubjectAttributes(db, 20n, new Date());
  assert.deepEqual(attrs.projects, ['PROJ-ALPHA']);
  assert.equal(capturedQueries.length, 1);
  assert.deepEqual(capturedQueries[0].where.AND[1].OR[0], { option_id: null });

  const pepService = new DocumentPepService(
    { evaluate: async () => ({ decision: 'PERMIT', obligations: [], matchedRuleIds: ['r1'] }) },
    { assertGrantValidForAccess: async () => {} },
    { record: async () => {} },
    db,
    undefined,
  );

  const session = await pepService.enforceAccess(
    docId,
    {
      userId: 20n,
      sessionId: randomUUID(),
      username: 'reader.pep',
      roles: ['DOCUMENT_READER'],
      mfa: true,
    },
    { ip: '10.0.0.10', userAgent: 'pep-test', correlationId: 'corr-pep-1' },
    { action: 'VIEW', grantId },
  );

  assert.equal(session.documentVersionId, verId.toString());
  assert.doesNotThrow(() => JSON.stringify(session));
});

test('[CRIT-02, MED-01, MED-07] AuditService.verifyChain stringifies BigInt violations, scrubValue handles BigInt, sanitizeIp validates net.isIP & AuditWriter retries P2034', async () => {
  const auditService = new AuditService(
    {},
    {
      verifyPartition: async () => ({
        partition: 'SECURITY',
        valid: false,
        totalChecked: 5,
        anchorsChecked: 1,
        violations: [
          {
            code: 'AUDIT_SEQUENCE_GAP',
            partition: 'SECURITY',
            sequence: 3n,
            logId: 9007199254740999n,
            message: 'Gap at 3',
          },
        ],
      }),
    },
    {},
  );

  const verified = await auditService.verifyChain(
    { userId: 1n, sessionId: 's1', username: 'auditor', roles: ['AUDITOR'], mfa: true },
    { chainPartition: 'SECURITY' },
  );
  assert.equal(verified.violations[0].sequence, '3');
  assert.equal(verified.violations[0].logId, '9007199254740999');
  assert.doesNotThrow(() => JSON.stringify(verified));

  const redactor = new AuditRedactionService();
  const scrubbed = redactor.sanitizeDetails({
    targetUserId: 1234567890123456789n,
    password: 'test-redaction-input',
  });
  assert.equal(scrubbed.targetUserId, '1234567890123456789');
  assert.equal(scrubbed.password, '[REDACTED]');
  assert.doesNotThrow(() => JSON.stringify(scrubbed));

  assert.equal(redactor.sanitizeIp('192.168.1.15'), '192.168.1.15');
  assert.equal(redactor.sanitizeIp('fe80::1%eth0'), 'fe80::1');
  assert.equal(redactor.sanitizeIp('not-an-ip-address'), null);
  assert.equal(redactor.sanitizeIp('   '), null);

  let txAttempts = 0;
  const retryDb = {
    $transaction: async (fn) => {
      txAttempts += 1;
      if (txAttempts === 1) {
        throw new DatabaseConflictError('Serialization conflict', { code: 'P2034' });
      }
      return fn({
        $executeRawUnsafe: async () => 1,
        $queryRawUnsafe: async () => [],
        auditLog: {
          findFirst: async () => null,
          create: async ({ data }) => ({ id: 1n, ...data }),
        },
      });
    },
  };
  const writer = new AuditWriterService(
    new AppConfigService({ AUTH_AUDIT_HMAC_KEY: randomBytes(32).toString('hex') }),
    redactor,
    retryDb,
  );
  const written = await writer.writeLog({ action: 'RETRY_TEST', outcome: 'SUCCESS' });
  assert.equal(txAttempts, 2);
  assert.equal(written.chain_sequence, 1n);
});

test('[CRIT-03, MED-06] HealthController enforces HEALTHY/DEGRADED/DOWN + fail-closed CSRF, HealthService serializes BigInts & matrix includes new permissions', async () => {
  assert.ok(SYSTEM_ROLE_PERMISSION_MATRIX.SYSTEM_ADMIN.includes('SYSTEM_HEALTH_MANAGE'));
  assert.ok(SYSTEM_ROLE_PERMISSION_MATRIX.DOCUMENT_OWNER.includes('DOCUMENT_MANAGE'));

  const mockHealthDb = {
    systemHealthSnapshot: {
      create: async ({ data }) => ({
        id: 42n,
        captured_at: new Date('2026-11-05T10:00:00.000Z'),
        service_name: data.service_name,
        status: data.status,
        response_time_ms: data.response_time_ms,
        storage_used_bytes: 1048576n,
        storage_total_bytes: 1073741824n,
        error_count: data.error_count,
        details: data.details,
      }),
    },
  };
  const healthService = new HealthService({ get: () => '' }, mockHealthDb);
  const csrf = new CsrfService(new AppConfigService({ CORS_ORIGIN: 'http://localhost:3000' }));
  const controller = new HealthController(healthService, {}, csrf);

  await assert.rejects(
    () =>
      controller.captureSnapshot(
        { serviceName: 'API', status: 'HEALTHY' },
        { headers: {}, cookies: {} },
      ),
    ForbiddenException,
  );

  const token = randomBytes(24).toString('hex');
  const validReq = {
    auth: { userId: 1n, sessionId: 's', username: 'sysadmin', roles: ['SYSTEM_ADMIN'], mfa: true },
    headers: { origin: 'http://localhost:3000', 'x-csrf-token': token },
    cookies: { sda_csrf: token },
  };
  await assert.rejects(
    () => controller.captureSnapshot({ serviceName: 'API', status: 'UP' }, validReq),
    BadRequestException,
  );

  const created = await controller.captureSnapshot(
    {
      serviceName: 'API_GATEWAY',
      status: 'DEGRADED',
      details: { queueDepth: 12 },
    },
    validReq,
  );
  assert.equal(created.id, '42');
  assert.equal(created.storageUsedBytes, '1048576');
  assert.equal(created.storageTotalBytes, '1073741824');
  assert.doesNotThrow(() => JSON.stringify(created));
});
