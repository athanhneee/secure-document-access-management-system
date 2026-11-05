import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import { ForbiddenException, NotFoundException } from '@nestjs/common';

process.env.STORAGE_MOCK = 'true';
process.env.NODE_ENV = 'test';
process.env.DATABASE_URL = 'postgresql://localhost:5432/secure_docs?schema=public';
process.env.APP_ENCRYPTION_MASTER_KEY = 'test-master-key-32-chars-long-000000000';

import { DocumentsService } from '../dist/modules/documents/documents.service.js';
import { appendChainedAuditLog } from '../dist/modules/audit/audit-chain-helper.js';
import { AuditVerifierService } from '../dist/modules/audit/audit-verifier.service.js';

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

  storedLogs[0].details = { title: 'Tampered Title' };
  const tamperedReport = await verifier.verifyPartition('DOCUMENT');
  assert.equal(tamperedReport.valid, false);
  assert.ok(tamperedReport.violations.length >= 1);
  assert.equal(createdAlerts.length, 1);
  assert.equal(createdLinks.length, 1);
});
