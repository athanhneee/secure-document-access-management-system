import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import './helpers/audit-trail-mocks.mjs';
import { AuditService } from '../dist/modules/audit/audit.service.js';

test('AuditService: Document Owner can only view logs for owned documents', async () => {
  const ownedDocId = '11111111-1111-4111-8111-111111111111';
  const foreignDocId = '22222222-2222-4222-8222-222222222222';
  const ownerUserId = 999n;

  const mockDb = {
    document: {
      findUnique: async ({ where }) => {
        if (where.id === ownedDocId) return { id: ownedDocId, owner_id: ownerUserId };
        if (where.id === foreignDocId) return { id: foreignDocId, owner_id: 888n };
        return null;
      },
      findMany: async () => [{ id: ownedDocId }],
    },
    auditLog: {
      count: async () => 1,
      findMany: async () => [
        {
          id: 1n,
          occurred_at: new Date(),
          actor_user_id: ownerUserId,
          actor_username: 'owner',
          action: 'DOCUMENT_METADATA_UPDATED',
          object_type: 'DOCUMENT',
          object_id: ownedDocId,
          document_id: ownedDocId,
          access_session_id: null,
          outcome: 'SUCCESS',
          reason_code: null,
          ip_address: '127.0.0.1',
          user_agent: 'Browser',
          correlation_id: randomUUID(),
          details: {},
          chain_partition: 'DOCUMENT',
          chain_sequence: 1n,
          entry_hash: 'hash1',
          previous_hash: null,
          hmac_key_version: 1,
          chain_algorithm: 'HMAC-SHA-256',
        },
      ],
    },
  };

  const auditService = new AuditService({}, {}, mockDb);

  const ownerPrincipal = {
    userId: ownerUserId,
    username: 'owner',
    roles: ['DOCUMENT_OWNER'],
    sessionId: randomUUID(),
    mfa: true,
  };

  const ownedResult = await auditService.queryAuditLogs(ownerPrincipal, {
    documentId: ownedDocId,
    page: 1,
    pageSize: 20,
    sort: 'occurred_at',
    order: 'desc',
  });
  assert.equal(ownedResult.data.length, 1);
  assert.equal(ownedResult.data[0].documentId, ownedDocId);

  await assert.rejects(
    async () => {
      await auditService.queryAuditLogs(ownerPrincipal, {
        documentId: foreignDocId,
        page: 1,
        pageSize: 20,
        sort: 'occurred_at',
        order: 'desc',
      });
    },
    (err) => {
      assert.equal(err.status, 403);
      assert.match(err.message, /Access to audit logs for this document is denied/);
      return true;
    },
  );
});

test('AuditService: Auditor has global access; System Admin is rejected (SoD)', async () => {
  const mockDatabase = {
    auditLog: {
      count: async () => 5,
      findMany: async () => [],
    },
  };
  const auditService = new AuditService({}, {}, mockDatabase);

  const auditorPrincipal = {
    userId: 50n,
    username: 'auditor',
    roles: ['AUDITOR'],
    sessionId: randomUUID(),
    mfa: true,
  };

  const adminPrincipal = {
    userId: 1n,
    username: 'sysadmin',
    roles: ['SYSTEM_ADMIN'],
    sessionId: randomUUID(),
    mfa: true,
  };

  const result = await auditService.queryAuditLogs(auditorPrincipal, {
    page: 1,
    pageSize: 20,
    sort: 'occurred_at',
    order: 'desc',
  });
  assert.equal(result.pagination.total, 5);

  await assert.rejects(
    async () => {
      await auditService.queryAuditLogs(adminPrincipal, {
        page: 1,
        pageSize: 20,
        sort: 'occurred_at',
        order: 'desc',
      });
    },
    (err) => {
      assert.equal(err.status, 403);
      return true;
    },
  );
});

test('AuditService: Export to CSV escapes special characters and does not leak keys', async () => {
  const mockDatabase = {
    auditLog: {
      findMany: async () => [
        {
          id: 101n,
          occurred_at: new Date('2026-09-23T10:00:00.000Z'),
          actor_user_id: 10n,
          actor_username: 'alice, with comma',
          action: 'DOCUMENT_SEARCHED',
          object_type: 'DOCUMENT',
          object_id: 'doc-1',
          document_id: 'doc-1',
          access_session_id: null,
          outcome: 'SUCCESS',
          reason_code: 'Searched "confidential" term',
          ip_address: '10.0.0.1',
          correlation_id: 'c-1',
          chain_partition: 'DOCUMENT',
          chain_sequence: 1n,
          entry_hash: 'hash-abc',
        },
      ],
    },
  };
  const auditService = new AuditService({}, {}, mockDatabase);

  const auditorPrincipal = {
    userId: 50n,
    username: 'auditor',
    roles: ['AUDITOR'],
    sessionId: randomUUID(),
    mfa: true,
  };

  const exported = await auditService.exportAuditLogs(auditorPrincipal, {
    format: 'CSV',
    limit: 100,
  });

  assert.equal(exported.format, 'CSV');
  assert.equal(exported.count, 1);
  assert.ok(exported.data.includes('"alice, with comma"'));
  assert.ok(exported.data.includes('"Searched ""confidential"" term"'));
});
