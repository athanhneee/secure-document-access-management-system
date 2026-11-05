import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import { createDocumentsTestService } from './helpers/document-lifecycle-mocks.mjs';

test('Document Lifecycle: Archiving transitions to ARCHIVED, sets archived_at, suspends grants, terminates sessions', async () => {
  const docId = randomUUID();
  const grantId = randomUUID();
  const sessionId = randomUUID();
  const versionId = 9999n;

  const { accessGrants, accessSessions, service } = createDocumentsTestService({
    documents: [
      [
        docId,
        {
          id: docId,
          document_code: 'DOC-ARCHIVE',
          title: 'Archive test',
          owner_id: 1n,
          department_id: 100n,
          status: 'ACTIVE',
          archived_at: null,
        },
      ],
    ],
    versions: [
      [
        versionId,
        {
          id: versionId,
          document_id: docId,
          version_no: 1,
          scan_status: 'CLEAN',
        },
      ],
    ],
    accessGrants: [
      [
        grantId,
        {
          id: grantId,
          document_id: docId,
          status: 'ACTIVE',
        },
      ],
    ],
    accessSessions: [
      [
        sessionId,
        {
          id: sessionId,
          access_grant_id: grantId,
          document_version_id: versionId,
          status: 'ACTIVE',
        },
      ],
    ],
  });

  const principal = { userId: 1n, username: 'owner_user', roles: ['DOCUMENT_OWNER'], mfa: true };
  const context = { ip: '127.0.0.1', correlationId: randomUUID() };

  const archived = await service.archiveDocument(
    docId,
    { reason: 'Project closed' },
    principal,
    context,
  );

  assert.equal(archived.status, 'ARCHIVED');
  assert.ok(archived.archivedAt !== null, 'archived_at is set for DB check constraint');
  assert.equal(accessGrants.get(grantId).status, 'SUSPENDED');
  assert.equal(accessSessions.get(sessionId).status, 'TERMINATED');

  await assert.rejects(
    service.updateMetadata(docId, { title: 'New title' }, principal, context),
    (err) => err.response?.errorCode === 'DOCUMENT_ARCHIVED',
  );
});

test('Document Lifecycle: Retention check emits notifications and alerts but NEVER deletes files or documents', async () => {
  const expiringDocId = randomUUID();
  const validDocId = randomUUID();

  const now = new Date();
  const pastRetentionDate = new Date(now.getTime() - 2 * 86400 * 1000);
  const futureRetentionDate = new Date(now.getTime() + 100 * 86400 * 1000);

  const { documents, notifications, securityAlerts, service } = createDocumentsTestService({
    documents: [
      [
        expiringDocId,
        {
          id: expiringDocId,
          document_code: 'DOC-EXPIRED',
          title: 'Expired document',
          owner_id: 1n,
          department_id: 100n,
          status: 'ACTIVE',
          retention_until: pastRetentionDate,
        },
      ],
      [
        validDocId,
        {
          id: validDocId,
          document_code: 'DOC-SAFE',
          title: 'Safe document',
          owner_id: 1n,
          department_id: 100n,
          status: 'ACTIVE',
          retention_until: futureRetentionDate,
        },
      ],
    ],
  });

  const result = await service.checkRetentionWarnings(30);

  assert.equal(result.warningCount, 1);
  assert.equal(result.warnings[0].documentId, expiringDocId);

  assert.equal(notifications.size, 1);
  const notif = Array.from(notifications.values())[0];
  assert.equal(notif.recipient_id, 1n);
  assert.equal(notif.notification_type, 'RETENTION_EXPIRATION_WARNING');

  assert.equal(securityAlerts.size, 1);
  const alert = Array.from(securityAlerts.values())[0];
  assert.equal(alert.alert_type, 'RETENTION_OVERDUE');

  assert.equal(documents.size, 2);
  assert.equal(documents.get(expiringDocId).status, 'ACTIVE');
});

test('Document Lifecycle: transfer document owner updates owner and records audit', async () => {
  const docId = randomUUID();
  const { documents, mockAudit, service } = createDocumentsTestService({
    documents: [
      [
        docId,
        {
          id: docId,
          document_code: 'DOC-TRANSFER',
          title: 'Ownership transfer test',
          owner_id: 1n,
          department_id: 100n,
          status: 'DRAFT',
        },
      ],
    ],
  });

  const principal = { userId: 1n, username: 'owner_user', roles: ['DOCUMENT_OWNER'], mfa: true };
  const context = { ip: '127.0.0.1', correlationId: randomUUID() };

  const transferred = await service.transferOwner(
    docId,
    { newOwnerId: 2n, reason: 'Department reorganization' },
    principal,
    context,
  );

  assert.equal(transferred.ownerId, '2');
  assert.equal(documents.get(docId).owner_id, 2n);

  const transferAudit = mockAudit.recorded.find((a) => a.action === 'DOCUMENT_OWNER_TRANSFERRED');
  assert.ok(transferAudit);
  assert.equal(transferAudit.details.previousOwnerId, '1');
  assert.equal(transferAudit.details.newOwnerId, '2');
});

test('Document Lifecycle: transferOwner rejects transfer when new owner clearance is lower than classification rank', async () => {
  const docId = randomUUID();
  const { service } = createDocumentsTestService({
    documents: [
      [
        docId,
        {
          id: docId,
          document_code: 'DOC-SECRET-TRANSFER',
          title: 'Top Secret document',
          owner_id: 1n,
          department_id: 100n,
          status: 'ACTIVE',
        },
      ],
    ],
    classifications: [
      [
        1n,
        {
          id: 1n,
          document_id: docId,
          classification_level_id: 4n,
          effective_to: null,
          classification_levels: { id: 4n, rank: 4, code: 'SECRET', name: 'Mật' },
        },
      ],
    ],
    userAttributeAssignments: [
      [
        1n,
        {
          id: 1n,
          user_id: 2n,
          attribute_definitions: { code: 'CLEARANCE_LEVEL' },
          attribute_options: { numeric_rank: 2 },
          valid_from: new Date(2020, 1, 1),
          valid_to: null,
        },
      ],
    ],
  });

  const principal = { userId: 1n, username: 'owner_user', roles: ['DOCUMENT_OWNER'], mfa: true };
  const context = { ip: '127.0.0.1', correlationId: randomUUID() };

  await assert.rejects(
    service.transferOwner(
      docId,
      { newOwnerId: 2n, reason: 'Unauthorized transfer' },
      principal,
      context,
    ),
    (err) => err.response?.errorCode === 'GRANT_CLEARANCE_INSUFFICIENT',
  );
});
