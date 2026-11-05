import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import { createDocumentsTestService } from './helpers/document-lifecycle-mocks.mjs';

test('Document Lifecycle: creates draft with required fields, initial classification and audit', async () => {
  const { service, mockAudit } = createDocumentsTestService();
  const principal = { userId: 1n, username: 'owner_user', roles: ['DOCUMENT_OWNER'], mfa: true };
  const context = { ip: '127.0.0.1', correlationId: randomUUID() };

  const created = await service.createDocumentDraft(
    {
      title: 'Kế hoạch an ninh mạng 2026',
      departmentId: 100n,
      description: 'Tài liệu mật về bảo mật hệ thống',
      classificationLevelId: 2n,
      businessCategoryId: 10n,
      retentionUntil: '2028-12-31',
    },
    principal,
    context,
  );

  assert.ok(created.id);
  assert.equal(created.title, 'Kế hoạch an ninh mạng 2026');
  assert.equal(created.status, 'DRAFT');
  assert.equal(created.ownerId, '1');
  assert.equal(created.departmentId, '100');
  assert.equal(created.retentionUntil, '2028-12-31');
  assert.ok(created.currentClassification);
  assert.equal(created.currentClassification.classificationLevelCode, 'CONFIDENTIAL');
  assert.equal(created.currentClassification.rank, 2);

  const auditEvent = mockAudit.recorded.find((a) => a.action === 'DOCUMENT_CREATED');
  assert.ok(auditEvent);
  assert.equal(auditEvent.outcome, 'SUCCESS');
  assert.equal(auditEvent.actorUserId, 1n);
});

test('Document Lifecycle: rejects activation when missing classification or CLEAN version', async () => {
  const docId = randomUUID();
  const { db, documents, versions, mockAudit, service } = createDocumentsTestService({
    documents: [
      [
        docId,
        {
          id: docId,
          document_code: 'DOC-TEST1',
          title: 'Draft document',
          owner_id: 1n,
          department_id: 100n,
          status: 'DRAFT',
          current_version_id: null,
          retention_until: null,
        },
      ],
    ],
  });

  const principal = { userId: 1n, username: 'owner_user', roles: ['DOCUMENT_OWNER'], mfa: true };
  const context = { ip: '127.0.0.1', correlationId: randomUUID() };

  await assert.rejects(
    service.activateDocument(docId, principal, context),
    (err) => err.response?.errorCode === 'DOCUMENT_ACTIVATION_FAILED',
  );

  db.documentClassificationHistory.create({
    data: {
      document_id: docId,
      classification_level_id: 1n,
      business_category_id: 10n,
      reason: 'Draft classification',
      classified_by: 1n,
      effective_from: new Date(),
      effective_to: null,
    },
  });

  await assert.rejects(
    service.activateDocument(docId, principal, context),
    (err) => err.response?.errorCode === 'DOCUMENT_ACTIVATION_FAILED',
  );

  const infectedVersionId = 5001n;
  versions.set(infectedVersionId, {
    id: infectedVersionId,
    document_id: docId,
    version_no: 1,
    original_filename: 'malware.pdf',
    scan_status: 'INFECTED',
    file_size_bytes: 1024n,
    sha256_hash: 'abc',
    created_at: new Date(),
  });
  documents.get(docId).current_version_id = infectedVersionId;

  await assert.rejects(
    service.activateDocument(docId, principal, context),
    (err) => err.response?.errorCode === 'VERSION_NOT_CLEAN',
  );

  const cleanVersionId = 5002n;
  versions.set(cleanVersionId, {
    id: cleanVersionId,
    document_id: docId,
    version_no: 2,
    original_filename: 'clean.pdf',
    scan_status: 'CLEAN',
    file_size_bytes: 2048n,
    sha256_hash: 'def',
    created_at: new Date(),
  });
  documents.get(docId).current_version_id = cleanVersionId;

  const activated = await service.activateDocument(docId, principal, context);
  assert.equal(activated.status, 'ACTIVE');

  const activatedAudit = mockAudit.recorded.find((a) => a.action === 'DOCUMENT_ACTIVATED');
  assert.ok(activatedAudit);
  assert.equal(activatedAudit.outcome, 'SUCCESS');
});

test('Document Lifecycle: activateDocument auto-provisions active access grant for document owner', async () => {
  const docId = randomUUID();
  const versionId = 999n;
  const { accessGrants, service } = createDocumentsTestService({
    users: [[10n, { id: 10n, username: 'owner10', status: 'ACTIVE' }]],
    documents: [
      [
        docId,
        {
          id: docId,
          document_code: 'DOC-ACTIVATE-GRANT',
          title: 'Auto grant activation test',
          owner_id: 10n,
          department_id: 100n,
          status: 'DRAFT',
          current_version_id: versionId,
          retention_until: null,
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
          file_size_bytes: 1024n,
          sha256_hash: 'abc123hash',
          original_filename: 'test.pdf',
          mime_type: 'application/pdf',
        },
      ],
    ],
    classifications: [
      [
        1n,
        {
          id: 1n,
          document_id: docId,
          classification_level_id: 2n,
          business_category_id: 10n,
          effective_to: null,
          classified_by: 10n,
          reason: 'Initial classification',
          effective_from: new Date(),
          classification_levels: {
            id: 2n,
            rank: 2,
            code: 'RESTRICTED',
            name: 'Nội bộ',
            allow_download: true,
          },
          business_categories: { id: 10n, code: 'GENERAL', name: 'Chung' },
        },
      ],
    ],
  });

  const principal = { userId: 10n, username: 'owner10', roles: ['DOCUMENT_OWNER'], mfa: true };
  const context = { ip: '127.0.0.1', correlationId: randomUUID() };

  await service.activateDocument(docId, principal, context);

  const grants = Array.from(accessGrants.values()).filter(
    (g) => g.document_id === docId && g.principal_user_id === 10n && g.status === 'ACTIVE',
  );
  assert.equal(grants.length, 1);
  assert.equal(grants[0].source, 'DIRECT');
  assert.equal(grants[0].granted_by, 10n);
});
