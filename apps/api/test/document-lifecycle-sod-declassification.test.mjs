import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import { DocumentsService } from '../dist/modules/documents/documents.service.js';
import {
  createDocumentsTestService,
  createMockAuthorization,
} from './helpers/document-lifecycle-mocks.mjs';

test('Document Lifecycle: Reclassification to lower level does NOT automatically expand or restore revoked grants', async () => {
  const docId = randomUUID();
  const revokedGrantId = randomUUID();

  const { db, accessGrants, service } = createDocumentsTestService({
    documents: [
      [
        docId,
        {
          id: docId,
          document_code: 'DOC-DEESCALATE',
          title: 'De-escalation test',
          owner_id: 1n,
          department_id: 100n,
          status: 'ACTIVE',
        },
      ],
    ],
    userAttributeAssignments: [
      [
        1n,
        {
          user_id: 1n,
          attribute_code: 'CLEARANCE_LEVEL',
          numeric_rank: 4,
        },
      ],
    ],
    accessGrants: [
      [
        revokedGrantId,
        {
          id: revokedGrantId,
          document_id: docId,
          principal_type: 'USER',
          principal_user_id: 3n,
          status: 'REVOKED',
          revoke_reason: 'Previously revoked',
        },
      ],
    ],
  });

  db.documentClassificationHistory.create({
    data: {
      document_id: docId,
      classification_level_id: 4n,
      business_category_id: 10n,
      reason: 'Top secret level',
      classified_by: 1n,
      effective_from: new Date(),
      effective_to: null,
    },
  });

  const principal = { userId: 1n, username: 'owner_user', roles: ['DOCUMENT_OWNER'], mfa: true };
  const context = { ip: '127.0.0.1', correlationId: randomUUID() };

  await service.reclassifyDocument(
    docId,
    { classificationLevelId: 1n, businessCategoryId: 10n, reason: 'Declassified to Internal' },
    principal,
    context,
  );

  const grant = accessGrants.get(revokedGrantId);
  assert.equal(grant.status, 'REVOKED');
});

test('Document Lifecycle: Technical Admin cannot modify document metadata without business permission', async () => {
  const docId = randomUUID();
  const { db, mockAudit, cache, service } = createDocumentsTestService({
    documents: [
      [
        docId,
        {
          id: docId,
          document_code: 'DOC-ADMIN-CHECK',
          title: 'Protected business document',
          owner_id: 1n,
          department_id: 100n,
          status: 'DRAFT',
        },
      ],
    ],
  });

  const techAdminPrincipal = {
    userId: 888n,
    username: 'admin.tech',
    roles: ['SYSTEM_ADMIN'],
    mfa: true,
  };
  const context = { ip: '127.0.0.1', correlationId: randomUUID() };

  await assert.rejects(
    service.updateMetadata(docId, { title: 'Hacked by admin' }, techAdminPrincipal, context),
    (err) => err.response?.errorCode === 'TECHNICAL_ADMIN_CANNOT_OWN',
  );

  const businessAdminAuth = createMockAuthorization([
    {
      userId: 555n,
      resource: 'DOCUMENT',
      action: 'CLASSIFY',
      scopeDepartmentId: 100n,
    },
  ]);
  const businessService = new DocumentsService(mockAudit, businessAdminAuth, cache, db);
  const businessAdminPrincipal = {
    userId: 555n,
    username: 'dept.manager',
    roles: ['DOCUMENT_OWNER'],
    mfa: true,
  };

  const updated = await businessService.updateMetadata(
    docId,
    { title: 'Authorized update by department manager' },
    businessAdminPrincipal,
    context,
  );
  assert.equal(updated.title, 'Authorized update by department manager');
});

test('Document Lifecycle [CRIT-04]: Actor with lower clearance cannot downgrade a higher-ranked document & ARCHIVE cannot transfer owner', async () => {
  const docId = randomUUID();
  const { db, mockAudit, cache } = createDocumentsTestService({
    documents: [
      [
        docId,
        {
          id: docId,
          document_code: 'DOC-BLP-DOWNGRADE',
          title: 'Top Secret Protected Document',
          owner_id: 1n,
          department_id: 100n,
          status: 'ACTIVE',
        },
      ],
    ],
    userAttributeAssignments: [
      [1n, { user_id: 555n, attribute_code: 'CLEARANCE_LEVEL', numeric_rank: 2 }],
      [2n, { user_id: 2n, attribute_code: 'CLEARANCE_LEVEL', numeric_rank: 4 }],
    ],
  });

  await db.documentClassificationHistory.create({
    data: {
      document_id: docId,
      classification_level_id: 4n,
      business_category_id: 10n,
      reason: 'Top Secret',
      classified_by: 1n,
      effective_from: new Date(),
      effective_to: null,
    },
  });

  const deptAuth = createMockAuthorization([
    { userId: 555n, resource: 'DOCUMENT', action: 'CLASSIFY', scopeDepartmentId: 100n },
    { userId: 777n, resource: 'DOCUMENT', action: 'ARCHIVE', scopeDepartmentId: 100n },
  ]);
  const deptService = new DocumentsService(mockAudit, deptAuth, cache, db);
  const context = { ip: '127.0.0.1', correlationId: randomUUID() };

  await assert.rejects(
    () =>
      deptService.reclassifyDocument(
        docId,
        { classificationLevelId: 1n, businessCategoryId: 10n, reason: 'Unauthorized downgrade' },
        { userId: 555n, username: 'dept.mgr', roles: ['DOCUMENT_OWNER'], mfa: true },
        context,
      ),
    (err) => err.response?.errorCode === 'BELL_LAPADULA_CLEARANCE_INSUFFICIENT',
  );

  await assert.rejects(
    () =>
      deptService.transferOwner(
        docId,
        { newOwnerId: 2n, reason: 'Archive role attempting ownership takeover' },
        { userId: 777n, username: 'archiver', roles: ['DOCUMENT_OWNER'], mfa: true },
        context,
      ),
    (err) => err.response?.errorCode === 'TECHNICAL_ADMIN_CANNOT_OWN',
  );
});
