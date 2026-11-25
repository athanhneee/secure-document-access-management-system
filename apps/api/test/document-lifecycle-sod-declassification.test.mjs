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

test('Document Lifecycle: Technical Admin and peer DOCUMENT_OWNER cannot read or modify another owner document (Anti-BOLA)', async () => {
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
          status: 'ACTIVE',
          discoverable: true,
        },
      ],
    ],
    userAttributeAssignments: [
      [1n, { user_id: 1n, attribute_code: 'CLEARANCE_LEVEL', numeric_rank: 4 }],
      [2n, { user_id: 555n, attribute_code: 'CLEARANCE_LEVEL', numeric_rank: 4 }],
      [3n, { user_id: 666n, attribute_code: 'CLEARANCE_LEVEL', numeric_rank: 4 }],
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

  // Even a peer DOCUMENT_OWNER holding global DOCUMENT:MANAGE/CLASSIFY/ARCHIVE/DISCOVER cannot read or modify owner 1's document
  const peerOwnerAuth = createMockAuthorization([
    { userId: 555n, resource: 'DOCUMENT', action: 'MANAGE', scopeDepartmentId: null },
    { userId: 555n, resource: 'DOCUMENT', action: 'CLASSIFY', scopeDepartmentId: null },
    { userId: 555n, resource: 'DOCUMENT', action: 'ARCHIVE', scopeDepartmentId: null },
    { userId: 555n, resource: 'DOCUMENT', action: 'DISCOVER', scopeDepartmentId: null },
  ]);
  const peerService = new DocumentsService(mockAudit, peerOwnerAuth, cache, db);
  const peerOwnerPrincipal = {
    userId: 555n,
    username: 'peer.owner',
    roles: ['DOCUMENT_OWNER'],
    mfa: true,
  };
  const ungrantedReader = {
    userId: 666n,
    username: 'ungranted.reader',
    roles: ['DOCUMENT_READER'],
    mfa: true,
  };

  await assert.rejects(
    peerService.getDocumentById(docId, peerOwnerPrincipal),
    (err) => err.response?.errorCode === 'DOCUMENT_NOT_FOUND',
  );
  await assert.rejects(
    peerService.getDocumentById(docId, ungrantedReader),
    (err) => err.response?.errorCode === 'DOCUMENT_NOT_FOUND',
  );
  await assert.rejects(
    peerService.getDocumentVersions(docId, peerOwnerPrincipal),
    (err) => err.response?.errorCode === 'DOCUMENT_NOT_FOUND',
  );
  await assert.rejects(
    peerService.getClassificationHistory(docId, peerOwnerPrincipal),
    (err) => err.response?.errorCode === 'DOCUMENT_NOT_FOUND',
  );
  await assert.rejects(
    peerService.updateMetadata(docId, { title: 'Peer BOLA edit' }, peerOwnerPrincipal, context),
    (err) => err.response?.errorCode === 'DOCUMENT_ACCESS_DENIED',
  );
  await assert.rejects(
    peerService.archiveDocument(
      docId,
      { reason: 'Peer BOLA archive' },
      peerOwnerPrincipal,
      context,
    ),
    (err) => err.response?.errorCode === 'DOCUMENT_ACCESS_DENIED',
  );
  await assert.rejects(
    peerService.transferOwner(
      docId,
      { newOwnerId: 555n, reason: 'Peer BOLA takeover' },
      peerOwnerPrincipal,
      context,
    ),
    (err) => err.response?.errorCode === 'DOCUMENT_ACCESS_DENIED',
  );

  // Only the legitimate document owner (userId: 1n) may update metadata
  const ownerPrincipal = {
    userId: 1n,
    username: 'true.owner',
    roles: ['DOCUMENT_OWNER'],
    mfa: true,
  };
  const updated = await peerService.updateMetadata(
    docId,
    { title: 'Authorized update by true owner' },
    ownerPrincipal,
    context,
  );
  assert.equal(updated.title, 'Authorized update by true owner');

  // Even after archival, an unauthorized peer must NOT receive 200 idempotent archive detail (no state/metadata leak)
  await peerService.archiveDocument(docId, { reason: 'Owner archived' }, ownerPrincipal, context);
  await assert.rejects(
    peerService.archiveDocument(
      docId,
      { reason: 'Peer probe archived doc' },
      peerOwnerPrincipal,
      context,
    ),
    (err) => err.response?.errorCode === 'DOCUMENT_ACCESS_DENIED',
  );
});

test('Document Lifecycle [CRIT-04]: Downgraded owner cannot reclassify above clearance & non-owner cannot steal ownership', async () => {
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
      [1n, { user_id: 1n, attribute_code: 'CLEARANCE_LEVEL', numeric_rank: 2 }],
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
    { userId: 777n, resource: 'DOCUMENT', action: 'MANAGE', scopeDepartmentId: 100n },
    { userId: 777n, resource: 'DOCUMENT', action: 'ARCHIVE', scopeDepartmentId: 100n },
  ]);
  const deptService = new DocumentsService(mockAudit, deptAuth, cache, db);
  const context = { ip: '127.0.0.1', correlationId: randomUUID() };

  await assert.rejects(
    () =>
      deptService.reclassifyDocument(
        docId,
        { classificationLevelId: 1n, businessCategoryId: 10n, reason: 'Unauthorized downgrade' },
        { userId: 1n, username: 'downgraded.owner', roles: ['DOCUMENT_OWNER'], mfa: true },
        context,
      ),
    (err) => err.response?.errorCode === 'BELL_LAPADULA_CLEARANCE_INSUFFICIENT',
  );

  await assert.rejects(
    () =>
      deptService.transferOwner(
        docId,
        { newOwnerId: 2n, reason: 'Peer role attempting ownership takeover' },
        { userId: 777n, username: 'peer.archiver', roles: ['DOCUMENT_OWNER'], mfa: true },
        context,
      ),
    (err) => err.response?.errorCode === 'DOCUMENT_ACCESS_DENIED',
  );
});
