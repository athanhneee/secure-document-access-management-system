import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import { createDocumentsTestService } from './helpers/document-lifecycle-mocks.mjs';

test('Document Lifecycle: SCD Type 2 classification history preserves past rows and maintains exactly 1 active row', async () => {
  const docId = randomUUID();
  const { service } = createDocumentsTestService({
    documents: [
      [
        docId,
        {
          id: docId,
          document_code: 'DOC-SCD2',
          title: 'SCD2 Test Document',
          owner_id: 1n,
          department_id: 100n,
          status: 'DRAFT',
        },
      ],
    ],
    userAttributeAssignments: [
      [
        10n,
        {
          user_id: 1n,
          attribute_code: 'CLEARANCE_LEVEL',
          numeric_rank: 4,
        },
      ],
    ],
  });

  const principal = { userId: 1n, username: 'owner_user', roles: ['DOCUMENT_OWNER'], mfa: true };
  const context = { ip: '127.0.0.1', correlationId: randomUUID() };

  await service.reclassifyDocument(
    docId,
    { classificationLevelId: 1n, businessCategoryId: 10n, reason: 'Initial classification' },
    principal,
    context,
  );

  await service.reclassifyDocument(
    docId,
    { classificationLevelId: 2n, businessCategoryId: 10n, reason: 'Promoted to Confidential' },
    principal,
    context,
  );

  await service.reclassifyDocument(
    docId,
    { classificationLevelId: 3n, businessCategoryId: 20n, reason: 'Escalated to Secret' },
    principal,
    context,
  );

  const history = await service.getClassificationHistory(docId, principal);
  assert.equal(history.length, 3, 'All 3 classification rows are preserved');

  const activeRows = history.filter((h) => h.effectiveTo === null);
  assert.equal(activeRows.length, 1, 'Exactly 1 active row at any time');
  assert.equal(activeRows[0].classificationLevelCode, 'SECRET');
  assert.equal(activeRows[0].rank, 3);

  assert.ok(history[0].effectiveTo !== null);
  assert.equal(history[0].classificationLevelCode, 'INTERNAL');
  assert.ok(history[1].effectiveTo !== null);
  assert.equal(history[1].classificationLevelCode, 'CONFIDENTIAL');
});

test('Document Lifecycle: Reclassification to higher level revokes insufficient user grants and terminates sessions', async () => {
  const docId = randomUUID();
  const grantUserLowId = randomUUID();
  const grantUserHighId = randomUUID();
  const sessionLowId = randomUUID();
  const sessionHighId = randomUUID();

  const { db, accessGrants, accessSessions, service } = createDocumentsTestService({
    documents: [
      [
        docId,
        {
          id: docId,
          document_code: 'DOC-RECLASS',
          title: 'Reclassification security test',
          owner_id: 1n,
          department_id: 100n,
          status: 'ACTIVE',
        },
      ],
    ],
    userAttributeAssignments: [
      [
        0n,
        {
          user_id: 1n,
          attribute_code: 'CLEARANCE_LEVEL',
          numeric_rank: 4,
        },
      ],
      [
        1n,
        {
          user_id: 3n,
          attribute_code: 'CLEARANCE_LEVEL',
          numeric_rank: 1,
        },
      ],
      [
        2n,
        {
          user_id: 4n,
          attribute_code: 'CLEARANCE_LEVEL',
          numeric_rank: 4,
        },
      ],
    ],
    accessGrants: [
      [
        grantUserLowId,
        {
          id: grantUserLowId,
          document_id: docId,
          principal_type: 'USER',
          principal_user_id: 3n,
          status: 'ACTIVE',
        },
      ],
      [
        grantUserHighId,
        {
          id: grantUserHighId,
          document_id: docId,
          principal_type: 'USER',
          principal_user_id: 4n,
          status: 'ACTIVE',
        },
      ],
    ],
    accessSessions: [
      [
        sessionLowId,
        {
          id: sessionLowId,
          access_grant_id: grantUserLowId,
          document_version_id: 100n,
          user_id: 3n,
          status: 'ACTIVE',
        },
      ],
      [
        sessionHighId,
        {
          id: sessionHighId,
          access_grant_id: grantUserHighId,
          document_version_id: 100n,
          user_id: 4n,
          status: 'ACTIVE',
        },
      ],
    ],
  });

  db.documentClassificationHistory.create({
    data: {
      document_id: docId,
      classification_level_id: 1n,
      business_category_id: 10n,
      reason: 'Initial',
      classified_by: 1n,
      effective_from: new Date(),
      effective_to: null,
    },
  });

  const principal = { userId: 1n, username: 'owner_user', roles: ['DOCUMENT_OWNER'], mfa: true };
  const context = { ip: '127.0.0.1', correlationId: randomUUID() };

  await service.reclassifyDocument(
    docId,
    { classificationLevelId: 3n, businessCategoryId: 10n, reason: 'Escalation to SECRET' },
    principal,
    context,
  );

  const lowGrant = accessGrants.get(grantUserLowId);
  assert.equal(lowGrant.status, 'REVOKED');
  assert.match(lowGrant.revoke_reason, /clearance insufficient/i);

  const lowSession = accessSessions.get(sessionLowId);
  assert.equal(lowSession.status, 'TERMINATED');

  const highGrant = accessGrants.get(grantUserHighId);
  assert.equal(highGrant.status, 'ACTIVE');

  const highSession = accessSessions.get(sessionHighId);
  assert.equal(highSession.status, 'ACTIVE');
});

test('Document Lifecycle [CRIT-04]: Actor with lower clearance cannot upgrade document above own clearance', async () => {
  const docId = randomUUID();
  const { db, service } = createDocumentsTestService({
    documents: [
      [
        docId,
        {
          id: docId,
          document_code: 'DOC-BLP-UPGRADE',
          title: 'Bell-LaPadula upgrade guard test',
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
          numeric_rank: 2,
        },
      ],
    ],
  });

  await db.documentClassificationHistory.create({
    data: {
      document_id: docId,
      classification_level_id: 1n,
      business_category_id: 10n,
      reason: 'Initial Internal',
      classified_by: 1n,
      effective_from: new Date(),
      effective_to: null,
    },
  });

  const lowClearedOwner = {
    userId: 1n,
    username: 'owner_rank2',
    roles: ['DOCUMENT_OWNER'],
    mfa: true,
  };
  const context = { ip: '127.0.0.1', correlationId: randomUUID() };

  await assert.rejects(
    () =>
      service.reclassifyDocument(
        docId,
        {
          classificationLevelId: 3n,
          businessCategoryId: 10n,
          reason: 'Attempt escalation to Secret',
        },
        lowClearedOwner,
        context,
      ),
    (err) => err.response?.errorCode === 'BELL_LAPADULA_CLEARANCE_INSUFFICIENT',
  );
});
