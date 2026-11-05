import 'reflect-metadata';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { Readable } from 'node:stream';
import { test } from 'node:test';
import { ForbiddenException } from '@nestjs/common';
import { AppErrorCode } from '@sda/contracts';
import {
  getUserClearanceRank,
  isPureTechnicalOrAuditRole,
} from '../dist/modules/documents/document-access-guard.helper.js';
import { isRestrictedNonBusinessRole } from '../dist/modules/documents/pep-context-builder.js';
import { checkUserClearance } from '../dist/modules/documents/pep-clearance.helper.js';
import { executeTransferDocumentOwner } from '../dist/modules/documents/document-ownership.helper.js';
import { validateIngestionPreconditions } from '../dist/modules/documents/ingestion-validation.helper.js';
import { validateGrantTargetAndSod } from '../dist/modules/access-grants/grant-target-sod.helper.js';
import { fetchUserClearanceRank } from '../dist/modules/access-grants/grant-pip.helper.js';
import { verifyGrantValidForAccess } from '../dist/modules/access-grants/grant-enforcement.helper.js';
import { validateCreateAccessRequestPreconditions } from '../dist/modules/access-requests/access-request-validation.helper.js';

test('[CRITICAL-04] SoD blocks stacked privileged + business roles and enforces SECURITY_OFFICER exclusions everywhere', async () => {
  for (const roles of [
    ['SYSTEM_ADMIN', 'DOCUMENT_READER'],
    ['AUDITOR', 'DOCUMENT_OWNER'],
    ['SECURITY_OFFICER'],
    ['SECURITY_OFFICER', 'DOCUMENT_OWNER'],
  ]) {
    assert.equal(
      isPureTechnicalOrAuditRole({
        userId: 1n,
        sessionId: 's',
        username: 'u',
        roles,
        mfa: true,
      }),
      true,
    );
    assert.equal(isRestrictedNonBusinessRole(roles), true);
  }
  assert.equal(isRestrictedNonBusinessRole(['DOCUMENT_OWNER', 'DOCUMENT_READER']), false);

  const now = new Date();
  const sodDb = {
    user: { findUnique: async () => ({ id: 2n, status: 'ACTIVE' }) },
    userRole: {
      findMany: async () => [
        { roles: { code: 'SYSTEM_ADMIN' } },
        { roles: { code: 'DOCUMENT_READER' } },
      ],
    },
    role: { findUnique: async () => ({ id: 9n, code: 'SECURITY_OFFICER', is_active: true }) },
  };
  await assert.rejects(
    validateGrantTargetAndSod(
      sodDb,
      {
        documentId: randomUUID(),
        principalType: 'USER',
        principalUserId: 2n,
        permissions: ['VIEW'],
        validFrom: now.toISOString(),
        validUntil: now.toISOString(),
      },
      now,
    ),
    ForbiddenException,
  );
  await assert.rejects(
    validateGrantTargetAndSod(
      sodDb,
      {
        documentId: randomUUID(),
        principalType: 'ROLE',
        principalRoleId: 9n,
        permissions: ['VIEW'],
        validFrom: now.toISOString(),
        validUntil: now.toISOString(),
      },
      now,
    ),
    ForbiddenException,
  );

  await assert.rejects(
    executeTransferDocumentOwner({
      database: {
        document: {
          findUnique: async () => ({
            id: 'doc-1',
            owner_id: 1n,
            department_id: 10n,
            status: 'ACTIVE',
          }),
        },
        user: { findUnique: async () => ({ id: 5n, status: 'ACTIVE' }) },
        documentClassificationHistory: {
          findFirst: async () => ({ classification_levels: { rank: 1 } }),
        },
        userRole: {
          findMany: async () => [
            { roles: { code: 'SECURITY_OFFICER' } },
            { roles: { code: 'DOCUMENT_OWNER' } },
          ],
        },
      },
      authorization: { hasPermission: async () => true },
      cache: { invalidateUser: () => undefined },
      audit: { record: async () => undefined },
      documentId: 'doc-1',
      input: { newOwnerId: 5n, reason: 'Transfer attempt' },
      principal: {
        userId: 1n,
        sessionId: 's',
        username: 'owner',
        roles: ['DOCUMENT_OWNER'],
        mfa: true,
      },
      context: { ip: '127.0.0.1', correlationId: randomUUID() },
    }),
    (err) => err.response?.errorCode === AppErrorCode.TECHNICAL_ADMIN_CANNOT_OWN,
  );

  await assert.rejects(
    validateIngestionPreconditions(
      {
        fileStream: Readable.from([Buffer.from('test')]),
        rawFilename: 'doc.pdf',
        declaredMime: 'application/pdf',
        principal: {
          userId: 6n,
          sessionId: 's',
          username: 'sec',
          roles: ['SECURITY_OFFICER', 'DOCUMENT_OWNER'],
          mfa: true,
        },
        context: { ip: '127.0.0.1', correlationId: randomUUID() },
      },
      {},
    ),
    (err) => err.response?.errorCode === AppErrorCode.TECHNICAL_ADMIN_CANNOT_OWN,
  );
});

test('[CRITICAL-05] Deactivated CLEARANCE_LEVEL definition or option (is_active = false) denies clearance across PIP, PEP, Grants, and Access Requests', async () => {
  const now = new Date();
  const capturedWheres = [];
  const makeClearanceDb = (row) => ({
    userAttributeAssignment: {
      findFirst: async ({ where }) => {
        capturedWheres.push(where);
        return row;
      },
    },
    accessGrant: {
      findUnique: async () => ({
        id: 'grant-1',
        document_id: 'doc-1',
        principal_type: 'USER',
        principal_user_id: 10n,
        status: 'ACTIVE',
        valid_from: new Date(now.getTime() - 60_000),
        valid_until: new Date(now.getTime() + 60_000),
        access_grant_permissions: [{ permission: 'VIEW' }],
        documents: {
          status: 'ACTIVE',
          classification_history: [{ classification_levels: { rank: 2, allow_download: true } }],
        },
      }),
    },
    user: { findUnique: async () => ({ id: 10n, status: 'ACTIVE' }) },
    document: {
      findUnique: async () => ({
        id: 'doc-1',
        owner_id: 1n,
        status: 'ACTIVE',
        discoverable: true,
        classification_history: [{ classification_levels: { rank: 2, allow_download: true } }],
      }),
    },
    accessRequest: { findFirst: async () => null },
  });

  const inactiveOptionDb = makeClearanceDb({
    attribute_definitions: { is_active: true },
    attribute_options: { numeric_rank: 4, is_active: false },
  });
  const inactiveDefDb = makeClearanceDb({
    attribute_definitions: { is_active: false },
    attribute_options: { numeric_rank: 4, is_active: true },
  });

  assert.equal(await fetchUserClearanceRank(inactiveOptionDb, 10n, now), null);
  assert.equal(await fetchUserClearanceRank(inactiveDefDb, 10n, now), null);
  assert.equal(await getUserClearanceRank(inactiveOptionDb, 10n, now), 0);
  assert.equal(await checkUserClearance(inactiveOptionDb, 10n, 1, now), false);

  await assert.rejects(
    verifyGrantValidForAccess(inactiveOptionDb, 'grant-1', 10n, 'VIEW', now, 'doc-1'),
    (err) => err.response?.errorCode === AppErrorCode.CLEARANCE_INSUFFICIENT,
  );
  await assert.rejects(
    validateCreateAccessRequestPreconditions(
      inactiveOptionDb,
      { documentId: 'doc-1', requestedAction: 'VIEW', reason: 'Need read' },
      { userId: 10n, sessionId: 's', username: 'reader', roles: ['DOCUMENT_READER'], mfa: true },
      now,
    ),
    (err) => err.response?.errorCode === AppErrorCode.CLEARANCE_INSUFFICIENT,
  );

  for (const where of capturedWheres) {
    assert.equal(where.attribute_definitions?.is_active, true);
    assert.equal(where.attribute_options?.is_active, true);
  }
});
