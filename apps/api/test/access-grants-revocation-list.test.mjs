import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import {
  RevokeAccessGrantSchema,
  ListAccessGrantsSchema,
} from '../../../packages/contracts/dist/dto.js';
import { AccessGrantsService } from '../dist/modules/access-grants/access-grants.service.js';

test('RevokeAccessGrantSchema — valid revocation with reason', () => {
  const result = RevokeAccessGrantSchema.safeParse({
    reason: 'User no longer needs access to this document.',
  });
  assert.ok(result.success);
  assert.equal(result.data.reason, 'User no longer needs access to this document.');
});

test('RevokeAccessGrantSchema — valid revocation with expectedVersion', () => {
  const result = RevokeAccessGrantSchema.safeParse({
    reason: 'Access revoked due to role change.',
    expectedVersion: 3,
  });
  assert.ok(result.success);
  assert.equal(result.data.expectedVersion, 3);
});

test('RevokeAccessGrantSchema — rejects reason shorter than 10 chars', () => {
  const result = RevokeAccessGrantSchema.safeParse({ reason: 'short' });
  assert.ok(!result.success);
});

test('RevokeAccessGrantSchema — trims whitespace from reason', () => {
  const result = RevokeAccessGrantSchema.safeParse({
    reason: '   This is a valid reason with sufficient length.   ',
  });
  assert.ok(result.success);
  assert.equal(result.data.reason, 'This is a valid reason with sufficient length.');
});

test('RevokeAccessGrantSchema — rejects empty reason', () => {
  const result = RevokeAccessGrantSchema.safeParse({ reason: '' });
  assert.ok(!result.success);
});

test('RevokeAccessGrantSchema — rejects missing reason', () => {
  const result = RevokeAccessGrantSchema.safeParse({});
  assert.ok(!result.success);
});

test('ListAccessGrantsSchema — valid with defaults', () => {
  const result = ListAccessGrantsSchema.safeParse({});
  assert.ok(result.success);
  assert.equal(result.data.sort, 'granted_at');
  assert.equal(result.data.order, 'desc');
  assert.equal(result.data.page, 1);
  assert.equal(result.data.pageSize, 20);
});

test('ListAccessGrantsSchema — valid with all filters', () => {
  const docId = randomUUID();
  const result = ListAccessGrantsSchema.safeParse({
    documentId: docId,
    status: 'REVOKED',
    principalType: 'ROLE',
    sort: 'valid_until',
    order: 'asc',
    page: '3',
    pageSize: '10',
  });
  assert.ok(result.success);
  assert.equal(result.data.documentId, docId);
  assert.equal(result.data.status, 'REVOKED');
  assert.equal(result.data.principalType, 'ROLE');
  assert.equal(result.data.page, 3);
  assert.equal(result.data.pageSize, 10);
});

test('ListAccessGrantsSchema — rejects pageSize > 50', () => {
  const result = ListAccessGrantsSchema.safeParse({ pageSize: '100' });
  assert.ok(!result.success);
});

test('ListAccessGrantsSchema — rejects invalid status', () => {
  const result = ListAccessGrantsSchema.safeParse({ status: 'INVALID' });
  assert.ok(!result.success);
});

test('ListAccessGrantsSchema — rejects invalid sort field', () => {
  const result = ListAccessGrantsSchema.safeParse({ sort: 'created_at' });
  assert.ok(!result.success);
});

test('ListAccessGrantsSchema — can filter by REVOKED status to see history', () => {
  const result = ListAccessGrantsSchema.safeParse({ status: 'REVOKED' });
  assert.ok(result.success);
  assert.equal(result.data.status, 'REVOKED');
});

test('ListAccessGrantsSchema — can filter by EXPIRED status to see history', () => {
  const result = ListAccessGrantsSchema.safeParse({ status: 'EXPIRED' });
  assert.ok(result.success);
  assert.equal(result.data.status, 'EXPIRED');
});

test('ListAccessGrantsSchema — can filter by SUSPENDED status', () => {
  const result = ListAccessGrantsSchema.safeParse({ status: 'SUSPENDED' });
  assert.ok(result.success);
  assert.equal(result.data.status, 'SUSPENDED');
});

test('createGrant — when extending existing grant with accessRequestId, updates request to APPROVED and records decision', async () => {
  const docId = randomUUID();
  const grantId = randomUUID();
  const reqId = randomUUID();
  const userId = 50n;
  const now = new Date();

  let updatedRequestStatus = '';
  let createdDecision = null;

  const existingGrant = {
    id: grantId,
    document_id: docId,
    principal_type: 'USER',
    principal_user_id: userId,
    principal_role_id: null,
    source: 'DIRECT',
    access_request_id: null,
    valid_from: now,
    valid_until: new Date(now.getTime() + 7 * 86400000),
    status: 'ACTIVE',
    granted_by: 1n,
    granted_at: now,
    revoked_by: null,
    revoked_at: null,
    revoke_reason: null,
    version: 0,
    access_grant_permissions: [{ permission: 'VIEW' }],
  };

  const mockDb = {
    document: {
      findUnique: async () => ({
        id: docId,
        owner_id: 1n,
        department_id: 10n,
        status: 'ACTIVE',
        classification_history: [
          {
            classification_levels: { rank: 2, allow_download: true },
          },
        ],
      }),
    },
    user: {
      findUnique: async () => ({ id: userId, status: 'ACTIVE' }),
    },
    userAttributeAssignment: {
      findFirst: async () => ({
        attribute_options: { numeric_rank: 3 },
      }),
    },
    accessGrant: {
      findFirst: async () => existingGrant,
      update: async () => existingGrant,
      findUnique: async () => existingGrant,
    },
    accessRequest: {
      update: async ({ data }) => {
        updatedRequestStatus = data.status;
      },
    },
    accessRequestDecision: {
      create: async ({ data }) => {
        createdDecision = data;
      },
    },
    $executeRawUnsafe: async () => {},
    $transaction: async (fn) => fn(mockDb),
  };

  const mockAudit = { record: async () => {} };
  const mockAuth = { hasPermission: async () => true };
  const mockCache = { invalidateUser: () => {} };
  const mockAbac = { evaluate: async () => ({ decision: 'PERMIT' }) };
  const mockConfig = { get: () => 365 };

  const service = new AccessGrantsService(
    mockAudit,
    mockAuth,
    mockCache,
    mockAbac,
    mockConfig,
    mockDb,
  );

  const principal = { userId: 1n, username: 'owner1', roles: ['DOCUMENT_OWNER'], mfa: true };
  const context = { ip: '127.0.0.1' };

  await service.createGrant(
    {
      documentId: docId,
      principalType: 'USER',
      principalUserId: userId,
      permissions: ['VIEW'],
      validFrom: now.toISOString(),
      validUntil: new Date(now.getTime() + 14 * 86400000).toISOString(),
      accessRequestId: reqId,
    },
    principal,
    context,
  );

  assert.equal(updatedRequestStatus, 'APPROVED');
  assert.ok(createdDecision);
  assert.equal(createdDecision.access_request_id, reqId);
  assert.equal(createdDecision.decision, 'APPROVED');
});
