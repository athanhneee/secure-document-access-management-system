import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import { AppErrorCode } from '../../../packages/contracts/dist/error-codes.js';
import { createMockServiceForAccess, makeMockGrant } from './helpers/access-grants-mocks.mjs';

test('assertGrantValidForAccess — permits valid user with VIEW permission', async () => {
  const grant = makeMockGrant();
  const service = createMockServiceForAccess({
    accessGrant: { findUnique: async () => grant },
  });

  const result = await service.assertGrantValidForAccess(grant.id, 100n, 'VIEW');
  assert.equal(result.grant.id, grant.id);
  assert.equal(result.documentRank, 1);
});

test('assertGrantValidForAccess [SECURITY] — IDOR protection: rejects when userId does not match grant principalUserId', async () => {
  const grant = makeMockGrant({ principal_user_id: 100n });
  const service = createMockServiceForAccess({
    accessGrant: { findUnique: async () => grant },
  });

  await assert.rejects(
    async () => {
      await service.assertGrantValidForAccess(grant.id, 999n, 'VIEW');
    },
    (err) => {
      assert.equal(err.response?.errorCode, AppErrorCode.DOCUMENT_ACCESS_DENIED);
      return true;
    },
  );
});

test('assertGrantValidForAccess [SECURITY] — rejects when document status is not ACTIVE (ARCHIVED)', async () => {
  const grant = makeMockGrant({
    documents: {
      id: randomUUID(),
      status: 'ARCHIVED',
      classification_history: [{ classification_levels: { rank: 1, allow_download: true } }],
    },
  });
  const service = createMockServiceForAccess({
    accessGrant: { findUnique: async () => grant },
  });

  await assert.rejects(
    async () => {
      await service.assertGrantValidForAccess(grant.id, 100n, 'VIEW');
    },
    (err) => {
      assert.equal(err.response?.errorCode, AppErrorCode.DOCUMENT_ACCESS_DENIED);
      return true;
    },
  );
});

test('assertGrantValidForAccess [SECURITY] — rejects DOWNLOAD when classification forbids download', async () => {
  const grant = makeMockGrant({
    documents: {
      id: randomUUID(),
      status: 'ACTIVE',
      classification_history: [
        {
          classification_levels: {
            rank: 1,
            allow_download: false,
          },
        },
      ],
    },
  });
  const service = createMockServiceForAccess({
    accessGrant: { findUnique: async () => grant },
  });

  await assert.rejects(
    async () => {
      await service.assertGrantValidForAccess(grant.id, 100n, 'DOWNLOAD');
    },
    (err) => {
      assert.equal(err.response?.errorCode, AppErrorCode.GRANT_DOWNLOAD_FORBIDDEN);
      return true;
    },
  );
});

test('assertGrantValidForAccess [SECURITY] — rejects when user clearance is lower than document rank', async () => {
  const grant = makeMockGrant({
    documents: {
      id: randomUUID(),
      status: 'ACTIVE',
      classification_history: [
        {
          classification_levels: {
            rank: 3,
            allow_download: true,
          },
        },
      ],
    },
  });
  const service = createMockServiceForAccess({
    accessGrant: { findUnique: async () => grant },
    userAttributeAssignment: {
      findFirst: async () => ({
        attribute_options: { numeric_rank: 1 },
      }),
    },
  });

  await assert.rejects(
    async () => {
      await service.assertGrantValidForAccess(grant.id, 100n, 'VIEW');
    },
    (err) => {
      assert.equal(err.response?.errorCode, AppErrorCode.CLEARANCE_INSUFFICIENT);
      return true;
    },
  );
});

test('assertGrantValidForAccess [SECURITY] — rejects when grant is REVOKED', async () => {
  const grant = makeMockGrant({ status: 'REVOKED' });
  const service = createMockServiceForAccess({
    accessGrant: { findUnique: async () => grant },
  });

  await assert.rejects(
    async () => {
      await service.assertGrantValidForAccess(grant.id, 100n, 'VIEW');
    },
    (err) => {
      assert.equal(err.response?.errorCode, AppErrorCode.GRANT_REVOKED);
      return true;
    },
  );
});

test('assertGrantValidForAccess [SECURITY] — rejects when grant has EXPIRED past valid_until', async () => {
  const now = new Date();
  const grant = makeMockGrant({
    valid_from: new Date(now.getTime() - 7200 * 1000),
    valid_until: new Date(now.getTime() - 3600 * 1000),
  });
  const service = createMockServiceForAccess({
    accessGrant: { findUnique: async () => grant },
  });

  await assert.rejects(
    async () => {
      await service.assertGrantValidForAccess(grant.id, 100n, 'VIEW');
    },
    (err) => {
      assert.equal(err.response?.errorCode, AppErrorCode.GRANT_EXPIRED);
      return true;
    },
  );
});

test('assertGrantValidForAccess [SECURITY] — rejects when grant is not yet valid (future valid_from)', async () => {
  const now = new Date();
  const grant = makeMockGrant({
    valid_from: new Date(now.getTime() + 3600 * 1000),
    valid_until: new Date(now.getTime() + 7200 * 1000),
  });
  const service = createMockServiceForAccess({
    accessGrant: { findUnique: async () => grant },
  });

  await assert.rejects(
    async () => {
      await service.assertGrantValidForAccess(grant.id, 100n, 'VIEW');
    },
    (err) => {
      assert.equal(err.response?.errorCode, AppErrorCode.GRANT_EXPIRED);
      return true;
    },
  );
});

test('assertGrantValidForAccess [SECURITY] — rejects when user account is not ACTIVE', async () => {
  const grant = makeMockGrant();
  const service = createMockServiceForAccess({
    accessGrant: { findUnique: async () => grant },
    user: { findUnique: async () => ({ status: 'SUSPENDED' }) },
  });

  await assert.rejects(
    async () => {
      await service.assertGrantValidForAccess(grant.id, 100n, 'VIEW');
    },
    (err) => {
      assert.equal(err.response?.errorCode, AppErrorCode.USER_NOT_ACTIVE);
      return true;
    },
  );
});

test('assertGrantValidForAccess [SECURITY] — role grant rejects when user does not hold the active role', async () => {
  const grant = makeMockGrant({
    principal_type: 'ROLE',
    principal_user_id: null,
    principal_role_id: 10n,
  });
  const service = createMockServiceForAccess({
    accessGrant: { findUnique: async () => grant },
    userRole: { findFirst: async () => null },
  });

  await assert.rejects(
    async () => {
      await service.assertGrantValidForAccess(grant.id, 100n, 'VIEW');
    },
    (err) => {
      assert.equal(err.response?.errorCode, AppErrorCode.DOCUMENT_ACCESS_DENIED);
      return true;
    },
  );
});
