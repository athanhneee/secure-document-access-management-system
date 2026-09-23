import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';

// ── Contract Tests (Schema validation) ───────────────────────────────────────

import {
  CreateAccessGrantSchema,
  RevokeAccessGrantSchema,
  ListAccessGrantsSchema,
} from '../../../packages/contracts/dist/dto.js';

// ── Test Helpers ─────────────────────────────────────────────────────────────

function validCreateGrant(overrides = {}) {
  const now = new Date();
  const validFrom = new Date(now.getTime() + 3600 * 1000);
  const validUntil = new Date(now.getTime() + 86400 * 1000);
  return {
    documentId: randomUUID(),
    principalType: 'USER',
    principalUserId: '1',
    permissions: ['VIEW'],
    validFrom: validFrom.toISOString(),
    validUntil: validUntil.toISOString(),
    ...overrides,
  };
}

// ── CreateAccessGrantSchema Tests ────────────────────────────────────────────

test('CreateAccessGrantSchema — valid USER grant with VIEW', () => {
  const result = CreateAccessGrantSchema.safeParse(validCreateGrant());
  assert.ok(result.success, `Expected success, got: ${JSON.stringify(result.error?.flatten())}`);
  assert.equal(result.data.principalType, 'USER');
  assert.deepEqual(result.data.permissions, ['VIEW']);
});

test('CreateAccessGrantSchema — valid USER grant with VIEW + DOWNLOAD', () => {
  const result = CreateAccessGrantSchema.safeParse(
    validCreateGrant({ permissions: ['VIEW', 'DOWNLOAD'] }),
  );
  assert.ok(result.success);
  assert.deepEqual(result.data.permissions, ['VIEW', 'DOWNLOAD']);
});

test('CreateAccessGrantSchema — valid ROLE grant', () => {
  const result = CreateAccessGrantSchema.safeParse(
    validCreateGrant({
      principalType: 'ROLE',
      principalUserId: undefined,
      principalRoleId: '5',
    }),
  );
  assert.ok(result.success);
  assert.equal(result.data.principalType, 'ROLE');
  assert.equal(result.data.principalRoleId, 5n);
});

test('CreateAccessGrantSchema — rejects both USER and ROLE principal', () => {
  const result = CreateAccessGrantSchema.safeParse(
    validCreateGrant({
      principalType: 'USER',
      principalUserId: '1',
      principalRoleId: '5',
    }),
  );
  assert.ok(!result.success);
  const issues = result.error.flatten().formErrors;
  assert.ok(
    issues.length > 0 || Object.keys(result.error.flatten().fieldErrors).length > 0,
    'Expected validation errors for dual principal',
  );
});

test('CreateAccessGrantSchema — rejects USER type without principalUserId', () => {
  const result = CreateAccessGrantSchema.safeParse(
    validCreateGrant({ principalUserId: undefined }),
  );
  assert.ok(!result.success);
});

test('CreateAccessGrantSchema — rejects ROLE type without principalRoleId', () => {
  const result = CreateAccessGrantSchema.safeParse(
    validCreateGrant({
      principalType: 'ROLE',
      principalUserId: undefined,
    }),
  );
  assert.ok(!result.success);
});

test('CreateAccessGrantSchema — rejects validUntil before validFrom', () => {
  const now = new Date();
  const result = CreateAccessGrantSchema.safeParse(
    validCreateGrant({
      validFrom: new Date(now.getTime() + 86400 * 1000).toISOString(),
      validUntil: new Date(now.getTime() + 3600 * 1000).toISOString(),
    }),
  );
  assert.ok(!result.success);
  const flat = result.error.flatten();
  const hasTimeError =
    flat.fieldErrors.validUntil?.some((m) => m.includes('after')) ||
    flat.formErrors?.some((m) => m.includes('after'));
  assert.ok(hasTimeError, 'Expected validUntil after validFrom error');
});

test('CreateAccessGrantSchema — rejects validUntil equal to validFrom', () => {
  const ts = new Date().toISOString();
  const result = CreateAccessGrantSchema.safeParse(
    validCreateGrant({ validFrom: ts, validUntil: ts }),
  );
  assert.ok(!result.success);
});

test('CreateAccessGrantSchema — rejects empty permissions array', () => {
  const result = CreateAccessGrantSchema.safeParse(validCreateGrant({ permissions: [] }));
  assert.ok(!result.success);
});

test('CreateAccessGrantSchema — rejects invalid permission', () => {
  const result = CreateAccessGrantSchema.safeParse(validCreateGrant({ permissions: ['SHARE'] }));
  assert.ok(!result.success);
});

test('CreateAccessGrantSchema — rejects invalid documentId', () => {
  const result = CreateAccessGrantSchema.safeParse(validCreateGrant({ documentId: 'not-a-uuid' }));
  assert.ok(!result.success);
});

test('CreateAccessGrantSchema — rejects extra fields (strict mode)', () => {
  const result = CreateAccessGrantSchema.safeParse(validCreateGrant({ extraField: 'should-fail' }));
  assert.ok(!result.success);
});

// ── RevokeAccessGrantSchema Tests ────────────────────────────────────────────

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

// ── ListAccessGrantsSchema Tests ─────────────────────────────────────────────

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

// ── Error Codes Tests ────────────────────────────────────────────────────────

import { AppErrorCode } from '../../../packages/contracts/dist/error-codes.js';

test('AppErrorCode — includes all grant error codes', () => {
  const expectedCodes = [
    'GRANT_NOT_FOUND',
    'GRANT_ALREADY_REVOKED',
    'GRANT_OVERLAP_EXISTS',
    'GRANT_PRINCIPAL_INVALID',
    'GRANT_DOWNLOAD_FORBIDDEN',
    'GRANT_CLEARANCE_INSUFFICIENT',
    'GRANT_ABAC_DENIED',
    'GRANT_CONCURRENCY_CONFLICT',
    'GRANT_DURATION_EXCEEDED',
    'GRANT_TIME_RANGE_INVALID',
    'USER_NOT_ACTIVE',
    'ROLE_NOT_ACTIVE',
  ];

  for (const code of expectedCodes) {
    assert.equal(AppErrorCode[code], code, `Expected AppErrorCode.${code} to equal '${code}'`);
  }
});

// ── Time Boundary Tests ──────────────────────────────────────────────────────

test('CreateAccessGrantSchema — accepts exact ISO 8601 with timezone offset', () => {
  const result = CreateAccessGrantSchema.safeParse(
    validCreateGrant({
      validFrom: '2026-09-23T00:00:00+07:00',
      validUntil: '2026-12-23T00:00:00+07:00',
    }),
  );
  assert.ok(result.success);
});

test('CreateAccessGrantSchema — accepts UTC datetime', () => {
  const result = CreateAccessGrantSchema.safeParse(
    validCreateGrant({
      validFrom: '2026-09-23T00:00:00Z',
      validUntil: '2026-12-23T00:00:00Z',
    }),
  );
  assert.ok(result.success);
});

test('CreateAccessGrantSchema — rejects naive datetime without timezone', () => {
  const result = CreateAccessGrantSchema.safeParse(
    validCreateGrant({
      validFrom: '2026-09-23T00:00:00',
      validUntil: '2026-12-23T00:00:00',
    }),
  );
  assert.ok(!result.success, 'Should reject datetime without timezone offset');
});

// ── VIEW does not imply DOWNLOAD Test ────────────────────────────────────────

test('Grant permissions — VIEW and DOWNLOAD are independent enums', () => {
  // VIEW-only grant
  const viewOnly = CreateAccessGrantSchema.safeParse(validCreateGrant({ permissions: ['VIEW'] }));
  assert.ok(viewOnly.success);
  assert.ok(!viewOnly.data.permissions.includes('DOWNLOAD'));

  // DOWNLOAD-only grant
  const downloadOnly = CreateAccessGrantSchema.safeParse(
    validCreateGrant({ permissions: ['DOWNLOAD'] }),
  );
  assert.ok(downloadOnly.success);
  assert.ok(!downloadOnly.data.permissions.includes('VIEW'));
});

// ── Grant History Preservation Test (Schema Level) ───────────────────────────

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

// ── BigInt Coercion Tests ────────────────────────────────────────────────────

test('CreateAccessGrantSchema — coerces string principalUserId to bigint', () => {
  const result = CreateAccessGrantSchema.safeParse(validCreateGrant({ principalUserId: '42' }));
  assert.ok(result.success);
  assert.equal(result.data.principalUserId, 42n);
});

test('CreateAccessGrantSchema — coerces string principalRoleId to bigint', () => {
  const result = CreateAccessGrantSchema.safeParse(
    validCreateGrant({
      principalType: 'ROLE',
      principalUserId: undefined,
      principalRoleId: '99',
    }),
  );
  assert.ok(result.success);
  assert.equal(result.data.principalRoleId, 99n);
});

test('CreateAccessGrantSchema — rejects non-positive principalUserId', () => {
  const result = CreateAccessGrantSchema.safeParse(validCreateGrant({ principalUserId: '0' }));
  assert.ok(!result.success);
});

test('CreateAccessGrantSchema — rejects negative principalRoleId', () => {
  const result = CreateAccessGrantSchema.safeParse(
    validCreateGrant({
      principalType: 'ROLE',
      principalUserId: undefined,
      principalRoleId: '-1',
    }),
  );
  assert.ok(!result.success);
});

// ── Security Hardening: assertGrantValidForAccess Tests ─────────────────────

import { AccessGrantsService } from '../dist/modules/access-grants/access-grants.service.js';

function createMockServiceForAccess(dbOverrides = {}) {
  const mockAudit = { record: async () => {} };
  const mockAuthz = { hasPermission: async () => true };
  const mockCache = { invalidateUser: async () => {} };
  const mockAbac = { evaluate: async () => ({ decision: 'PERMIT' }) };
  const mockConfig = { get: (key) => (key === 'GRANT_MAX_DURATION_DAYS' ? 30 : 60000) };

  const defaultDb = {
    accessGrant: {
      findUnique: async () => null,
    },
    user: {
      findUnique: async () => ({ status: 'ACTIVE' }),
    },
    userAttributeAssignment: {
      findFirst: async () => ({
        attribute_options: { numeric_rank: 2 },
      }),
    },
    userRole: {
      findFirst: async () => ({ id: 1n }),
    },
  };

  const mockDb = { ...defaultDb, ...dbOverrides };
  return new AccessGrantsService(mockAudit, mockAuthz, mockCache, mockAbac, mockConfig, mockDb);
}

function makeMockGrant(overrides = {}) {
  const now = new Date();
  return {
    id: randomUUID(),
    document_id: randomUUID(),
    principal_type: 'USER',
    principal_user_id: 100n,
    principal_role_id: null,
    status: 'ACTIVE',
    valid_from: new Date(now.getTime() - 3600 * 1000),
    valid_until: new Date(now.getTime() + 3600 * 1000),
    access_grant_permissions: [{ permission: 'VIEW' }, { permission: 'DOWNLOAD' }],
    documents: {
      id: randomUUID(),
      status: 'ACTIVE',
      classification_history: [
        {
          classification_levels: {
            rank: 1,
            allow_download: true,
          },
        },
      ],
    },
    ...overrides,
  };
}

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

  // User 999 tries to use grant issued to User 100
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
            allow_download: false, // Download forbidden by policy
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
            rank: 3, // Requires clearance level 3
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
        attribute_options: { numeric_rank: 1 }, // User only has clearance 1
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
    valid_until: new Date(now.getTime() - 3600 * 1000), // Expired 1 hour ago
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
    valid_from: new Date(now.getTime() + 3600 * 1000), // Valid in 1 hour
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
    userRole: { findFirst: async () => null }, // User does not hold role 10
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
