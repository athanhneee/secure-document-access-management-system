import { randomUUID } from 'node:crypto';
import { AccessGrantsService } from '../../dist/modules/access-grants/access-grants.service.js';

export function validCreateGrant(overrides = {}) {
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

export function createMockServiceForAccess(dbOverrides = {}) {
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

export function makeMockGrant(overrides = {}) {
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
