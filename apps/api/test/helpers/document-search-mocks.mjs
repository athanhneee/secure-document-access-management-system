// @ts-check
import { mock } from 'node:test';

/** @typedef {{ id: string; document_code: string; title: string; description: string | null; status: string; owner_id: bigint; department_id: bigint; discoverable: boolean; created_at: Date; updated_at: Date }} MockDoc */

/** @type {MockDoc[]} */
export const MOCK_DOCUMENTS = [
  {
    id: 'aaaa-1111-0000-0000',
    document_code: 'DOC-001',
    title: 'Báo cáo tài chính quý 3',
    description: 'Báo cáo chi tiết tài chính nội bộ',
    status: 'ACTIVE',
    owner_id: 10n,
    department_id: 1n,
    discoverable: true,
    created_at: new Date('2026-01-10T00:00:00Z'),
    updated_at: new Date('2026-01-10T00:00:00Z'),
  },
  {
    id: 'bbbb-2222-0000-0000',
    document_code: 'DOC-002',
    title: 'Chiến lược kinh doanh mật',
    description: 'Kế hoạch mở rộng thị trường',
    status: 'ACTIVE',
    owner_id: 20n,
    department_id: 2n,
    discoverable: true,
    created_at: new Date('2026-02-15T00:00:00Z'),
    updated_at: new Date('2026-02-15T00:00:00Z'),
  },
  {
    id: 'cccc-3333-0000-0000',
    document_code: 'DOC-003',
    title: 'Draft nội bộ R&D',
    description: 'Tài liệu draft chưa active',
    status: 'DRAFT',
    owner_id: 10n,
    department_id: 1n,
    discoverable: false,
    created_at: new Date('2026-03-01T00:00:00Z'),
    updated_at: new Date('2026-03-01T00:00:00Z'),
  },
  {
    id: 'dddd-4444-0000-0000',
    document_code: 'DOC-004',
    title: 'Hồ sơ nhân sự tối mật',
    description: 'Danh sách lương nhân viên',
    status: 'ACTIVE',
    owner_id: 30n,
    department_id: 3n,
    discoverable: true,
    created_at: new Date('2026-04-01T00:00:00Z'),
    updated_at: new Date('2026-04-01T00:00:00Z'),
  },
];

export const MOCK_GRANTS = [
  {
    id: 'grant-1',
    document_id: 'bbbb-2222-0000-0000',
    principal_type: 'USER',
    principal_user_id: 10n,
    principal_role_id: null,
    status: 'ACTIVE',
    valid_from: new Date('2026-01-01'),
    valid_until: new Date('2027-01-01'),
    granted_at: new Date('2026-01-01'),
  },
  {
    id: 'grant-2',
    document_id: 'dddd-4444-0000-0000',
    principal_type: 'USER',
    principal_user_id: 10n,
    principal_role_id: null,
    status: 'REVOKED',
    valid_from: new Date('2026-01-01'),
    valid_until: new Date('2027-01-01'),
    granted_at: new Date('2026-01-01'),
  },
];

/** @type {import('../../src/modules/auth/auth.types.js').AuthPrincipal} */
export const READER_PRINCIPAL = {
  userId: 10n,
  sessionId: 'session-reader',
  username: 'reader',
  roles: ['DOCUMENT_READER'],
  mfa: false,
};

/** @type {import('../../src/modules/auth/auth.types.js').AuthPrincipal} */
export const NO_DISCOVER_PRINCIPAL = {
  userId: 99n,
  sessionId: 'session-nobody',
  username: 'nobody',
  roles: [],
  mfa: false,
};

/** @type {import('../../src/modules/auth/auth.types.js').RequestContext} */
export const TEST_CONTEXT = {
  ip: '127.0.0.1',
  correlationId: '00000000-0000-0000-0000-000000000001',
};

/**
 * Build a DocumentSearchService with fully mocked dependencies.
 * @param {object} options
 * @param {bigint[] | null} [options.discoverableDeptIds]
 * @param {{ roleId: bigint }[]} [options.effectiveGrants]
 * @param {typeof MOCK_GRANTS} [options.grants]
 */
export async function buildService(options = {}) {
  const discoverableDeptIds =
    options.discoverableDeptIds !== undefined ? options.discoverableDeptIds : null;
  const effectiveGrants = options.effectiveGrants || [];
  const grants = options.grants || MOCK_GRANTS;

  /** @type {string[]} */
  const capturedQueries = [];
  /** @type {Array<import('../../src/modules/documents/document-audit.service.js').DocumentAuditEvent>} */
  const capturedAudits = [];

  const mockDatabase = {
    $queryRaw: mock.fn(async (/** @type {any} */ templateOrSql) => {
      const queryStr =
        typeof templateOrSql === 'string'
          ? templateOrSql
          : templateOrSql?.strings
            ? templateOrSql.strings.join('?')
            : JSON.stringify(templateOrSql);
      capturedQueries.push(queryStr);

      if (queryStr.includes('FROM documents d')) {
        return MOCK_DOCUMENTS.filter((doc) => {
          if (doc.owner_id === BigInt(READER_PRINCIPAL.userId)) return true;
          if (discoverableDeptIds === null && doc.discoverable && doc.status === 'ACTIVE')
            return true;
          if (
            Array.isArray(discoverableDeptIds) &&
            discoverableDeptIds.includes(doc.department_id) &&
            doc.discoverable &&
            doc.status === 'ACTIVE'
          )
            return true;
          return grants.some(
            (g) =>
              g.document_id === doc.id &&
              g.principal_user_id === READER_PRINCIPAL.userId &&
              g.status === 'ACTIVE' &&
              g.valid_from <= new Date() &&
              g.valid_until > new Date(),
          );
        }).map((doc) => ({
          id: doc.id,
          document_code: doc.document_code,
          title: doc.title,
          description: doc.description,
          status: doc.status,
          department_name: `Dept-${doc.department_id}`,
          classification_level_name: 'CONFIDENTIAL',
          classification_level_code: 'CFD',
          created_at: doc.created_at,
          updated_at: doc.updated_at,
        }));
      }

      if (queryStr.includes('FROM access_grants ag')) {
        return grants
          .filter((g) => g.principal_user_id === READER_PRINCIPAL.userId)
          .map((g) => ({
            grant_id: g.id,
            grant_status: g.status,
            valid_from: g.valid_from,
            valid_until: g.valid_until,
            granted_at: g.granted_at,
            doc_id: g.document_id,
            doc_code: `DOC-${g.document_id.slice(0, 4)}`,
            doc_title: MOCK_DOCUMENTS.find((d) => d.id === g.document_id)?.title ?? 'Unknown',
            doc_status: 'ACTIVE',
            cl_name: 'CONFIDENTIAL',
          }));
      }

      if (queryStr.includes('FROM access_grant_permissions')) {
        return [
          { access_grant_id: 'grant-1', permission: 'VIEW' },
          { access_grant_id: 'grant-2', permission: 'VIEW' },
        ];
      }

      return [];
    }),
  };

  const mockAuthorization = {
    visibleDepartmentIds: mock.fn(async () => discoverableDeptIds),
    effectiveGrants: mock.fn(async () => effectiveGrants),
  };

  const mockAudit = {
    record: mock.fn(async (/** @type {any} */ event) => {
      capturedAudits.push(event);
    }),
  };

  const { DocumentSearchService } =
    await import('../../dist/modules/documents/document-search.service.js');

  const service = new DocumentSearchService(
    /** @type {any} */ (mockAuthorization),
    /** @type {any} */ (mockAudit),
  );
  Object.assign(service, { database: mockDatabase });

  return { service, capturedQueries, capturedAudits, mockDatabase, mockAuthorization };
}
