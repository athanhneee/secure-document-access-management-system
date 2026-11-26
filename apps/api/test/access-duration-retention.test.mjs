import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { describe, it } from 'node:test';
import {
  AppErrorCode,
  DEFAULT_GRANT_MAX_DURATION_DAYS,
  DecideAccessRequestSchema,
} from '../../../packages/contracts/dist/index.js';
import { AccessRequestsService } from '../dist/modules/access-requests/access-requests.service.js';
import { AccessGrantsService } from '../dist/modules/access-grants/access-grants.service.js';
import { buildService, READER_PRINCIPAL, TEST_CONTEXT } from './helpers/document-search-mocks.mjs';

/**
 * Thuật toán: Kiểm Chứng Toàn Diện Ràng Buộc Trần Thời Hạn 30 Ngày, `retention_until`, `default_view_days` & Ngữ Cảnh Quyền Hiện Hành Phía API (`access-duration-retention`).
 */
describe('Access Request & Grant Retention Ceiling, 30-Day Sync & default_view_days', () => {
  const readerPrincipal = {
    userId: 10n,
    sessionId: 's-reader',
    username: 'reader.qa',
    roles: ['DOCUMENT_READER'],
    mfa: false,
  };
  const ownerPrincipal = {
    userId: 5n,
    sessionId: 's-owner',
    username: 'owner.qa',
    roles: ['DOCUMENT_OWNER'],
    mfa: true,
  };
  const ctx = { ip: '127.0.0.1', correlationId: 'corr-retention-test' };

  it('DecideAccessRequestSchema synchronizes validDays ceiling to 30 days and accepts validUntil', () => {
    assert.equal(DEFAULT_GRANT_MAX_DURATION_DAYS, 30);
    assert.equal(
      DecideAccessRequestSchema.safeParse({ decision: 'APPROVED', validDays: 2 }).success,
      true,
    );
    assert.equal(
      DecideAccessRequestSchema.safeParse({ decision: 'APPROVED', validDays: 30 }).success,
      true,
    );
    assert.equal(
      DecideAccessRequestSchema.safeParse({ decision: 'APPROVED', validDays: 31 }).success,
      false,
    );
    assert.equal(
      DecideAccessRequestSchema.safeParse({ decision: 'APPROVED', validDays: 365 }).success,
      false,
    );
    assert.equal(
      DecideAccessRequestSchema.safeParse({
        decision: 'APPROVED',
        validUntil: new Date(Date.now() + 2 * 86_400_000).toISOString(),
      }).success,
      true,
    );
  });

  it('AccessRequestsService.createRequest blocks requests exceeding document retention_until (2 days vs 7 days) and allows requests within retention', async () => {
    const docId = randomUUID();
    const now = new Date();
    const retentionInTwoDays = new Date(
      Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 2),
    );
    const retentionIso = retentionInTwoDays.toISOString().substring(0, 10);

    let capturedCreateData = null;
    const mockDb = {
      document: {
        findUnique: async () => ({
          id: docId,
          owner_id: 5n,
          status: 'ACTIVE',
          discoverable: true,
          retention_until: retentionInTwoDays,
          classification_history: [
            {
              classification_levels: {
                code: 'CONFIDENTIAL',
                rank: 2,
                allow_download: true,
                default_view_days: 14,
              },
            },
          ],
        }),
      },
      userAttributeAssignment: {
        findFirst: async () => ({
          attribute_definitions: { is_active: true },
          attribute_options: { numeric_rank: 3, is_active: true },
        }),
      },
      accessRequest: {
        findFirst: async () => null,
        create: async ({ data }) => {
          capturedCreateData = data;
          return {
            ...data,
            documents: {
              title: 'Tài liệu hạn 2 ngày',
              document_code: 'DOC-2D',
              retention_until: retentionInTwoDays,
              classification_history: [
                {
                  classification_levels: {
                    code: 'CONFIDENTIAL',
                    default_view_days: 14,
                    allow_download: true,
                  },
                },
              ],
            },
            users: {
              username: 'reader.qa',
              full_name: 'Người đọc QA',
              departments: { name: 'KT' },
            },
            access_request_permissions: [{ permission: 'VIEW' }],
          };
        },
      },
      $transaction: async (fn) => fn(mockDb),
    };

    const service = new AccessRequestsService(
      { record: async () => {} },
      { createGrant: async () => ({ id: randomUUID() }) },
      mockDb,
    );

    // Requesting 7 days when retention is only 2 days -> MUST reject with GRANT_DURATION_EXCEEDED
    await assert.rejects(
      () =>
        service.createRequest(
          {
            documentId: docId,
            requestedAction: 'VIEW',
            reason: 'Cần đối chiếu nội dung tài liệu trong 7 ngày',
            requestedFrom: now.toISOString(),
            requestedUntil: new Date(now.getTime() + 7 * 86_400_000).toISOString(),
          },
          readerPrincipal,
          ctx,
        ),
      (err) =>
        err.response?.errorCode === AppErrorCode.GRANT_DURATION_EXCEEDED &&
        String(err.response?.message).includes(retentionIso),
    );

    // Requesting 31 days (> 30-day ceiling) -> MUST reject with GRANT_DURATION_EXCEEDED
    await assert.rejects(
      () =>
        service.createRequest(
          {
            documentId: docId,
            requestedAction: 'VIEW',
            reason: 'Cần sử dụng tài liệu dài hơn trần 30 ngày',
            requestedFrom: now.toISOString(),
            requestedUntil: new Date(now.getTime() + 31 * 86_400_000).toISOString(),
          },
          readerPrincipal,
          ctx,
        ),
      (err) =>
        err.response?.errorCode === AppErrorCode.GRANT_DURATION_EXCEEDED &&
        String(err.response?.message).includes('30 days'),
    );

    // Requesting 2 days -> ALLOWED
    const okDetail = await service.createRequest(
      {
        documentId: docId,
        requestedAction: 'VIEW',
        reason: 'Cần xem tài liệu trong đúng 2 ngày hiệu lực',
        requestedFrom: now.toISOString(),
        requestedUntil: new Date(now.getTime() + 2 * 86_400_000).toISOString(),
      },
      readerPrincipal,
      ctx,
    );
    assert.equal(okDetail.status, 'PENDING');
    assert.equal(okDetail.documentRetentionUntil, retentionIso);
    assert.equal(okDetail.documentDefaultViewDays, 14);
    assert.ok(capturedCreateData);
  });

  it('AccessRequestsService.createRequest applies classification default_view_days (1 day for TOP_SECRET) and blocks expired retention', async () => {
    const docId = randomUUID();
    const now = new Date();
    let capturedUntil = null;

    const mockDb = {
      document: {
        findUnique: async () => ({
          id: docId,
          owner_id: 5n,
          status: 'ACTIVE',
          discoverable: true,
          retention_until: null,
          classification_history: [
            {
              classification_levels: {
                code: 'TOP_SECRET',
                rank: 4,
                allow_download: false,
                default_view_days: 1,
              },
            },
          ],
        }),
      },
      userAttributeAssignment: {
        findFirst: async () => ({
          attribute_definitions: { is_active: true },
          attribute_options: { numeric_rank: 4, is_active: true },
        }),
      },
      accessRequest: {
        findFirst: async () => null,
        create: async ({ data }) => {
          capturedUntil = data.requested_until;
          return {
            ...data,
            documents: { title: 'Tài liệu Tuyệt mật', document_code: 'DOC-TS' },
            users: {
              username: 'reader.qa',
              full_name: 'Người đọc QA',
              departments: { name: 'KT' },
            },
            access_request_permissions: [{ permission: 'VIEW' }],
          };
        },
      },
      $transaction: async (fn) => fn(mockDb),
    };

    const service = new AccessRequestsService(
      { record: async () => {} },
      { createGrant: async () => ({ id: randomUUID() }) },
      mockDb,
    );

    await service.createRequest(
      {
        documentId: docId,
        requestedAction: 'VIEW',
        reason: 'Phục vụ họp khẩn cấp hội đồng quản trị',
      },
      readerPrincipal,
      ctx,
    );
    assert.ok(capturedUntil instanceof Date);
    const diffHours = (capturedUntil.getTime() - now.getTime()) / 3_600_000;
    assert.ok(
      diffHours >= 23.5 && diffHours <= 24.5,
      `Expected ~24h default for TOP_SECRET, got ${diffHours}h`,
    );

    // Expired retention document -> MUST reject
    const expiredRetention = new Date(
      Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() - 1),
    );
    mockDb.document.findUnique = async () => ({
      id: docId,
      owner_id: 5n,
      status: 'ACTIVE',
      discoverable: true,
      retention_until: expiredRetention,
      classification_history: [
        {
          classification_levels: {
            code: 'INTERNAL',
            rank: 1,
            allow_download: true,
            default_view_days: 30,
          },
        },
      ],
    });

    await assert.rejects(
      () =>
        service.createRequest(
          {
            documentId: docId,
            requestedAction: 'VIEW',
            reason: 'Thử xin quyền tài liệu đã quá hạn lưu trữ',
          },
          readerPrincipal,
          ctx,
        ),
      (err) => err.response?.errorCode === AppErrorCode.GRANT_DURATION_EXCEEDED,
    );
  });

  it('AccessRequestsService.decideRequest blocks approval past retention_until and supports validUntil override', async () => {
    const reqId = randomUUID();
    const docId = randomUUID();
    const now = new Date();
    const retentionInTwoDays = new Date(
      Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 2),
    );
    const createdGrantPayloads = [];

    const mockDb = {
      accessRequest: {
        findUnique: async () => ({
          id: reqId,
          document_id: docId,
          requester_id: 10n,
          requested_from: now,
          requested_until: new Date(now.getTime() + 2 * 86_400_000),
          status: 'PENDING',
          documents: {
            id: docId,
            owner_id: 5n,
            title: 'Tài liệu hạn 2 ngày',
            retention_until: retentionInTwoDays,
          },
          access_request_permissions: [{ permission: 'VIEW' }],
        }),
      },
    };

    const service = new AccessRequestsService(
      { record: async () => {} },
      {
        createGrant: async (dto) => {
          createdGrantPayloads.push(dto);
          return { id: randomUUID() };
        },
      },
      mockDb,
    );

    // Approving for 7 days when document retention is 2 days -> REJECT
    await assert.rejects(
      () =>
        service.decideRequest(reqId, { decision: 'APPROVED', validDays: 7 }, ownerPrincipal, ctx),
      (err) => err.response?.errorCode === AppErrorCode.GRANT_DURATION_EXCEEDED,
    );

    // Approving with explicit validUntil within 2 days -> ALLOW
    const targetUntil = new Date(now.getTime() + 36 * 3_600_000).toISOString();
    const res = await service.decideRequest(
      reqId,
      { decision: 'APPROVED', validUntil: targetUntil, permissions: ['VIEW', 'DOWNLOAD'] },
      ownerPrincipal,
      ctx,
    );
    assert.equal(res.status, 'APPROVED');
    assert.equal(createdGrantPayloads.length, 1);
    assert.equal(createdGrantPayloads[0].validUntil, targetUntil);
  });

  it('AccessRequestsService.listRequests(incoming) attaches existingActiveGrant and document retention metadata', async () => {
    const docId = randomUUID();
    const reqId = randomUUID();
    const grantId = randomUUID();
    const now = new Date();
    const retentionDate = new Date(
      Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 5),
    );
    const existingUntil = new Date(now.getTime() + 2 * 86_400_000);

    const mockDb = {
      accessRequest: {
        findMany: async () => [
          {
            id: reqId,
            document_id: docId,
            requester_id: 10n,
            reason: 'Xin bổ sung quyền tải xuống tài liệu',
            status: 'PENDING',
            submitted_at: now,
            requested_from: now,
            requested_until: existingUntil,
            documents: {
              title: 'Báo cáo tài chính',
              document_code: 'DOC-FIN',
              retention_until: retentionDate,
              classification_history: [
                {
                  classification_levels: {
                    code: 'CONFIDENTIAL',
                    default_view_days: 14,
                    allow_download: true,
                  },
                },
              ],
            },
            users: { username: 'reader.qa', full_name: 'Nguyễn Đọc', departments: { name: 'KT' } },
            access_request_permissions: [{ permission: 'DOWNLOAD' }],
            access_request_decisions: null,
          },
        ],
        count: async () => 1,
      },
      accessGrant: {
        findMany: async () => [
          {
            id: grantId,
            document_id: docId,
            principal_type: 'USER',
            principal_user_id: 10n,
            status: 'ACTIVE',
            valid_from: now,
            valid_until: existingUntil,
            access_grant_permissions: [{ permission: 'VIEW' }],
          },
        ],
      },
    };

    const service = new AccessRequestsService(
      { record: async () => {} },
      { createGrant: async () => ({ id: randomUUID() }) },
      mockDb,
    );

    const list = await service.listRequests(ownerPrincipal, {
      scope: 'incoming',
      status: 'PENDING',
      page: 1,
      pageSize: 20,
    });
    assert.equal(list.total, 1);
    const item = list.data[0];
    assert.equal(item.documentRetentionUntil, retentionDate.toISOString().substring(0, 10));
    assert.equal(item.documentDefaultViewDays, 14);
    assert.equal(item.documentAllowDownload, true);
    assert.deepEqual(item.existingActiveGrant, {
      grantId,
      permissions: ['VIEW'],
      validFrom: now.toISOString(),
      validUntil: existingUntil.toISOString(),
    });
  });

  it('AccessGrantsService.createGrant blocks direct grants exceeding document retention_until', async () => {
    const docId = randomUUID();
    const now = new Date();
    const retentionInTwoDays = new Date(
      Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 2),
    );

    const mockDb = {
      document: {
        findUnique: async () => ({
          id: docId,
          title: 'Tài liệu hạn 2 ngày',
          document_code: 'DOC-2D',
          owner_id: 5n,
          department_id: 1n,
          status: 'ACTIVE',
          retention_until: retentionInTwoDays,
          classification_history: [
            {
              classification_levels: { rank: 1, allow_download: true },
              business_categories: { code: 'GENERAL_OPERATIONS' },
            },
          ],
        }),
      },
      userAttributeAssignment: {
        findFirst: async () => ({
          attribute_definitions: { is_active: true },
          attribute_options: { numeric_rank: 3, is_active: true },
        }),
      },
    };

    const service = new AccessGrantsService(
      { record: async () => {} },
      { hasPermission: async () => true },
      { invalidateUser: async () => {} },
      { evaluate: async () => ({ decision: 'PERMIT' }) },
      { get: (key) => (key === 'GRANT_MAX_DURATION_DAYS' ? 30 : 60000) },
      mockDb,
    );

    await assert.rejects(
      () =>
        service.createGrant(
          {
            documentId: docId,
            principalType: 'USER',
            principalUserId: 10n,
            permissions: ['VIEW'],
            validFrom: now.toISOString(),
            validUntil: new Date(now.getTime() + 7 * 86_400_000).toISOString(),
          },
          ownerPrincipal,
          ctx,
        ),
      (err) => err.response?.errorCode === AppErrorCode.GRANT_DURATION_EXCEEDED,
    );
  });

  it('DocumentSearchService exposes retentionUntil and defaultViewDays in search and my-grants responses', async () => {
    const { service } = await buildService({ discoverableDeptIds: null });
    const searchRes = await service.searchDocuments(
      { page: 1, pageSize: 20, sort: 'created_at', order: 'desc' },
      READER_PRINCIPAL,
      TEST_CONTEXT,
    );
    assert.ok(searchRes.data.length > 0);
    assert.ok('retentionUntil' in searchRes.data[0]);
    assert.equal(searchRes.data[0].defaultViewDays, 14);

    const grantsRes = await service.getMyGrantedDocuments(
      { page: 1, pageSize: 20, sort: 'granted_at', order: 'desc' },
      READER_PRINCIPAL,
    );
    assert.ok(grantsRes.data.length > 0);
    assert.ok('retentionUntil' in grantsRes.data[0].document);
    assert.equal(typeof grantsRes.data[0].document.defaultViewDays, 'number');
  });
});
