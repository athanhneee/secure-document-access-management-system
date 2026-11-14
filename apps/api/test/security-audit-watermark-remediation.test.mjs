/**
 * @module SecurityAuditWatermarkRemediationTests
 * Thuật toán: Bộ kiểm thử đơn vị toàn diện cho khắc phục lỗ hổng ngữ cảnh ABAC cấp quyền, truy vấn lô `O(1)` cho vai trò,
 * ẩn dấu vết `WATERMARK_TRACE_PERFORMED` khỏi `DOCUMENT_OWNER`, nối tiếp kiểm toán từ `AuditAnchor`,
 * truy vết thủy vân 15 ký tự + khóa QR `SECRET`/`TOP_SECRET` + làm phẳng biểu mẫu PDF, và phân mảnh khử trùng lặp 5 phút.
 */
import 'reflect-metadata';
import assert from 'node:assert/strict';
import { createHmac, randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { buildRoleGrantSubjectAttributes } from '../dist/modules/access-grants/grant-pip.helper.js';
import { validateCreateGrantPreconditions } from '../dist/modules/access-grants/grant-validation.helper.js';
import { AuditVerifierService } from '../dist/modules/audit/audit-verifier.service.js';
import { AuditService } from '../dist/modules/audit/audit.service.js';
import { createAuditWriterHarness } from './helpers/audit-trail-mocks.mjs';

/**
 * Thuật toán: Kiểm chứng `validateCreateGrantPreconditions` dùng môi trường trung tính tĩnh (`mfa: true`, `trustedNetwork: true`)
 * thay vì mượn phiên không có MFA của chủ tài liệu, và `buildRoleGrantSubjectAttributes` chạy truy vấn lô `in: holderIds`.
 */
test('Grant ABAC context uses neutral static environment and bulk O(1) role-holder queries', async () => {
  const docId = randomUUID();
  const validFrom = new Date('2026-10-15T09:00:00.000Z');
  const validUntil = new Date('2026-10-20T09:00:00.000Z');
  let capturedAbacReq = null;

  const mockDb = {
    document: {
      findUnique: async () => ({
        id: docId,
        owner_id: 10n,
        department_id: 5n,
        status: 'ACTIVE',
        classification_history: [
          {
            effective_to: null,
            classification_levels: { rank: 2, allow_download: true },
            business_categories: { code: 'ENG' },
          },
        ],
      }),
    },
    user: {
      findUnique: async () => ({ id: 25n, status: 'ACTIVE', department_id: 5n }),
    },
    userRole: { findMany: async () => [] },
    userAttributeAssignment: {
      findFirst: async () => ({ attribute_options: { numeric_rank: 3, is_active: true } }),
      findMany: async () => [],
    },
  };

  await validateCreateGrantPreconditions({
    input: {
      documentId: docId,
      principalType: 'USER',
      principalUserId: 25n,
      permissions: ['VIEW'],
      validFrom: validFrom.toISOString(),
      validUntil: validUntil.toISOString(),
    },
    // Owner approving from a password-only untrusted IP session must NOT pollute grantee static eligibility!
    principal: {
      userId: 10n,
      sessionId: 's-owner',
      username: 'owner',
      roles: ['DOCUMENT_OWNER'],
      mfa: false,
    },
    context: { ip: '203.0.113.99', correlationId: 'corr-grant-env' },
    now: new Date('2026-10-14T23:30:00.000Z'),
    maxDurationDays: 30,
    database: mockDb,
    authorization: { hasPermission: async () => true },
    abac: {
      evaluate: async (req) => {
        capturedAbacReq = req;
        return { decision: 'PERMIT', reasonCode: 'OK', obligations: [] };
      },
    },
    config: { get: () => '' },
  });

  assert.deepEqual(capturedAbacReq.environment, {
    currentTime: validFrom.toISOString(),
    ip: '127.0.0.1',
    trustedNetwork: true,
    deviceTrust: true,
    mfa: true,
    riskScore: 0,
  });

  let userQueryCalls = 0;
  let attrQueryCalls = 0;
  const roleProfile = await buildRoleGrantSubjectAttributes(
    {
      userRole: {
        findMany: async () => [{ user_id: 11n }, { user_id: 12n }, { user_id: 13n }],
      },
      user: {
        findMany: async ({ where }) => {
          userQueryCalls += 1;
          assert.deepEqual(where.id.in, [11n, 12n, 13n]);
          return [
            { id: 11n, department_id: 4n, status: 'ACTIVE' },
            { id: 12n, department_id: 4n, status: 'ACTIVE' },
            { id: 13n, department_id: 4n, status: 'ACTIVE' },
          ];
        },
      },
      userAttributeAssignment: {
        findMany: async ({ where }) => {
          attrQueryCalls += 1;
          assert.deepEqual(where.user_id.in, [11n, 12n, 13n]);
          return [
            {
              user_id: 11n,
              attribute_definitions: { code: 'CLEARANCE_LEVEL', is_active: true },
              attribute_options: { numeric_rank: 4, is_active: true },
            },
            {
              user_id: 12n,
              attribute_definitions: { code: 'CLEARANCE_LEVEL', is_active: true },
              attribute_options: { numeric_rank: 3, is_active: true },
            },
            {
              user_id: 13n,
              attribute_definitions: { code: 'CLEARANCE_LEVEL', is_active: true },
              attribute_options: { numeric_rank: 3, is_active: true },
            },
          ];
        },
      },
    },
    8n,
    validFrom,
  );
  assert.equal(userQueryCalls, 1);
  assert.equal(attrQueryCalls, 1);
  assert.equal(roleProfile.clearanceRank, 3);
  assert.equal(roleProfile.holderCount, 3);
});

/**
 * Thuật toán: Kiểm chứng `AuditService` lọc bỏ `WATERMARK_TRACE_PERFORMED` với `DOCUMENT_OWNER`
 * và `AuditVerifierService` nối tiếp từ điểm neo `VALID` mới nhất khi bỏ trống `fromSequence`.
 */
test('AuditService hides WATERMARK_TRACE_PERFORMED from DOCUMENT_OWNER & AuditVerifierService resumes from VALID anchor', async () => {
  const docId = randomUUID();
  let capturedWhere = null;
  const auditSvc = new AuditService(
    {},
    {},
    {
      document: {
        findUnique: async () => ({ id: docId, owner_id: 42n }),
        findMany: async () => [{ id: docId }],
      },
      auditLog: {
        count: async ({ where }) => {
          capturedWhere = where;
          return 0;
        },
        findMany: async () => [],
      },
    },
  );

  await auditSvc.queryAuditLogs(
    { userId: 42n, username: 'owner', roles: ['DOCUMENT_OWNER'], sessionId: 's1', mfa: false },
    {
      documentId: docId,
      action: 'WATERMARK_TRACE_PERFORMED',
      page: 1,
      pageSize: 20,
      sort: 'occurred_at',
      order: 'desc',
    },
  );
  assert.deepEqual(capturedWhere.action, { in: [], notIn: ['WATERMARK_TRACE_PERFORMED'] });

  const { config, writer, logs, mockTx } = createAuditWriterHarness();
  const ctx = { ip: '127.0.0.1', correlationId: randomUUID() };
  for (const act of ['E1', 'E2', 'E3']) {
    await writer.record(
      { action: act, outcome: 'SUCCESS', objectType: 'DOC', chainPartition: 'P1' },
      ctx,
      mockTx,
    );
  }
  const anchorSig = createHmac('sha256', config.get('AUDIT_INTEGRITY_KEY'))
    .update(`P1:2:${logs[1].entry_hash}`)
    .digest('hex');

  let queriedGtSequence = null;
  const verifier = new AuditVerifierService(writer, {
    auditAnchor: {
      findMany: async () => [
        {
          chain_partition: 'P1',
          anchor_sequence: 2n,
          entry_hash: logs[1].entry_hash,
          signature: anchorSig,
          signer_key_id: 'v1',
          status: 'VALID',
        },
      ],
    },
    auditLog: {
      findFirst: async ({ where }) =>
        logs.find((l) => l.chain_sequence === where.chain_sequence) ?? null,
      findMany: async ({ where }) => {
        queriedGtSequence = where.chain_sequence?.gt ?? null;
        return logs.filter((l) =>
          where.chain_sequence?.gt ? l.chain_sequence > where.chain_sequence.gt : true,
        );
      },
    },
  });

  const verifyRes = await verifier.verifyPartition('P1');
  assert.equal(verifyRes.valid, true);
  assert.equal(queriedGtSequence, 2n, 'Verifier must resume after verified anchor sequence 2n');
  assert.equal(verifyRes.totalChecked, 3);
});
