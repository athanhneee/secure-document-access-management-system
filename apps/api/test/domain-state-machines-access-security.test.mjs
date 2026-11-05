import 'reflect-metadata';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import {
  AppErrorCode,
  CompleteIncidentActionSchema,
  CreateAccessRequestSchema,
  CreateIncidentReportSchema,
  DecideAccessRequestSchema,
  UpdateAlertStatusSchema,
} from '@sda/contracts';
import { AppConfigService } from '../dist/config/config.service.js';
import { AuthorizationCache } from '../dist/modules/rbac/authorization-cache.js';
import { AccessRequestsService } from '../dist/modules/access-requests/access-requests.service.js';
import { AccessGrantsService } from '../dist/modules/access-grants/access-grants.service.js';
import { AccessSessionsService } from '../dist/modules/access-sessions/access-sessions.service.js';

const ownerPrincipal = {
  userId: 10n,
  sessionId: 'sess-owner',
  username: 'owner.alpha',
  roles: ['DOCUMENT_OWNER'],
  mfa: true,
};
const ctx = { ip: '10.0.0.12', correlationId: 'corr-state-machine' };

test('Access Request State Machine — real AccessRequestsService enforces terminal one-way decisions (D-BR13)', async () => {
  const validRequest = {
    documentId: randomUUID(),
    requestedAction: 'VIEW',
    reason: 'Can tham chieu so lieu cho buoi hop hoi dong quan tri ngay mai.',
    requestedUntil: new Date(Date.now() + 86400 * 1000).toISOString(),
  };
  assert.ok(CreateAccessRequestSchema.safeParse(validRequest).success);
  assert.ok(!DecideAccessRequestSchema.safeParse({ decision: 'PENDING' }).success);

  const reqId = randomUUID();
  const reqState = {
    id: reqId,
    document_id: validRequest.documentId,
    requester_id: 25n,
    status: 'PENDING',
    documents: { id: validRequest.documentId, owner_id: 10n },
    access_request_permissions: [{ permission: 'VIEW' }],
  };

  const mockDb = {
    accessRequest: {
      findUnique: async () => reqState,
      update: async ({ data }) => {
        reqState.status = data.status;
        return reqState;
      },
    },
    accessRequestDecision: { create: async () => ({ id: 1n }) },
    $transaction: async (fn) => fn(mockDb),
  };

  const service = new AccessRequestsService(
    { record: async () => {} },
    {
      createGrant: async () => {
        reqState.status = 'APPROVED';
        return { id: randomUUID() };
      },
    },
    mockDb,
  );

  const approved = await service.decideRequest(
    reqId,
    { decision: 'APPROVED', validDays: 3 },
    ownerPrincipal,
    ctx,
  );
  assert.equal(approved.status, 'APPROVED');

  await assert.rejects(
    () =>
      service.decideRequest(
        reqId,
        { decision: 'REJECTED', decisionNote: 'Late override attempt' },
        ownerPrincipal,
        ctx,
      ),
    (err) => err.response?.errorCode === AppErrorCode.ACCESS_REQUEST_ALREADY_DECIDED,
  );
});

test('Access Grant & Session State Machines — real AccessGrantsService & AccessSessionsService enforce irreversible revocation & termination', async () => {
  const now = new Date();
  const grantId = randomUUID();
  const docId = randomUUID();
  const sessionId = randomUUID();

  const grantRow = {
    id: grantId,
    document_id: docId,
    principal_type: 'USER',
    principal_user_id: 25n,
    principal_role_id: null,
    status: 'ACTIVE',
    valid_from: new Date(now.getTime() - 10_000),
    valid_until: new Date(now.getTime() + 3_600_000),
    revoked_at: null,
    revoked_by: null,
    revoke_reason: null,
    granted_by: 10n,
    granted_at: now,
    source: 'DIRECT',
    access_request_id: null,
    version: 0,
    access_grant_permissions: [{ permission: 'VIEW' }],
    documents: {
      status: 'ACTIVE',
      owner_id: 10n,
      department_id: 1n,
      classification_history: [
        { effective_to: null, classification_levels: { rank: 1, allow_download: true } },
      ],
    },
  };
  const sessionRow = {
    id: sessionId,
    access_grant_id: grantId,
    user_id: 25n,
    status: 'ACTIVE',
    started_at: now,
    last_activity_at: now,
    ended_at: null,
    terminated_reason: null,
    users: { id: 25n, username: 'reader.beta', full_name: 'Reader Beta' },
    document_versions: {
      version_no: 1,
      document: { id: docId, title: 'Doc', document_code: 'DOC-1', owner_id: 10n },
    },
  };

  const mockDb = {
    user: { findUnique: async () => ({ id: 25n, status: 'ACTIVE' }) },
    userAttributeAssignment: {
      findFirst: async () => ({ attribute_options: { numeric_rank: 2, is_active: true } }),
    },
    accessGrant: {
      findUnique: async () => grantRow,
      update: async ({ data }) => {
        Object.assign(grantRow, {
          status: data.status,
          revoked_by: data.revoked_by,
          revoked_at: data.revoked_at,
          revoke_reason: data.revoke_reason,
          version: grantRow.version + 1,
        });
        return grantRow;
      },
    },
    accessSession: {
      findUnique: async () => sessionRow,
      findMany: async () => (sessionRow.status === 'ACTIVE' ? [sessionRow] : []),
      update: async ({ data }) => Object.assign(sessionRow, data),
      updateMany: async ({ data }) => {
        Object.assign(sessionRow, data);
        return { count: 1 };
      },
    },
    $executeRawUnsafe: async () => 1,
    $transaction: async (fn) => fn(mockDb),
  };

  const grantsService = new AccessGrantsService(
    { record: async () => {} },
    { hasPermission: async () => true },
    new AuthorizationCache(),
    { evaluate: async () => ({ decision: 'PERMIT', obligations: [] }) },
    new AppConfigService({ GRANT_MAX_DURATION_DAYS: 90 }),
    mockDb,
  );

  await grantsService.assertGrantValidForAccess(grantId, 25n, 'VIEW', now, docId);
  const revoked = await grantsService.revokeGrant(
    grantId,
    { reason: 'Security policy change' },
    ownerPrincipal,
    ctx,
  );
  assert.equal(revoked.status, 'REVOKED');
  assert.equal(sessionRow.status, 'TERMINATED');

  await assert.rejects(
    () => grantsService.assertGrantValidForAccess(grantId, 25n, 'VIEW', now, docId),
    (err) => err.response?.errorCode === AppErrorCode.GRANT_REVOKED,
  );

  const sessionsService = new AccessSessionsService(mockDb, { writeLog: async () => {} });
  const idempotentTerminated = await sessionsService.terminateSession(
    sessionId,
    'Already closed',
    ownerPrincipal,
    ctx,
  );
  assert.equal(idempotentTerminated.status, 'TERMINATED');
});

test('Security Alert & Incident Schemas — enforce required resolution and completion notes', () => {
  assert.ok(UpdateAlertStatusSchema.safeParse({ status: 'INVESTIGATING' }).success);
  assert.ok(!UpdateAlertStatusSchema.safeParse({ status: 'RESOLVED' }).success);
  assert.ok(
    UpdateAlertStatusSchema.safeParse({
      status: 'RESOLVED',
      resolutionNote: 'Đã xác minh hoạt động tải hợp lệ phục vụ kiểm toán.',
    }).success,
  );
  assert.ok(!UpdateAlertStatusSchema.safeParse({ status: 'FALSE_POSITIVE' }).success);
  assert.ok(
    CreateIncidentReportSchema.safeParse({
      alertId: randomUUID(),
      title: 'Phat hien truy cap bat thuong tu dai IP la',
      summary: 'Tai khoan user 456 dang nhap tu dai IP ngoai gio hanh chinh va tai 10 file.',
    }).success,
  );
  assert.ok(!CompleteIncidentActionSchema.safeParse({}).success);
  assert.ok(
    CompleteIncidentActionSchema.safeParse({
      completionNote: 'Da chan IP va thu hoi toan bo phien truy cap cua user.',
    }).success,
  );
});
