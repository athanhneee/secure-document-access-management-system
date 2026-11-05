import 'reflect-metadata';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { withSerializableTransaction } from '@sda/database';
import { AppErrorCode } from '@sda/contracts';
import { AppConfigService } from '../dist/config/config.service.js';
import { RedlockService } from '../dist/modules/concurrency/redlock.service.js';
import { AuthorizationCache } from '../dist/modules/rbac/authorization-cache.js';
import { AccessRequestsService } from '../dist/modules/access-requests/access-requests.service.js';
import { AccessGrantsService } from '../dist/modules/access-grants/access-grants.service.js';
import { DocumentDeliveryService } from '../dist/modules/documents/document-delivery.service.js';

const ownerPrincipal = {
  userId: 101n,
  sessionId: 'sess-101',
  username: 'owner.concurrent',
  roles: ['DOCUMENT_OWNER'],
  mfa: true,
};
const ctx = { ip: '10.0.0.99', correlationId: 'corr-concurrency' };

function createInMemoryRedisNode() {
  const store = new Map();
  return {
    async set(key, token, _px, ttlMs) {
      const existing = store.get(key);
      const now = Date.now();
      if (existing && existing.expiresAt > now) return null;
      store.set(key, { token, expiresAt: now + ttlMs });
      return 'OK';
    },
    async eval(script, _numKeys, key, token, ttlMs) {
      const existing = store.get(key);
      if (!existing || existing.token !== token) return 0;
      if (script.includes('del')) return Number(store.delete(key));
      if (script.includes('pexpire')) {
        existing.expiresAt = Date.now() + Number(ttlMs);
        return 1;
      }
      return 0;
    },
    async ping() {
      return 'PONG';
    },
    async quit() {
      store.clear();
      return 'OK';
    },
    disconnect() {
      store.clear();
    },
  };
}

test('Concurrency Scenario 1 — real 3-node RedlockService quorum + AccessRequestsService serializes concurrent approvals', async () => {
  const redlock = new RedlockService(
    new AppConfigService({
      NODE_ENV: 'test',
      REDLOCK_RETRY_COUNT: 15,
      REDLOCK_RETRY_DELAY_MS: 10,
      REDLOCK_RETRY_JITTER_MS: 4,
    }),
    [createInMemoryRedisNode(), createInMemoryRedisNode(), createInMemoryRedisNode()],
  );
  assert.equal(redlock.quorumCount, 2);

  const reqId = randomUUID();
  const docId = randomUUID();
  const createdGrants = [];
  const reqState = {
    id: reqId,
    document_id: docId,
    requester_id: 202n,
    status: 'PENDING',
    documents: { id: docId, owner_id: 101n },
    access_request_permissions: [{ permission: 'VIEW' }],
  };

  const service = new AccessRequestsService(
    { record: async () => {} },
    {
      createGrant: async (input) => {
        await new Promise((r) => setTimeout(r, 15));
        reqState.status = 'APPROVED';
        const grant = { id: randomUUID(), documentId: input.documentId };
        createdGrants.push(grant);
        return grant;
      },
    },
    { accessRequest: { findUnique: async () => reqState } },
    redlock,
  );

  try {
    const outcomes = await Promise.allSettled([
      service.decideRequest(reqId, { decision: 'APPROVED', validDays: 5 }, ownerPrincipal, ctx),
      service.decideRequest(reqId, { decision: 'APPROVED', validDays: 5 }, ownerPrincipal, ctx),
    ]);
    const fulfilled = outcomes.filter((o) => o.status === 'fulfilled');
    const rejected = outcomes.filter((o) => o.status === 'rejected');
    assert.equal(fulfilled.length, 1);
    assert.equal(rejected.length, 1);
    assert.equal(
      rejected[0].reason.response?.errorCode,
      AppErrorCode.ACCESS_REQUEST_ALREADY_DECIDED,
    );
    assert.equal(createdGrants.length, 1);
  } finally {
    await redlock.onModuleDestroy();
  }
});

test('Concurrency Scenario 2 — real withSerializableTransaction retries PostgreSQL 40001 serialization failure with CSPRNG jitter', async () => {
  let attempts = 0;
  const fakeClient = {
    $transaction: async (fn) => {
      attempts += 1;
      if (attempts < 3) {
        throw Object.assign(new Error('could not serialize access'), { code: '40001' });
      }
      return fn({ committedAttempt: attempts });
    },
  };
  const result = await withSerializableTransaction(
    async (tx) => ({ ok: true, attempt: tx.committedAttempt }),
    { client: fakeClient, maxRetries: 4, baseDelayMs: 2 },
  );
  assert.deepEqual(result, { ok: true, attempt: 3 });
});

test('Concurrency Scenario 3 — real AccessGrantsService.revokeGrant terminates sessions and blocks DocumentDeliveryService ticket issuance', async () => {
  const grantId = randomUUID();
  const docId = randomUUID();
  const sessionId = randomUUID();
  const now = new Date();
  const notificationsSent = [];
  const classHistory = [
    {
      effective_to: null,
      classification_levels: { allow_download: true, require_watermark: true, rank: 2 },
      business_categories: { code: 'OPS' },
    },
  ];
  const grantRow = {
    id: grantId,
    document_id: docId,
    principal_type: 'USER',
    principal_user_id: 42n,
    principal_role_id: null,
    status: 'ACTIVE',
    valid_from: new Date(now.getTime() - 10_000),
    valid_until: new Date(now.getTime() + 600_000),
    revoked_at: null,
    revoked_by: null,
    revoke_reason: null,
    granted_by: 101n,
    granted_at: now,
    source: 'DIRECT',
    access_request_id: null,
    version: 1,
    access_grant_permissions: [{ permission: 'VIEW' }, { permission: 'DOWNLOAD' }],
    documents: {
      owner_id: 101n,
      department_id: 1n,
      status: 'ACTIVE',
      classification_history: classHistory,
    },
  };
  const sessionRow = {
    id: sessionId,
    access_grant_id: grantId,
    user_id: 42n,
    status: 'ACTIVE',
    started_at: now,
    last_activity_at: now,
    ended_at: null,
    terminated_reason: null,
    document_versions: {
      id: 1n,
      document_id: docId,
      version_no: 1,
      document: { id: docId, classification_history: classHistory },
    },
  };

  const mockDb = {
    user: { findUnique: async () => ({ status: 'ACTIVE' }) },
    userAttributeAssignment: {
      findFirst: async () => ({
        attribute_definitions: { is_active: true },
        attribute_options: { is_active: true, numeric_rank: 3 },
      }),
    },
    accessGrant: {
      findUnique: async () => grantRow,
      update: async ({ data }) => Object.assign(grantRow, data, { version: grantRow.version + 1 }),
    },
    accessSession: {
      findUnique: async () => sessionRow,
      findMany: async () => (sessionRow.status === 'ACTIVE' ? [sessionRow] : []),
      updateMany: async ({ data }) => (Object.assign(sessionRow, data), { count: 1 }),
    },
    $executeRawUnsafe: async () => 1,
    $transaction: async (fn) => fn(mockDb),
  };

  const config = new AppConfigService({
    GRANT_MAX_DURATION_DAYS: 90,
    DOWNLOAD_TICKET_TTL_SECONDS: 60,
  });
  const grantsService = new AccessGrantsService(
    { record: async () => {} },
    { hasPermission: async () => true },
    new AuthorizationCache(),
    { evaluate: async () => ({ decision: 'PERMIT', obligations: [] }) },
    config,
    mockDb,
    undefined,
    {
      sendNotification: async (p) => (notificationsSent.push(p), { isDuplicate: false }),
    },
  );
  const deliveryService = new DocumentDeliveryService(
    {
      enforceSessionPolicy: async () => ({
        grantedAction: 'DOWNLOAD',
        forbidDownload: false,
        expiresAtMs: null,
      }),
    },
    {},
    {},
    {},
    {},
    grantsService,
    { record: async () => {} },
    config,
    mockDb,
  );
  const reader = {
    userId: 42n,
    sessionId: 'auth-42',
    username: 'reader.42',
    roles: ['DOCUMENT_READER'],
    mfa: true,
  };

  const ticketBefore = await deliveryService.createDownloadTicket(docId, sessionId, reader, ctx);
  assert.ok(ticketBefore.ticket.startsWith('DT-'));

  await grantsService.revokeGrant(grantId, { reason: 'Emergency Incident' }, ownerPrincipal, ctx);
  assert.equal(sessionRow.status, 'TERMINATED');
  assert.equal(notificationsSent[0]?.notificationType, 'ACCESS_GRANT_REVOKED');

  await assert.rejects(
    () => deliveryService.createDownloadTicket(docId, sessionId, reader, ctx),
    (err) => err.response?.errorCode === AppErrorCode.SESSION_TERMINATED,
  );
});
