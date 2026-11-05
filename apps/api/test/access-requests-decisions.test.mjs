import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import { AccessRequestsService } from '../dist/modules/access-requests/access-requests.service.js';

function createMockAudit() {
  return {
    record: async () => {},
  };
}

function createMockGrantsService() {
  return {
    createGrant: async () => ({ id: randomUUID() }),
  };
}

test('AccessRequestsService: cancelRequest allows requester to cancel pending request', async () => {
  const reqId = randomUUID();
  let updatedStatus = '';

  const mockDb = {
    accessRequest: {
      findUnique: async () => ({
        id: reqId,
        requester_id: 10n,
        document_id: randomUUID(),
        status: 'PENDING',
      }),
      update: async ({ data }) => {
        updatedStatus = data.status;
      },
    },
    $transaction: async (fn) => fn(mockDb),
  };

  const service = new AccessRequestsService(createMockAudit(), createMockGrantsService(), mockDb);
  const principal = {
    userId: 10n,
    sessionId: 's1',
    username: 'reader1',
    roles: ['DOCUMENT_READER'],
    mfa: false,
  };
  const context = { ip: '127.0.0.1', correlationId: 'c1' };

  const res = await service.cancelRequest(reqId, principal, context);
  assert.equal(res.status, 'CANCELLED');
  assert.equal(updatedStatus, 'CANCELLED');
});

test('AccessRequestsService: cancelRequest blocks non-owner of the request', async () => {
  const reqId = randomUUID();
  const mockDb = {
    accessRequest: {
      findUnique: async () => ({
        id: reqId,
        requester_id: 10n,
        document_id: randomUUID(),
        status: 'PENDING',
      }),
    },
  };

  const service = new AccessRequestsService(createMockAudit(), createMockGrantsService(), mockDb);
  const principal = {
    userId: 99n,
    sessionId: 's1',
    username: 'other_user',
    roles: ['DOCUMENT_READER'],
    mfa: false,
  };
  const context = { ip: '127.0.0.1', correlationId: 'c1' };

  await assert.rejects(
    () => service.cancelRequest(reqId, principal, context),
    (err) => err.response?.errorCode === 'FORBIDDEN',
  );
});

test('AccessRequestsService: decideRequest allows document owner to approve request and creates grant', async () => {
  const reqId = randomUUID();
  const docId = randomUUID();
  let createdGrant = false;

  const mockDb = {
    accessRequest: {
      findUnique: async () => ({
        id: reqId,
        document_id: docId,
        requester_id: 10n,
        status: 'PENDING',
        documents: { owner_id: 5n },
        access_request_permissions: [{ permission: 'VIEW' }],
      }),
    },
  };

  const mockGrants = {
    createGrant: async () => {
      createdGrant = true;
      return { id: 'grant-new-id' };
    },
  };

  const service = new AccessRequestsService(createMockAudit(), mockGrants, mockDb);
  const principal = {
    userId: 5n,
    sessionId: 's1',
    username: 'owner1',
    roles: ['DOCUMENT_OWNER'],
    mfa: false,
  };
  const context = { ip: '127.0.0.1', correlationId: 'c1' };

  const res = await service.decideRequest(
    reqId,
    { decision: 'APPROVED', validDays: 7 },
    principal,
    context,
  );

  assert.equal(res.status, 'APPROVED');
  assert.equal(res.grantId, 'grant-new-id');
  assert.equal(createdGrant, true);
});

test('AccessRequestsService: decideRequest emits ACCESS_REQUEST_APPROVED audit event', async () => {
  const reqId = randomUUID();
  const docId = randomUUID();
  const auditedEvents = [];

  const mockDb = {
    accessRequest: {
      findUnique: async () => ({
        id: reqId,
        document_id: docId,
        requester_id: 10n,
        status: 'PENDING',
        documents: { owner_id: 5n },
        access_request_permissions: [{ permission: 'VIEW' }],
      }),
    },
  };

  const mockAudit = {
    record: async (event) => {
      auditedEvents.push(event);
    },
  };

  const mockGrants = {
    createGrant: async () => ({ id: 'grant-test-123' }),
  };

  const service = new AccessRequestsService(mockAudit, mockGrants, mockDb);
  const principal = {
    userId: 5n,
    sessionId: 's1',
    username: 'owner1',
    roles: ['DOCUMENT_OWNER'],
    mfa: false,
  };
  const context = { ip: '127.0.0.1', correlationId: 'c1' };

  await service.decideRequest(
    reqId,
    { decision: 'APPROVED', validDays: 14, permissions: ['VIEW'] },
    principal,
    context,
  );

  const approvedEvent = auditedEvents.find((e) => e.action === 'ACCESS_REQUEST_APPROVED');
  assert.ok(approvedEvent, 'ACCESS_REQUEST_APPROVED event must be recorded');
  assert.equal(approvedEvent.objectId, reqId);
  assert.equal(approvedEvent.documentId, docId);
  assert.equal(approvedEvent.details.grantId, 'grant-test-123');
});
