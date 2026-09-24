import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import {
  CreateAccessRequestSchema,
  DecideAccessRequestSchema,
  ListAccessRequestsSchema,
} from '../../../packages/contracts/dist/dto.js';
import { AccessRequestsService } from '../dist/modules/access-requests/access-requests.service.js';

// ── Contract Schema Tests ────────────────────────────────────────────────────

test('CreateAccessRequestSchema — valid VIEW request with 10+ char justification', () => {
  const result = CreateAccessRequestSchema.safeParse({
    documentId: randomUUID(),
    requestedAction: 'VIEW',
    reason: 'Cần tra cứu quy trình vận hành bảo mật tài liệu',
  });
  assert.ok(result.success, `Expected success, got: ${JSON.stringify(result.error?.flatten())}`);
  assert.equal(result.data.requestedAction, 'VIEW');
});

test('CreateAccessRequestSchema — rejects reason shorter than 10 characters', () => {
  const result = CreateAccessRequestSchema.safeParse({
    documentId: randomUUID(),
    requestedAction: 'VIEW',
    reason: 'Cần xem',
  });
  assert.equal(result.success, false);
});

test('CreateAccessRequestSchema — rejects invalid UUID', () => {
  const result = CreateAccessRequestSchema.safeParse({
    documentId: 'not-a-uuid',
    requestedAction: 'DOWNLOAD',
    reason: 'Cần tải tài liệu để phục vụ công tác thanh tra',
  });
  assert.equal(result.success, false);
});

test('DecideAccessRequestSchema — validates APPROVED and REJECTED decisions', () => {
  const approveRes = DecideAccessRequestSchema.safeParse({
    decision: 'APPROVED',
    validDays: 14,
  });
  assert.ok(approveRes.success);
  assert.equal(approveRes.data.validDays, 14);

  const rejectRes = DecideAccessRequestSchema.safeParse({
    decision: 'REJECTED',
    decisionNote: 'Chưa đủ điều kiện thẩm tra bảo mật theo quy định',
  });
  assert.ok(rejectRes.success);
  assert.equal(rejectRes.data.decision, 'REJECTED');
});

test('ListAccessRequestsSchema — validates default values and scopes', () => {
  const result = ListAccessRequestsSchema.safeParse({});
  assert.ok(result.success);
  assert.equal(result.data.scope, 'my');
  assert.equal(result.data.page, 1);
  assert.equal(result.data.pageSize, 20);

  const incoming = ListAccessRequestsSchema.safeParse({ scope: 'incoming', status: 'PENDING' });
  assert.ok(incoming.success);
  assert.equal(incoming.data.scope, 'incoming');
  assert.equal(incoming.data.status, 'PENDING');
});

// ── AccessRequestsService Unit Tests ─────────────────────────────────────────

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

test('AccessRequestsService: createRequest rejects non-existent document', async () => {
  const mockDb = {
    document: {
      findUnique: async () => null,
    },
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

  await assert.rejects(
    () =>
      service.createRequest(
        {
          documentId: randomUUID(),
          requestedAction: 'VIEW',
          reason: 'Cần tra cứu tài liệu phục vụ công tác',
        },
        principal,
        context,
      ),
    (err) => err.response?.errorCode === 'DOCUMENT_NOT_FOUND',
  );
});

test('AccessRequestsService: createRequest rejects non-ACTIVE document', async () => {
  const mockDb = {
    document: {
      findUnique: async () => ({
        id: randomUUID(),
        status: 'DRAFT',
        classification_history: [],
      }),
    },
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

  await assert.rejects(
    () =>
      service.createRequest(
        {
          documentId: randomUUID(),
          requestedAction: 'VIEW',
          reason: 'Cần tra cứu tài liệu phục vụ công tác',
        },
        principal,
        context,
      ),
    (err) => err.response?.errorCode === 'DOCUMENT_ACCESS_DENIED',
  );
});

test('AccessRequestsService: createRequest rejects duplicate pending request', async () => {
  const docId = randomUUID();
  const mockDb = {
    document: {
      findUnique: async () => ({
        id: docId,
        status: 'ACTIVE',
        classification_history: [{ classification_levels: { allow_download: true, rank: 2 } }],
      }),
    },
    accessRequest: {
      findFirst: async () => ({ id: 'req-dup', status: 'PENDING' }),
    },
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

  await assert.rejects(
    () =>
      service.createRequest(
        {
          documentId: docId,
          requestedAction: 'VIEW',
          reason: 'Cần tra cứu tài liệu phục vụ công tác',
        },
        principal,
        context,
      ),
    (err) => err.response?.errorCode === 'ACCESS_REQUEST_DUPLICATE',
  );
});

test('AccessRequestsService: createRequest creates request in transaction and returns detail', async () => {
  const docId = randomUUID();
  const reqId = randomUUID();
  const now = new Date();
  const mockCreated = {
    id: reqId,
    document_id: docId,
    requester_id: 10n,
    reason: 'Cần tra cứu tài liệu phục vụ công tác',
    requested_from: now,
    requested_until: new Date(now.getTime() + 7 * 86400000),
    status: 'PENDING',
    submitted_at: now,
    documents: { title: 'Báo cáo kỹ thuật', document_code: 'DOC-001' },
    users: { username: 'reader1', full_name: 'Nguyễn Văn Đọc', departments: { name: 'Kỹ thuật' } },
    access_request_permissions: [{ permission: 'VIEW' }],
  };

  const mockDb = {
    document: {
      findUnique: async () => ({
        id: docId,
        status: 'ACTIVE',
        classification_history: [{ classification_levels: { allow_download: true, rank: 2 } }],
      }),
    },
    accessRequest: {
      findFirst: async () => null,
      create: async () => mockCreated,
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

  const result = await service.createRequest(
    {
      documentId: docId,
      requestedAction: 'VIEW',
      reason: 'Cần tra cứu tài liệu phục vụ công tác',
    },
    principal,
    context,
  );

  assert.equal(result.id, reqId);
  assert.equal(result.status, 'PENDING');
  assert.equal(result.documentTitle, 'Báo cáo kỹ thuật');
  assert.equal(result.requestorName, 'Nguyễn Văn Đọc');
});

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
