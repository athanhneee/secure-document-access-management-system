/**
 * @module OwnerNotificationsTests
 * Thuật toán: Kiểm Chứng Đa Tầng Luồng Thông Báo Chủ Sở Hữu (`DOCUMENT_OWNER`)
 * Gồm: tạo/hủy yêu cầu truy cập (`AccessRequestsService`), chuyển quyền sở hữu & cảnh báo hạn lưu trữ SSE (`DocumentsService`),
 * và đệ trình biên bản sự cố SOC tới chủ sở hữu (`IncidentsService`).
 */
import 'reflect-metadata';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { describe, it } from 'node:test';
import { AccessRequestsService } from '../dist/modules/access-requests/access-requests.service.js';
import { DocumentsService } from '../dist/modules/documents/documents.service.js';
import { IncidentsService } from '../dist/modules/security-operations/incidents.service.js';
import { AuthorizationCache } from '../dist/modules/rbac/authorization-cache.js';
import {
  createInMemoryDatabase,
  createMockAudit,
  createMockAuthorization,
} from './helpers/document-lifecycle-mocks.mjs';

describe('Owner Notification Dispatch Across Access Requests, Documents & Incidents', () => {
  it('createRequest dispatches ACCESS_REQUEST_CREATED notification to document owner and survives notification errors', async () => {
    const docId = randomUUID();
    const reqId = randomUUID();
    const now = new Date();
    const sent = [];
    const sseEvents = [];

    const mockCreated = {
      id: reqId,
      document_id: docId,
      requester_id: 10n,
      reason: 'Cần tra cứu quy định công tác phí năm 2026 để đối soát chứng từ',
      requested_from: now,
      requested_until: new Date(now.getTime() + 3 * 86_400_000),
      status: 'PENDING',
      submitted_at: now,
      documents: {
        owner_id: 6n,
        title: 'Quy định chế độ công tác phí năm 2026',
        document_code: 'DOC-HC-2026-002',
      },
      users: {
        username: 'qa.reader',
        full_name: 'Lê Chuyên Viên Nghiên Cứu',
        departments: { name: 'Khối Công nghệ & Kỹ thuật' },
      },
      access_request_permissions: [{ permission: 'VIEW' }],
    };

    const mockDb = {
      document: {
        findUnique: async () => ({
          id: docId,
          owner_id: 6n,
          status: 'ACTIVE',
          discoverable: true,
          classification_history: [{ classification_levels: { allow_download: true, rank: 1 } }],
        }),
      },
      accessRequest: {
        findFirst: async () => null,
        create: async () => mockCreated,
      },
      $transaction: async (fn) => fn(mockDb),
    };

    const service = new AccessRequestsService(
      { record: async () => {} },
      { createGrant: async () => ({ id: randomUUID() }) },
      mockDb,
      undefined,
      { publish: (ev) => sseEvents.push(ev) },
      { sendNotification: async (payload) => sent.push(payload) },
    );

    const readerPrincipal = {
      userId: 10n,
      sessionId: 'sess-r1',
      username: 'qa.reader',
      roles: ['DOCUMENT_READER'],
      mfa: false,
    };
    const context = { ip: '127.0.0.1', correlationId: 'corr-1' };

    const created = await service.createRequest(
      {
        documentId: docId,
        requestedAction: 'VIEW',
        reason: 'Cần tra cứu quy định công tác phí năm 2026 để đối soát chứng từ',
      },
      readerPrincipal,
      context,
    );

    assert.equal(created.id, reqId);
    assert.equal(sent.length, 1);
    assert.equal(sent[0].recipientId, 6n);
    assert.equal(sent[0].notificationType, 'ACCESS_REQUEST_CREATED');
    assert.equal(sent[0].relatedObjectType, 'ACCESS_REQUEST');
    assert.equal(sent[0].relatedObjectId, reqId);
    assert.equal(sent[0].deduplicationKey, `ACCESS_REQUEST_CREATED:6:${reqId}`);
    assert.match(sent[0].body, /Lê Chuyên Viên Nghiên Cứu/);
    assert.match(sent[0].body, /DOC-HC-2026-002/);
    assert.match(sent[0].body, /Chỉ xem/);
    assert.equal(sseEvents.length, 1);
    assert.deepEqual(sseEvents[0].targetUserIds, ['10', '6']);

    // Notification dispatch failure must remain non-fatal after DB commit
    const resilientService = new AccessRequestsService(
      { record: async () => {} },
      { createGrant: async () => ({ id: randomUUID() }) },
      mockDb,
      undefined,
      undefined,
      {
        sendNotification: async () => {
          throw new Error('Transient outbox error');
        },
      },
    );
    const created2 = await resilientService.createRequest(
      {
        documentId: docId,
        requestedAction: 'VIEW',
        reason: 'Cần tra cứu quy định công tác phí năm 2026 để đối soát chứng từ',
      },
      readerPrincipal,
      context,
    );
    assert.equal(created2.id, reqId);
  });

  it('cancelRequest dispatches ACCESS_REQUEST_CANCELLED notification to document owner', async () => {
    const reqId = randomUUID();
    const docId = randomUUID();
    const sent = [];

    const mockDb = {
      accessRequest: {
        findUnique: async () => ({
          id: reqId,
          requester_id: 10n,
          document_id: docId,
          status: 'PENDING',
          documents: {
            owner_id: 6n,
            title: 'Quy định chế độ công tác phí năm 2026',
            document_code: 'DOC-HC-2026-002',
          },
          users: { full_name: 'Lê Chuyên Viên Nghiên Cứu', username: 'qa.reader' },
        }),
        updateMany: async () => ({ count: 1 }),
      },
      $transaction: async (fn) => fn(mockDb),
    };

    const service = new AccessRequestsService(
      { record: async () => {} },
      { createGrant: async () => ({ id: randomUUID() }) },
      mockDb,
      undefined,
      undefined,
      { sendNotification: async (payload) => sent.push(payload) },
    );

    const res = await service.cancelRequest(
      reqId,
      {
        userId: 10n,
        sessionId: 'sess-r1',
        username: 'qa.reader',
        roles: ['DOCUMENT_READER'],
        mfa: false,
      },
      { ip: '127.0.0.1', correlationId: 'corr-cancel' },
    );

    assert.equal(res.status, 'CANCELLED');
    assert.equal(sent.length, 1);
    assert.equal(sent[0].recipientId, 6n);
    assert.equal(sent[0].notificationType, 'ACCESS_REQUEST_CANCELLED');
    assert.equal(sent[0].relatedObjectType, 'ACCESS_REQUEST');
    assert.equal(sent[0].relatedObjectId, reqId);
    assert.match(sent[0].body, /DOC-HC-2026-002/);
  });

  it('transferOwner notifies new owner, and checkRetentionWarnings publishes SSE NOTIFICATION_CREATED', async () => {
    const docId = randomUUID();
    const pastDate = new Date(Date.now() - 2 * 86_400_000);
    const stores = createInMemoryDatabase({
      documents: [
        [
          docId,
          {
            id: docId,
            document_code: 'DOC-OWN-NOTIF',
            title: 'Tài liệu bàn giao chủ sở hữu',
            owner_id: 1n,
            department_id: 100n,
            status: 'ACTIVE',
            retention_until: pastDate,
            version: 0,
          },
        ],
      ],
    });
    const sent = [];
    const published = [];
    const service = new DocumentsService(
      createMockAudit(),
      createMockAuthorization([
        { userId: 1n, resource: 'DOCUMENT', action: 'MANAGE', scopeDepartmentId: 100n },
      ]),
      new AuthorizationCache(),
      stores.db,
      { sendNotification: async (payload) => sent.push(payload) },
      { publish: (ev) => published.push(ev) },
    );

    await service.transferOwner(
      docId,
      { newOwnerId: 2n, reason: 'Điều chuyển nhân sự phòng ban' },
      { userId: 1n, username: 'owner.demo', roles: ['DOCUMENT_OWNER'], mfa: true },
      { ip: '127.0.0.1', correlationId: randomUUID() },
    );

    assert.equal(sent.length, 1);
    assert.equal(sent[0].recipientId, 2n);
    assert.equal(sent[0].notificationType, 'DOCUMENT_OWNERSHIP_TRANSFERRED');
    assert.equal(sent[0].relatedObjectType, 'DOCUMENT');
    assert.equal(sent[0].relatedObjectId, docId);

    await service.checkRetentionWarnings(30, undefined, undefined, { systemScan: true });
    const retentionEvent = published.find((ev) => ev.type === 'NOTIFICATION_CREATED');
    assert.ok(retentionEvent, 'Expected NOTIFICATION_CREATED SSE event for retention warning');
    assert.deepEqual(retentionEvent.targetUserIds, ['2']);
    assert.equal(retentionEvent.payload.notificationType, 'RETENTION_EXPIRATION_WARNING');
  });

  it('submitIncidentReport notifies submittedToOwner via NotificationsService', async () => {
    const incidentId = randomUUID();
    const sent = [];
    const storedReport = {
      id: incidentId,
      incident_code: 'INC-2026-0099',
      alert_id: null,
      title: 'Cảnh báo truy cập bất thường tài liệu mật',
      summary: 'Phát hiện tải bất thường ngoài khung giờ làm việc.',
      findings: 'Đã ngắt phiên',
      impact_assessment: 'Trung bình',
      status: 'DRAFT',
      prepared_by: 4n,
      submitted_to_owner: null,
      submitted_to_admin: null,
      created_at: new Date(),
      submitted_at: null,
      closed_at: null,
      users_incident_reports_prepared_byTousers: {
        id: 4n,
        username: 'security.demo',
        full_name: 'Bảo mật demo',
      },
      incident_actions: [],
    };

    const mockDb = {
      user: {
        findUnique: async ({ where }) => ({ id: where.id }),
      },
      incidentReport: {
        findUnique: async () => storedReport,
        update: async ({ data }) => {
          Object.assign(storedReport, data);
          return storedReport;
        },
      },
    };

    const incidentsService = new IncidentsService(mockDb, undefined, undefined, undefined, {
      sendNotification: async (payload) => sent.push(payload),
    });

    await incidentsService.submitIncidentReport(
      incidentId,
      { submittedToOwner: 6n },
      {
        userId: 4n,
        sessionId: 'soc-1',
        username: 'security.demo',
        roles: ['SECURITY_OFFICER'],
        mfa: true,
      },
    );

    assert.equal(sent.length, 1);
    assert.equal(sent[0].recipientId, 6n);
    assert.equal(sent[0].notificationType, 'INCIDENT_REPORT_SUBMITTED');
    assert.equal(sent[0].relatedObjectType, 'INCIDENT_REPORT');
    assert.equal(sent[0].relatedObjectId, incidentId);
    assert.match(sent[0].title, /INC-2026-0099/);
  });
});
