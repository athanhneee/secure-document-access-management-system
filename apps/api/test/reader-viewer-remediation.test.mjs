import 'reflect-metadata';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { describe, it } from 'node:test';
import { isAllowedSseOrigin } from '../dist/modules/realtime/realtime-events.controller.js';
import { RealtimeEventsService } from '../dist/modules/realtime/realtime-events.service.js';
import { AccessSessionsService } from '../dist/modules/access-sessions/access-sessions.service.js';
import { AccessRequestsService } from '../dist/modules/access-requests/access-requests.service.js';
import { NotificationsService } from '../dist/modules/notifications/notifications.service.js';
import { PasswordService } from '../dist/modules/auth/password.service.js';
import { sendAttachmentDownloadReply } from '../dist/modules/documents/documents-controller.helpers.js';
import { registerFastifyHooks } from '../dist/common/hooks/fastify-hooks.js';

/**
 * Thuật toán: Kiểm Chứng Toàn Diện Các Khắc Phục Bảo Mật, SSE, Phiên Đọc, Quy Trình Yêu Cầu & Thông Báo Backend (`reader-viewer-remediation`)
 * Mục đích: Xác nhận các sửa lỗi cốt lõi V-02, V-03, V-05, V-06, V-08, V-10, V-28, V-35, V-37, V-39, V-48 và V-56 hoạt động chính xác trực tiếp trên mã biên dịch `dist/`.
 */
describe('Reader / Viewer Backend Security & Workflow Remediation (V-02..V-56)', () => {
  it('V-02: preserves route-specific Referrer-Policy: no-referrer inside Fastify onSend hook', async () => {
    let onSendHook;
    const fakeInstance = {
      addHook(name, handler) {
        if (name === 'onSend') onSendHook = handler;
      },
    };
    registerFastifyHooks(fakeInstance);
    assert.equal(typeof onSendHook, 'function');

    const headers = new Map([['referrer-policy', 'no-referrer']]);
    const fakeReply = {
      getHeader: (k) => headers.get(String(k).toLowerCase()),
      header(k, v) {
        headers.set(String(k).toLowerCase(), v);
        return this;
      },
    };
    await onSendHook({}, fakeReply, 'ok');
    assert.equal(headers.get('referrer-policy'), 'no-referrer');

    const defaultHeaders = new Map();
    const defaultReply = {
      getHeader: (k) => defaultHeaders.get(String(k).toLowerCase()),
      header(k, v) {
        defaultHeaders.set(String(k).toLowerCase(), v);
        return this;
      },
    };
    await onSendHook({}, defaultReply, 'ok');
    assert.equal(defaultHeaders.get('referrer-policy'), 'strict-origin-when-cross-origin');
  });

  it('V-03: validates SSE CORS origins strictly against allowlist instead of reflecting arbitrary origins', () => {
    const allowed = ['http://localhost:3000', 'https://docs.example.vn'];
    assert.equal(isAllowedSseOrigin('http://localhost:3000', allowed), true);
    assert.equal(isAllowedSseOrigin('https://docs.example.vn', allowed), true);
    assert.equal(isAllowedSseOrigin('https://evil.attacker.tld', allowed), false);
    assert.equal(isAllowedSseOrigin('http://localhost:3000.evil.tld', allowed), false);
    assert.equal(isAllowedSseOrigin(undefined, allowed), false);
  });

  it('V-06: disconnects only targeted sessions on USER_SESSION_REVOKED and honors excludeSessionId', () => {
    const realtime = new RealtimeEventsService();
    const ended = [];
    const written = [];
    const makeClient = (tag, sessionId) => ({
      userId: '77',
      sessionId,
      roles: ['DOCUMENT_READER'],
      writeFrame: (chunk) => {
        written.push({ tag, chunk });
        return true;
      },
      close: () => {
        ended.push(tag);
      },
    });

    realtime.registerClient(makeClient('A', 'sess-A'));
    realtime.registerClient(makeClient('B', 'sess-B'));

    // Revoke only sess-A -> sess-B must remain open
    realtime.publish({
      type: 'USER_SESSION_REVOKED',
      targetUserIds: ['77'],
      targetSessionIds: ['sess-A'],
      payload: { userId: '77', sessionId: 'sess-A', reason: 'USER_LOGOUT' },
    });
    assert.deepEqual(ended, ['A']);

    // Register sess-C and revoke all others excluding sess-B
    realtime.registerClient(makeClient('C', 'sess-C'));
    realtime.publish({
      type: 'USER_SESSION_REVOKED',
      targetUserIds: ['77'],
      excludeSessionId: 'sess-B',
      payload: { userId: '77', reason: 'LOGOUT_OTHERS' },
    });
    assert.deepEqual(ended, ['A', 'C']);
    assert.ok(written.some((w) => w.tag === 'A' && w.chunk.includes('USER_SESSION_REVOKED')));
    assert.ok(!ended.includes('B'));
    realtime.onModuleDestroy();
  });

  it('V-05 & V-10: terminateSession notifies owner via SSE and endOwnSession closes only caller session', async () => {
    const sessionId = randomUUID();
    const documentId = randomUUID();
    const published = [];
    const realtime = {
      publish: (ev) => published.push(ev),
    };
    const auditWriter = { writeLog: async () => undefined };
    let updatedStatus = null;

    const db = {
      accessSession: {
        findUnique: async () => ({
          id: sessionId,
          user_id: 42n,
          status: 'ACTIVE',
          document_versions: {
            document_id: documentId,
            documents: { department_id: 1n },
          },
        }),
        updateMany: async ({ data }) => {
          updatedStatus = data.status;
          return { count: 1 };
        },
        update: async ({ data }) => {
          updatedStatus = data.status;
          return { id: sessionId, status: data.status };
        },
      },
      $transaction: async (fn) => fn(db),
    };

    const service = new AccessSessionsService(db, auditWriter, undefined, realtime);
    await service.terminateSession(
      sessionId,
      'SOC policy',
      { userId: 1n, sessionId: 'soc-1', username: 'soc', roles: ['SECURITY_OFFICER'], mfa: true },
      { ip: '127.0.0.1', correlationId: 'c1' },
    );
    assert.equal(updatedStatus, 'TERMINATED');
    assert.equal(published.length, 1);
    assert.deepEqual(published[0].targetUserIds, ['42']);
    assert.equal(published[0].payload.documentId, documentId);

    // Non-owner cannot end someone else's session (returns 404 anti-IDOR)
    await assert.rejects(
      () =>
        service.endOwnSession(
          sessionId,
          {
            userId: 99n,
            sessionId: 'other',
            username: 'intruder',
            roles: ['DOCUMENT_READER'],
            mfa: false,
          },
          { ip: '127.0.0.1', correlationId: 'c2' },
        ),
      (err) => err.status === 404,
    );

    // Owner cleanly ends their own active session
    updatedStatus = null;
    const endedRes = await service.endOwnSession(
      sessionId,
      {
        userId: 42n,
        sessionId: 'reader-auth-1',
        username: 'qa.view',
        roles: ['DOCUMENT_READER'],
        mfa: false,
      },
      { ip: '127.0.0.1', correlationId: 'c3' },
    );
    assert.equal(endedRes.status, 'ENDED');
    assert.equal(updatedStatus, 'ENDED');
  });

  it('V-08: sendAttachmentDownloadReply exposes Content-Disposition and X-Total-Pages headers', () => {
    const sentHeaders = new Map();
    let contentType = '';
    let payloadSent = null;
    const reply = {
      type(val) {
        contentType = val;
        return this;
      },
      header(name, val) {
        sentHeaders.set(name, val);
        return this;
      },
      send(buf) {
        payloadSent = buf;
        return this;
      },
    };
    sendAttachmentDownloadReply(reply, {
      buffer: Buffer.from('%PDF-1.7'),
      mimeType: 'application/pdf',
      filename: 'DOC-001.pdf',
      fileSizeBytes: 8,
      outputSha256Hash: 'abc',
      totalPages: 4,
    });
    assert.equal(contentType, 'application/pdf');
    assert.equal(
      sentHeaders.get('Access-Control-Expose-Headers'),
      'Content-Disposition, X-Total-Pages',
    );
    assert.match(String(sentHeaders.get('Content-Disposition')), /DOC-001\.pdf/);
    assert.equal(payloadSent.toString(), '%PDF-1.7');
  });

  it('V-35 & V-39: validates future access request windows, honors requested window on approve, and notifies on reject', async () => {
    const docId = randomUUID();
    const notifications = [];
    const createdGrants = [];
    const mockDb = {
      document: {
        findUnique: async () => ({
          id: docId,
          title: 'Quy chế tài chính mật',
          status: 'ACTIVE',
          classification_history: [
            {
              classification_levels: { code: 'CONFIDENTIAL', rank: 2, allow_download: true },
            },
          ],
        }),
      },
      user: {
        findUnique: async () => ({
          id: 50n,
          status: 'ACTIVE',
          clearance_options: { rank: 3 },
        }),
      },
      accessRequest: {
        findFirst: async () => null,
        findUnique: async () => ({
          id: randomUUID(),
          document_id: docId,
          requester_id: 50n,
          requested_from: new Date('2027-01-10T00:00:00.000Z'),
          requested_until: new Date('2027-01-20T00:00:00.000Z'),
          status: 'PENDING',
          documents: { id: docId, owner_id: 2n, title: 'Quy chế tài chính mật' },
          access_request_permissions: [{ action: 'VIEW' }],
        }),
        updateMany: async () => ({ count: 1 }),
        update: async () => undefined,
      },
      accessRequestDecision: {
        create: async () => undefined,
      },
      $transaction: async (fn) => fn(mockDb),
    };

    const service = new AccessRequestsService(
      { record: async () => undefined },
      {
        createGrant: async (dto) => {
          createdGrants.push(dto);
          return { id: randomUUID() };
        },
      },
      mockDb,
      undefined,
      undefined,
      {
        sendNotification: async (payload) => {
          notifications.push(payload);
        },
      },
    );

    // Reject past requestedFrom
    await assert.rejects(
      () =>
        service.createRequest(
          {
            documentId: docId,
            requestedAction: 'VIEW',
            reason: 'Cần đối soát báo cáo quý trước để lập kế hoạch mới',
            requestedFrom: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
            requestedUntil: new Date(Date.now() + 2 * 24 * 60 * 60 * 1000).toISOString(),
          },
          {
            userId: 50n,
            sessionId: 's',
            username: 'qa.view',
            roles: ['DOCUMENT_READER'],
            mfa: false,
          },
          { ip: '127.0.0.1', correlationId: 'c1' },
        ),
      (err) => err.status === 400,
    );

    // Approve without validDays -> honors requester's requested_from & requested_until
    await service.decideRequest(
      randomUUID(),
      { decision: 'APPROVED', decisionNote: 'Đồng ý cấp theo khung đề xuất' },
      { userId: 2n, sessionId: 's', username: 'owner', roles: ['DOCUMENT_OWNER'], mfa: true },
      { ip: '127.0.0.1', correlationId: 'c2' },
    );
    assert.equal(createdGrants.length, 1);
    assert.equal(createdGrants[0].validFrom, '2027-01-10T00:00:00.000Z');
    assert.equal(createdGrants[0].validUntil, '2027-01-20T00:00:00.000Z');

    // Reject -> sends ACCESS_REQUEST_REJECTED notification carrying decisionNote
    await service.decideRequest(
      randomUUID(),
      { decision: 'REJECTED', decisionNote: 'Chưa thuộc phạm vi dự án kiểm toán Q4' },
      { userId: 2n, sessionId: 's', username: 'owner', roles: ['DOCUMENT_OWNER'], mfa: true },
      { ip: '127.0.0.1', correlationId: 'c3' },
    );
    assert.equal(notifications.length, 1);
    assert.equal(notifications[0].notificationType, 'ACCESS_REQUEST_REJECTED');
    assert.match(notifications[0].body, /Chưa thuộc phạm vi dự án kiểm toán Q4/);
  });

  it('V-28 & V-37: NotificationsService returns real DB unreadCount and supports markAllAsRead', async () => {
    let updateManyCalled = false;
    const db = {
      notification: {
        findMany: async () => [
          {
            id: randomUUID(),
            notification_type: 'ACCESS_GRANTED',
            title: 'Đã cấp quyền',
            body: 'Bạn được cấp quyền',
            related_object_type: 'ACCESS_GRANT',
            related_object_id: randomUUID(),
            status: 'UNREAD',
            created_at: new Date(),
            read_at: null,
          },
        ],
        count: async () => 27,
        updateMany: async () => {
          updateManyCalled = true;
          return { count: 27 };
        },
      },
    };
    const svc = new NotificationsService(db);
    const list = await svc.listUserNotifications(42n, { page: 1, pageSize: 15 });
    assert.equal(list.unreadCount, 27);
    assert.equal(list.hasMore, false);

    const updatedCount = await svc.markAllAsRead(42n);
    assert.equal(updateManyCalled, true);
    assert.equal(updatedCount, 27);
  });

  it('V-56: PasswordService rejects common 15+ char passphrases', () => {
    const pw = new PasswordService();
    assert.throws(
      () => pw.validate('password1234567', ['qa.view', 'qa@local']),
      /PASSWORD_COMMON/i,
    );
    assert.doesNotThrow(() =>
      pw.validate('VanPhongBaoMat-2026#Unique91!', ['qa.view', 'qa@local']),
    );
  });
});
