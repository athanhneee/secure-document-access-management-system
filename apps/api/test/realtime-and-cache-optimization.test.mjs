import 'reflect-metadata';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { describe, it } from 'node:test';
import { Reflector } from '@nestjs/core';
import { AuthGuard } from '../dist/modules/auth/auth.guard.js';
import { TokenService } from '../dist/modules/auth/token.service.js';
import { DistributedStateService } from '../dist/modules/concurrency/distributed-state.service.js';
import { AuthorizationCache } from '../dist/modules/rbac/authorization-cache.js';
import { RealtimeEventsService } from '../dist/modules/realtime/realtime-events.service.js';
import { config } from './helpers/auth-security-mocks.mjs';

/**
 * Thuật toán: Kiểm Chứng Bộ Nhớ Đệm L1 + Thu Hồi Tức Thì Qua Pub/Sub Và Cô Lập Đối Tượng Kênh SSE Zero-Trust (`realtime-and-cache-optimization`)
 * Mục đích:
 *   1. Xác minh `AuthGuard` sử dụng bộ nhớ đệm L1 nội bộ (TTL 60s, 0 truy vấn DB lặp lại) và thu hồi tức thì khi `auth-user:<id>`, `auth-global` hoặc `auth-session:<sid>` bị xóa/tăng epoch.
 *   2. Xác minh `AuthorizationCache` sử dụng L1 cache 60s kèm thu hồi tức thì khi tăng epoch `rbac-user:<id>` hoặc `rbac-global` mà vẫn kẹp trần `valid_to`.
 *   3. Xác minh `RealtimeEventsService` phân phát sự kiện SSE đúng phạm vi `targetUserIds`/`targetRoles`, gọt bỏ trường định tuyến khỏi khung SSE gửi xuống trình duyệt và chặn mặc định (fail-closed) mọi sự kiện không khai báo đích.
 */
describe('L1 Cache + Instant Revocation & Zero-Trust SSE Audience Scoping', () => {
  it('AuthGuard serves L1 cache hits in 0 DB round-trips and revokes immediately on user/session/global invalidation', async () => {
    const tokens = new TokenService(config());
    const stateStore = new DistributedStateService();
    const sessionId = randomUUID();
    let repoLookups = 0;

    const guard = new AuthGuard(
      new Reflector(),
      tokens,
      {
        principalForSession: async () => {
          repoLookups += 1;
          return {
            userId: 42n,
            sessionId,
            username: 'alice',
            roles: ['DOCUMENT_READER'],
            mfa: true,
            mfaPending: false,
          };
        },
        touchSessionActivity: async () => undefined,
      },
      undefined,
      config({ AUTH_SESSION_TOUCH_INTERVAL_SECONDS: 60 }),
      stateStore,
    );

    const accessToken = await tokens.issueAccessToken(42n, sessionId, true);
    const handler = () => undefined;
    class DummyController {}
    const makeContext = () => ({
      getHandler: () => handler,
      getClass: () => DummyController,
      switchToHttp: () => ({
        getRequest: () => ({ cookies: { sda_access: accessToken }, ip: '203.0.113.10' }),
      }),
    });

    assert.equal(await guard.canActivate(makeContext()), true);
    assert.equal(repoLookups, 1);

    // L1 hit: zero repository calls
    assert.equal(await guard.canActivate(makeContext()), true);
    assert.equal(await guard.canActivate(makeContext()), true);
    assert.equal(repoLookups, 1);

    // User lock / status change invalidation -> immediate L1 eviction
    await stateStore.bumpNamespaceEpoch('auth-user:42');
    assert.equal(await guard.canActivate(makeContext()), true);
    assert.equal(repoLookups, 2);

    // Single session logout -> immediate L1 eviction
    await stateStore.deleteKey('auth-session', sessionId);
    assert.equal(await guard.canActivate(makeContext()), true);
    assert.equal(repoLookups, 3);

    // Global emergency revocation -> immediate L1 flush
    await stateStore.bumpNamespaceEpoch('auth-global');
    assert.equal(await guard.canActivate(makeContext()), true);
    assert.equal(repoLookups, 4);

    guard.onModuleDestroy();
    await stateStore.onModuleDestroy();
  });

  it('AuthorizationCache hits L1 across calls and invalidates immediately on user/global RBAC epoch bump', async () => {
    const stateStore = new DistributedStateService();
    const cache = new AuthorizationCache(undefined, stateStore);
    const grant = {
      permissionId: 10n,
      code: 'DOCUMENT_VIEW',
      resource: 'DOCUMENT',
      action: 'VIEW',
      roleId: 1n,
      roleCode: 'DOCUMENT_READER',
      scopeDepartmentId: null,
      validTo: new Date(Date.now() + 300_000),
    };

    await cache.set(77n, [grant]);
    const hit = await cache.get(77n);
    assert.equal(hit?.length, 1);
    assert.equal(hit?.[0]?.code, 'DOCUMENT_VIEW');

    await cache.invalidateUser(77n);
    assert.equal(await cache.get(77n), undefined);

    await cache.set(77n, [grant]);
    assert.equal((await cache.get(77n))?.length, 1);

    await cache.invalidateAll();
    assert.equal(await cache.get(77n), undefined);

    cache.onModuleDestroy();
    await stateStore.onModuleDestroy();
  });

  it('RealtimeEventsService enforces Zero-Trust user/role audience scoping and strips routing metadata', async () => {
    const stateStore = new DistributedStateService();
    const realtime = new RealtimeEventsService(stateStore);

    const readerChunks = [];
    const ownerChunks = [];
    const socChunks = [];

    const flushAsyncPublish = () => new Promise((resolve) => setImmediate(resolve));

    const readerId = realtime.registerClient({
      userId: '10',
      roles: ['DOCUMENT_READER'],
      writeFrame: (frame) => {
        readerChunks.push(frame);
        return true;
      },
      close: () => undefined,
    });
    const ownerId = realtime.registerClient({
      userId: '20',
      roles: ['DOCUMENT_OWNER'],
      writeFrame: (frame) => {
        ownerChunks.push(frame);
        return true;
      },
      close: () => undefined,
    });
    const socId = realtime.registerClient({
      userId: '30',
      roles: ['SECURITY_OFFICER'],
      writeFrame: (frame) => {
        socChunks.push(frame);
        return true;
      },
      close: () => undefined,
    });

    // 1. User-targeted event must only reach user 10
    realtime.publish({
      type: 'NOTIFICATION_CREATED',
      targetUserIds: ['10'],
      payload: { id: 'notif-1', title: 'Cấp quyền thành công' },
    });
    await flushAsyncPublish();

    assert.equal(readerChunks.length, 1);
    assert.equal(ownerChunks.length, 0);
    assert.equal(socChunks.length, 0);
    assert.match(readerChunks[0], /^event: NOTIFICATION_CREATED\n/m);
    assert.doesNotMatch(readerChunks[0], /targetUserIds|targetRoles/);

    // 2. Role-targeted event must only reach SECURITY_OFFICER
    realtime.publish({
      type: 'SECURITY_ALERT_UPDATED',
      targetRoles: ['SECURITY_OFFICER'],
      payload: { id: 'alert-99', status: 'OPEN', action: 'CREATED' },
    });
    await flushAsyncPublish();

    assert.equal(readerChunks.length, 1);
    assert.equal(ownerChunks.length, 0);
    assert.equal(socChunks.length, 1);
    assert.match(socChunks[0], /^event: SECURITY_ALERT_UPDATED\n/m);

    // 3. Fail-closed: event with empty/missing target audience must be dropped
    realtime.publish({
      type: 'ACCESS_GRANT_UPDATED',
      payload: { id: 'grant-leak' },
    });
    await flushAsyncPublish();

    assert.equal(readerChunks.length, 1);
    assert.equal(ownerChunks.length, 0);
    assert.equal(socChunks.length, 1);

    realtime.unregisterClient(readerId);
    realtime.unregisterClient(ownerId);
    realtime.unregisterClient(socId);
    realtime.onModuleDestroy();
    await stateStore.onModuleDestroy();
  });
});
