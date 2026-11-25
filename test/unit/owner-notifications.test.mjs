import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  applyIncomingNotificationToCache,
  parseWorkspaceTabTarget,
  resolveNotificationHref,
} from '../../apps/web/components/navigation/notification-routing.ts';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const webRoot = path.resolve(__dirname, '../../apps/web');

/**
 * Thuật toán: Kiểm Chứng Định Tuyến Thông Báo Theo Vai Trò & Cập Nhật SSE Nguyên Tử Không Tăng Kép (`owner-notifications`)
 * Mục đích: Đảm bảo Chủ sở hữu (`DOCUMENT_OWNER`) lẫn tài khoản kiêm nhiệm (`DOCUMENT_OWNER` + `DOCUMENT_READER`) luôn điều hướng đúng tab `/owner?tab=...` cho sự kiện sở hữu, không bị rò rỉ đường dẫn trái phân hệ và không gọi `setState` lồng nhau trong `NotificationBellDialog`.
 */
describe('Owner Notification Routing & Atomic SSE Cache Update', () => {
  it('routes owner notifications to /owner tabs and blocks unauthorized portal links', () => {
    const ownerOnly = { canAccessOwner: true, canAccessReader: false };
    const readerOnly = { canAccessOwner: false, canAccessReader: true };
    const dualRole = { canAccessOwner: true, canAccessReader: true };
    const adminOnly = { canAccessOwner: false, canAccessReader: false };

    assert.equal(
      resolveNotificationHref(
        { notificationType: 'ACCESS_REQUEST_CREATED', relatedObjectType: 'ACCESS_REQUEST' },
        ownerOnly,
      ),
      '/owner?tab=requests',
    );
    assert.equal(
      resolveNotificationHref(
        { notificationType: 'ACCESS_REQUEST_CREATED', relatedObjectType: 'ACCESS_REQUEST' },
        dualRole,
      ),
      '/owner?tab=requests',
    );
    assert.equal(
      resolveNotificationHref(
        { notificationType: 'ACCESS_REQUEST_CREATED', relatedObjectType: 'ACCESS_REQUEST' },
        readerOnly,
      ),
      null,
    );
    assert.equal(
      resolveNotificationHref(
        { notificationType: 'ACCESS_REQUEST_CANCELLED', relatedObjectType: 'ACCESS_REQUEST' },
        dualRole,
      ),
      '/owner?tab=requests',
    );
    assert.equal(
      resolveNotificationHref(
        { notificationType: 'DOCUMENT_OWNERSHIP_TRANSFERRED', relatedObjectType: 'DOCUMENT' },
        dualRole,
      ),
      '/owner?tab=documents',
    );
    assert.equal(
      resolveNotificationHref(
        { notificationType: 'RETENTION_EXPIRATION_WARNING', relatedObjectType: 'DOCUMENT' },
        ownerOnly,
      ),
      '/owner?tab=documents',
    );
    assert.equal(
      resolveNotificationHref(
        { notificationType: 'INCIDENT_REPORT_SUBMITTED', relatedObjectType: 'INCIDENT_REPORT' },
        ownerOnly,
      ),
      '/owner?tab=history',
    );

    assert.equal(
      resolveNotificationHref(
        { notificationType: 'ACCESS_GRANT_ISSUED', relatedObjectType: 'ACCESS_GRANT' },
        dualRole,
      ),
      '/reader?tab=my-docs',
    );
    assert.equal(
      resolveNotificationHref(
        { notificationType: 'ACCESS_REQUEST_REJECTED', relatedObjectType: 'ACCESS_REQUEST' },
        dualRole,
      ),
      '/reader?tab=my-requests',
    );
    assert.equal(
      resolveNotificationHref(
        { notificationType: 'ACCESS_REQUEST_CREATED', relatedObjectType: 'ACCESS_REQUEST' },
        adminOnly,
      ),
      null,
    );

    assert.deepEqual(parseWorkspaceTabTarget('/owner?tab=requests'), {
      path: '/owner',
      tab: 'requests',
    });
    assert.equal(parseWorkspaceTabTarget('/owner'), null);
  });

  it('deduplicates incoming SSE notifications and increments unreadCount atomically', () => {
    const initial = { items: [], unreadCount: 0, page: 1, hasMore: false };
    const notif = { id: 'n-1', status: 'UNREAD' };
    const afterFirst = applyIncomingNotificationToCache(initial, notif);
    assert.equal(afterFirst.items.length, 1);
    assert.equal(afterFirst.unreadCount, 1);

    // Duplicate delivery of the same notification id must not double-increment unreadCount
    const afterDuplicate = applyIncomingNotificationToCache(afterFirst, notif);
    assert.equal(afterDuplicate.items.length, 1);
    assert.equal(afterDuplicate.unreadCount, 1);

    // Verification that NotificationBellDialog no longer nests setUnreadCount inside setItems
    const bellSrc = fs.readFileSync(
      path.join(webRoot, 'components/navigation/notification-bell-dialog.tsx'),
      'utf8',
    );
    assert.match(bellSrc, /applyIncomingNotificationToCache/);
    assert.doesNotMatch(bellSrc, /setUnreadCount\(/);
  });
});
