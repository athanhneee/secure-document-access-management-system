import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  applyOptimisticPolicyActivate,
  applyOptimisticRoleDisable,
  applyOptimisticStatusById,
  applyOptimisticUserStatus,
  removeOptimisticById,
} from '../../apps/web/lib/optimistic-state.ts';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const webRoot = path.resolve(__dirname, '../../apps/web');

/**
 * Thuật toán: Kiểm Chứng Ngưỡng Phản Hồi Tức Thì `< 100ms` (0,1s), Bất Biến Optimistic Rollback & Mở Hộp Thoại Không Chặn
 * Mục đích: Đảm bảo mọi phép biến đổi trạng thái lạc quan bảo toàn ảnh chụp gốc phục vụ hoàn tác (`rollback`), mọi thời lượng chuyển cảnh Tab/Modal/Nút bấm nằm trong ngân sách `<= 100ms`, hộp thoại xem trước mở ngay trước lệnh `await` mạng và chuyển trang Sidebar không gọi lặp `/users/me`.
 */
describe('Optimistic State Transitions & Lossless Rollback Invariants', () => {
  it('transitions user status (lock/unlock/disable) with OCC version bump while preserving snapshot immutably', () => {
    const snapshot = Object.freeze([
      Object.freeze({ id: 'u-1', status: 'ACTIVE', version: 3 }),
      Object.freeze({ id: 'u-2', status: 'LOCKED', version: 7 }),
    ]);

    const locked = applyOptimisticUserStatus(snapshot, 'u-1', 'lock');
    assert.deepEqual(locked, [
      { id: 'u-1', status: 'LOCKED', version: 4 },
      { id: 'u-2', status: 'LOCKED', version: 7 },
    ]);

    const unlocked = applyOptimisticUserStatus(snapshot, 'u-2', 'unlock');
    assert.equal(unlocked[1].status, 'ACTIVE');
    assert.equal(unlocked[1].version, 8);

    const disabled = applyOptimisticUserStatus(snapshot, 'u-1', 'disable');
    assert.equal(disabled[0].status, 'DISABLED');
    assert.equal(snapshot[0].status, 'ACTIVE');
    assert.equal(snapshot[0].version, 3);
  });

  it('applies optimistic role disable, policy activation, status transitions, and queue removal immutably', () => {
    const rolesSnapshot = Object.freeze([Object.freeze({ id: 'r-1', isActive: true, version: 1 })]);
    const nextRoles = applyOptimisticRoleDisable(rolesSnapshot, 'r-1');
    assert.deepEqual(nextRoles, [{ id: 'r-1', isActive: false, version: 2 }]);
    assert.equal(rolesSnapshot[0].isActive, true);

    const policiesSnapshot = Object.freeze([{ id: '10', isActive: false }]);
    assert.deepEqual(applyOptimisticPolicyActivate(policiesSnapshot, '10'), [
      { id: '10', isActive: true },
    ]);

    const docsSnapshot = Object.freeze([
      { id: 'd-1', status: 'DRAFT' },
      { id: 'd-2', status: 'ACTIVE' },
    ]);
    assert.deepEqual(applyOptimisticStatusById(docsSnapshot, 'd-1', 'ACTIVE'), [
      { id: 'd-1', status: 'ACTIVE' },
      { id: 'd-2', status: 'ACTIVE' },
    ]);
    assert.deepEqual(removeOptimisticById(docsSnapshot, 'd-1'), [{ id: 'd-2', status: 'ACTIVE' }]);
    assert.equal(docsSnapshot.length, 2);
  });
});

describe('Sub-100ms (< 0.1s) UI Feedback, Instant Modal/Tab & Navigation Gates', () => {
  it('keeps tab, modal, and tactile press CSS durations within <= 100ms budget', () => {
    const animationsCss = fs.readFileSync(path.join(webRoot, 'app/styles/animations.css'), 'utf8');
    const surfacesCss = fs.readFileSync(path.join(webRoot, 'app/styles/surfaces.css'), 'utf8');

    const tabMatch = animationsCss.match(/\.animate-tab-enter\s*\{[^}]*?(\d+)ms/s);
    const modalMatch = animationsCss.match(/\.animate-modal-enter\s*\{[^}]*?(\d+)ms/s);
    const animateInMatch = animationsCss.match(
      /\.animate-in\s*\{[^}]*?animation-duration:\s*(\d+)ms/s,
    );
    assert.ok(tabMatch && Number(tabMatch[1]) <= 100, 'Tab enter animation must be <= 100ms');
    assert.ok(modalMatch && Number(modalMatch[1]) <= 100, 'Modal enter animation must be <= 100ms');
    assert.ok(
      animateInMatch && Number(animateInMatch[1]) <= 100,
      '.animate-in utility duration must be <= 100ms',
    );

    const ihbMatch = surfacesCss.match(/\.ihb-button\s*\{([^}]*)\}/s);
    assert.ok(ihbMatch, '.ihb-button class must exist');
    const durations = [...ihbMatch[1].matchAll(/(\d+)ms/g)].map((m) => Number(m[1]));
    assert.ok(durations.length > 0 && durations.every((ms) => ms <= 100));

    const tabsTsx = fs.readFileSync(path.join(webRoot, 'components/ui/tabs.tsx'), 'utf8');
    const dialogTsx = fs.readFileSync(path.join(webRoot, 'components/ui/dialog.tsx'), 'utf8');
    assert.match(tabsTsx, /animate-tab-enter/);
    assert.doesNotMatch(tabsTsx, /animate-fade-in-up/);
    assert.match(dialogTsx, /animate-modal-enter/);
    assert.doesNotMatch(dialogTsx, /animate-scale-in/);
  });

  it('tracks async Promise clicks automatically in Button and InteractiveHoverButton', () => {
    for (const rel of ['components/ui/button.tsx', 'components/ui/interactive-hover-button.tsx']) {
      const content = fs.readFileSync(path.join(webRoot, rel), 'utf8');
      assert.match(content, /function isPromiseLike\(/);
      assert.match(content, /setAutoPending\(true\)/);
      assert.match(content, /aria-busy=\{effectiveLoading/);
    }
  });

  it('opens preview modals synchronously before awaiting session creation and avoids /users/me refetch on pathname change', () => {
    for (const rel of [
      'app/reader/hooks/use-reader-viewer.ts',
      'app/owner/hooks/use-owner-delivery.ts',
    ]) {
      const content = fs.readFileSync(path.join(webRoot, rel), 'utf8');
      const [, fnBody = ''] = content.split('async function handleOpenPreview');
      const openIdx = fnBody.indexOf('setPreviewOpen(true)');
      const awaitIdx = fnBody.indexOf('await apiClient');
      assert.ok(
        openIdx > -1 && awaitIdx > -1 && openIdx < awaitIdx,
        `${rel} must open preview modal before awaiting session API`,
      );
    }

    const authContext = fs.readFileSync(path.join(webRoot, 'lib/auth-context.tsx'), 'utf8');
    const refreshMatch = authContext.match(
      /const refreshUser = useCallback\([\s\S]*?,\s*\[([^\]]*)\]\s*\)/,
    );
    assert.ok(refreshMatch, 'refreshUser useCallback must exist');
    assert.doesNotMatch(refreshMatch[1], /pathname/);
  });
});
