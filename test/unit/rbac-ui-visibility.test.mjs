import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  checkEffectivePermission,
  ROLE_DEFAULT_PERMISSIONS,
} from '../../apps/web/lib/role-permissions.ts';
import {
  PERMISSION_LABELS_BY_CODE,
  resolvePermissionLabel,
  resolvePermissionScopeLabel,
} from '../../apps/web/lib/permission-labels.ts';
import { permissions as seedPermissions } from '../../packages/database/prisma/seed-catalog.ts';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const webRoot = path.resolve(__dirname, '../../apps/web');

/**
 * Thuật toán: Kiểm Chứng Ẩn Tuyệt Đối Mục Không Có Quyền, Cô Lập Hook Sau `AuthGuard` & Chống Tự Động Đăng Xuất Khi `403`
 * Mục đích: Đảm bảo toàn bộ giao diện tuân thủ nghiêm ngặt quy tắc Least-Privilege UI — không hiển thị mục bị khóa gây hiểu nhầm và không xóa phiên người dùng khi gặp lỗi phân quyền `403`.
 */
describe('RBAC Least-Privilege UI Visibility & Non-Logout 403 Invariants', () => {
  it('evaluates explicit user.permissions strictly when present and falls back to ROLE_DEFAULT_PERMISSIONS when empty', () => {
    assert.equal(checkEffectivePermission(null, 'DOCUMENT:VIEW'), false);

    // Scoped custom role with explicit permissions array must NOT inherit extra role defaults
    const customScopedOwner = {
      roles: ['DOCUMENT_OWNER'],
      permissions: ['DOCUMENT:VIEW'],
    };
    assert.equal(checkEffectivePermission(customScopedOwner, 'DOCUMENT:VIEW'), true);
    assert.equal(checkEffectivePermission(customScopedOwner, 'DOCUMENT_VIEW'), true);
    assert.equal(checkEffectivePermission(customScopedOwner, 'DOCUMENT:UPLOAD'), false);

    // System role session with empty permissions array (e.g. E2E role mock) resolves exact role matrix
    const ownerRoleOnly = { roles: ['DOCUMENT_OWNER'], permissions: [] };
    assert.equal(checkEffectivePermission(ownerRoleOnly, 'DOCUMENT:UPLOAD'), true);
    assert.equal(checkEffectivePermission(ownerRoleOnly, 'NOTIFICATION:VIEW'), true);
    assert.equal(checkEffectivePermission(ownerRoleOnly, 'USER:MANAGE'), false);

    // Separation of Duties: SYSTEM_ADMIN, SECURITY_OFFICER, AUDITOR lack NOTIFICATION:VIEW and DOCUMENT:VIEW
    for (const sodRole of ['SYSTEM_ADMIN', 'SECURITY_OFFICER', 'AUDITOR']) {
      const principal = { roles: [sodRole], permissions: [] };
      assert.equal(
        checkEffectivePermission(principal, 'NOTIFICATION:VIEW'),
        false,
        `${sodRole} must not receive NOTIFICATION:VIEW`,
      );
      assert.equal(
        checkEffectivePermission(principal, 'DOCUMENT:VIEW'),
        false,
        `${sodRole} must not receive DOCUMENT:VIEW`,
      );
      assert.ok(ROLE_DEFAULT_PERMISSIONS[sodRole].length > 0);
    }
  });

  it('never clears authenticated user state on 403 Forbidden inside AuthProvider.refreshUser', () => {
    const authContext = fs.readFileSync(path.join(webRoot, 'lib/auth-context.tsx'), 'utf8');
    assert.doesNotMatch(authContext, /err\.status\s*===\s*403/);
    assert.match(authContext, /err\.status\s*===\s*401/);
  });

  it('hides unauthorized role portals in SidebarDirectory and AppHeader without rendering locked items', () => {
    const sidebar = fs.readFileSync(
      path.join(webRoot, 'components/navigation/sidebar-directory.tsx'),
      'utf8',
    );
    const header = fs.readFileSync(
      path.join(webRoot, 'components/navigation/app-header.tsx'),
      'utf8',
    );

    assert.match(sidebar, /NAV_ITEMS\.filter\(/);
    assert.doesNotMatch(sidebar, /Chưa gán vai trò/);

    assert.match(header, /ROLE_NAV_ITEMS\.filter\(/);
    assert.doesNotMatch(header, />Khóa</);
    assert.match(header, /canViewNotifications && \(\s*<NotificationBellDialog/);
  });

  it('isolates workspace data-fetching hooks inside AuthGuard so unauthorized routes fire zero API calls', () => {
    const guardedWorkspaces = [
      { file: 'app/admin/workspace.tsx', hook: '= useAdminData()' },
      { file: 'app/owner/owner-workspace.tsx', hook: '= useOwnerData()' },
      { file: 'app/reader/reader-workspace.tsx', hook: '= useReaderCatalog()' },
      { file: 'app/security/security-workspace.tsx', hook: '= useSecurityData()' },
      { file: 'app/auditor/auditor-workspace.tsx', hook: '= useAuditorData()' },
      { file: 'app/sessions/page.tsx', hook: 'const loadActiveSessions =' },
    ];

    for (const { file, hook } of guardedWorkspaces) {
      const content = fs.readFileSync(path.join(webRoot, file), 'utf8');
      const guardIdx = content.indexOf('<AuthGuard');
      const hookIdx = content.indexOf(hook);
      assert.ok(
        guardIdx > -1 && hookIdx > guardIdx,
        `${file} must render <AuthGuard> in outer wrapper before invoking ${hook} inside authorized content component`,
      );
    }
  });

  it('localizes all 34 RBAC permission codes and resource-action scopes into Vietnamese across RolesTab and RolePermissionsModal', () => {
    assert.equal(Object.keys(PERMISSION_LABELS_BY_CODE).length, 34);
    assert.equal(seedPermissions.length, 34);

    assert.equal(
      resolvePermissionLabel({ code: 'ALERT_VIEW', name: 'ALERT_VIEW' }),
      'Xem cảnh báo an ninh',
    );
    assert.equal(
      resolvePermissionLabel({ code: 'AUDIT_EXPORT', name: 'AUDIT_EXPORT' }),
      'Xuất nhật ký kiểm toán',
    );
    assert.equal(
      resolvePermissionLabel({ code: 'AUDIT_VIEW', name: 'AUDIT_VIEW' }),
      'Xem nhật ký kiểm toán',
    );
    assert.equal(
      resolvePermissionLabel({ code: 'SYSTEM_REPORT_EXPORT', name: 'SYSTEM_REPORT_EXPORT' }),
      'Xuất báo cáo hệ thống',
    );
    assert.equal(
      resolvePermissionLabel({ code: 'WATERMARK_TRACE', name: 'WATERMARK_TRACE' }),
      'Truy vết watermark',
    );

    for (const [code, resourceType, action, seededVietnameseName] of seedPermissions) {
      assert.equal(PERMISSION_LABELS_BY_CODE[code], seededVietnameseName);
      assert.equal(resolvePermissionLabel({ code, name: code }), seededVietnameseName);
      const scopeLabel = resolvePermissionScopeLabel({ resourceType, action });
      assert.ok(scopeLabel.includes(' · '), `Missing scope separator for ${code}: ${scopeLabel}`);
      assert.doesNotMatch(scopeLabel, /^[A-Z_]+\s*·\s*[A-Z_]+$/);
    }

    assert.equal(
      resolvePermissionLabel({ code: 'CUSTOM_REVIEW', name: 'Thẩm định hồ sơ đặc biệt' }),
      'Thẩm định hồ sơ đặc biệt',
    );

    const rolesTab = fs.readFileSync(path.join(webRoot, 'app/admin/tabs/roles-tab.tsx'), 'utf8');
    const rolePermModal = fs.readFileSync(
      path.join(webRoot, 'app/admin/modals/role-permissions-modal.tsx'),
      'utf8',
    );
    assert.match(rolesTab, /resolvePermissionLabel\(/);
    assert.doesNotMatch(rolesTab, /font-mono/);
    assert.match(rolePermModal, /resolvePermissionLabel\(/);
    assert.match(rolePermModal, /resolvePermissionScopeLabel\(/);
    assert.doesNotMatch(rolePermModal, /font-mono/);
  });
});
