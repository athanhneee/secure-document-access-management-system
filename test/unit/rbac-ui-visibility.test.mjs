import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  canAccessPortal,
  checkEffectivePermission,
  getAccessiblePortals,
  resolveDefaultPortalForUser,
  ROLE_DEFAULT_PERMISSIONS,
} from '../../apps/web/lib/role-permissions.ts';
import {
  isPermissionSodCompatibleWithSelection,
  resolveCompatibleSodArchetypes,
  SYSTEM_ROLE_ALLOWED_CODES,
} from '../../apps/web/lib/rbac-sod.ts';
import {
  PERMISSION_LABELS_BY_CODE,
  resolvePermissionLabel,
  resolvePermissionScopeLabel,
} from '../../apps/web/lib/permission-labels.ts';
import { SYSTEM_ROLE_PERMISSION_MATRIX } from '../../apps/api/dist/modules/rbac/permission-matrix.js';
import { permissions as seedPermissions } from '../../packages/database/prisma/seed-catalog.ts';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const webRoot = path.resolve(__dirname, '../../apps/web');

/**
 * Thuật toán: Kiểm Chứng Phân Quyền Nghiêm Ngặt Không Quyền Giả, Truy Cập Custom Role Vào 5 Phân Hệ & Lưới 4 Trụ Cột SoD
 * Mục đích:
 *   - Đảm bảo khi vai trò hệ thống bị gỡ sạch quyền (`permissions: []`), giao diện tuyệt đối không suy diễn quyền giả từ `ROLE_DEFAULT_PERMISSIONS`.
 *   - Đảm bảo vai trò tùy chỉnh (như `HR_MANAGER` có `USER:MANAGE`) vào đúng phân hệ tương ứng thay vì bị đẩy sang `/reader` nhận `403`.
 *   - Đảm bảo ma trận vai trò hệ thống & phân nhóm 4 trụ cột SoD ở Frontend khớp 1-1 với Backend `permission-matrix.ts`.
 */
describe('RBAC Least-Privilege UI Visibility, Custom Role Portals & Non-Logout 403 Invariants', () => {
  it('evaluates user.permissions strictly with ZERO fake fallback when permissions is empty', () => {
    assert.equal(checkEffectivePermission(null, 'DOCUMENT:VIEW'), false);

    // Stripping all permissions from a system role must yield FALSE for every permission and ZERO portals
    for (const sysRole of [
      'SYSTEM_ADMIN',
      'DOCUMENT_OWNER',
      'DOCUMENT_READER',
      'SECURITY_OFFICER',
      'AUDITOR',
    ]) {
      const stripped = { roles: [sysRole], permissions: [] };
      assert.equal(checkEffectivePermission(stripped, 'USER:MANAGE'), false);
      assert.equal(checkEffectivePermission(stripped, 'DOCUMENT:UPLOAD'), false);
      assert.equal(checkEffectivePermission(stripped, 'DOCUMENT:VIEW'), false);
      assert.equal(checkEffectivePermission(stripped, 'SECURITY_ALERT:VIEW'), false);
      assert.equal(checkEffectivePermission(stripped, 'AUDIT_LOG:VIEW'), false);
      assert.deepEqual(getAccessiblePortals(stripped), []);
      assert.equal(resolveDefaultPortalForUser(stripped), '/');
    }

    // Explicit permissions match both RESOURCE:ACTION and RESOURCE_ACTION tokens
    const customScopedOwner = {
      roles: ['DOCUMENT_OWNER'],
      permissions: ['DOCUMENT:VIEW'],
    };
    assert.equal(checkEffectivePermission(customScopedOwner, 'DOCUMENT:VIEW'), true);
    assert.equal(checkEffectivePermission(customScopedOwner, 'DOCUMENT_VIEW'), true);
    assert.equal(checkEffectivePermission(customScopedOwner, 'DOCUMENT:UPLOAD'), false);

    // Standard 5 system roles with their real permissions each unlock ONLY their dedicated portal
    const expectedSinglePortal = {
      SYSTEM_ADMIN: ['SYSTEM_ADMIN'],
      DOCUMENT_OWNER: ['DOCUMENT_OWNER'],
      DOCUMENT_READER: ['DOCUMENT_READER'],
      SECURITY_OFFICER: ['SECURITY_OFFICER'],
      AUDITOR: ['AUDITOR'],
    };
    for (const [role, portals] of Object.entries(expectedSinglePortal)) {
      const principal = { roles: [role], permissions: [...ROLE_DEFAULT_PERMISSIONS[role]] };
      assert.deepEqual(
        getAccessiblePortals(principal),
        portals,
        `${role} must only access its own portal`,
      );
    }
  });

  it('unlocks matching workspace portals and default landing routes for Custom Roles', () => {
    const hrManager = { roles: ['HR_MANAGER'], permissions: ['USER:MANAGE'] };
    assert.equal(canAccessPortal(hrManager, 'SYSTEM_ADMIN'), true);
    assert.equal(canAccessPortal(hrManager, 'DOCUMENT_READER'), false);
    assert.deepEqual(getAccessiblePortals(hrManager), ['SYSTEM_ADMIN']);
    assert.equal(resolveDefaultPortalForUser(hrManager), '/admin');

    const docUploader = {
      roles: ['DEPT_UPLOADER'],
      permissions: ['DOCUMENT:UPLOAD', 'DOCUMENT:DISCOVER', 'DOCUMENT:VIEW'],
    };
    assert.deepEqual(getAccessiblePortals(docUploader), ['DOCUMENT_OWNER']);
    assert.equal(resolveDefaultPortalForUser(docUploader), '/owner');

    const readOnlyViewer = {
      roles: ['EXTERNAL_READER'],
      permissions: ['DOCUMENT:DISCOVER', 'DOCUMENT:VIEW'],
    };
    assert.deepEqual(getAccessiblePortals(readOnlyViewer), ['DOCUMENT_READER']);
    assert.equal(resolveDefaultPortalForUser(readOnlyViewer), '/reader');

    const socAnalyst = {
      roles: ['SOC_TIER1'],
      permissions: ['SECURITY_ALERT:VIEW', 'WATERMARK_INSTANCE:TRACE'],
    };
    assert.deepEqual(getAccessiblePortals(socAnalyst), ['SECURITY_OFFICER']);
    assert.equal(resolveDefaultPortalForUser(socAnalyst), '/security');

    const auditViewer = {
      roles: ['COMPLIANCE_READER'],
      permissions: ['AUDIT_LOG:VIEW'],
    };
    assert.deepEqual(getAccessiblePortals(auditViewer), ['AUDITOR']);
    assert.equal(resolveDefaultPortalForUser(auditViewer), '/auditor');
  });

  it('synchronizes Frontend SoD matrix 1-to-1 with Backend permission-matrix.ts and blocks cross-pillar Custom Role mixing', () => {
    for (const [roleCode, backendPerms] of Object.entries(SYSTEM_ROLE_PERMISSION_MATRIX)) {
      const frontendSet = SYSTEM_ROLE_ALLOWED_CODES[roleCode];
      assert.ok(frontendSet, `Missing SYSTEM_ROLE_ALLOWED_CODES entry for ${roleCode}`);
      assert.deepEqual(
        [...frontendSet].sort(),
        [...backendPerms].sort(),
        `Frontend and Backend permission matrices must match for ${roleCode}`,
      );
    }

    // Selecting USER_MANAGE locks Custom Role to ADMIN_GOVERNANCE
    const adminSelection = resolveCompatibleSodArchetypes(['USER_MANAGE']);
    assert.deepEqual([...adminSelection], ['ADMIN_GOVERNANCE']);
    assert.equal(
      isPermissionSodCompatibleWithSelection({ code: 'DEPARTMENT_MANAGE' }, adminSelection),
      true,
    );
    assert.equal(
      isPermissionSodCompatibleWithSelection({ code: 'POLICY_SIMULATE' }, adminSelection),
      true,
    );
    assert.equal(
      isPermissionSodCompatibleWithSelection({ code: 'DOCUMENT_VIEW' }, adminSelection),
      false,
    );
    assert.equal(
      isPermissionSodCompatibleWithSelection({ code: 'ALERT_MANAGE' }, adminSelection),
      false,
    );
    assert.equal(
      isPermissionSodCompatibleWithSelection({ code: 'AUDIT_EXPORT' }, adminSelection),
      false,
    );

    // Selecting ALERT_VIEW + WATERMARK_TRACE remains compatible with SECURITY_SOC & AUDITOR_COMPLIANCE
    const sharedSecAudit = resolveCompatibleSodArchetypes(['ALERT_VIEW', 'WATERMARK_TRACE']);
    assert.deepEqual([...sharedSecAudit].sort(), ['AUDITOR_COMPLIANCE', 'SECURITY_SOC']);
    assert.equal(
      isPermissionSodCompatibleWithSelection({ code: 'USER_MANAGE' }, sharedSecAudit),
      false,
    );
  });

  it('never clears authenticated user state on 403 Forbidden inside AuthProvider.refreshUser', () => {
    const authContext = fs.readFileSync(path.join(webRoot, 'lib/auth-context.tsx'), 'utf8');
    assert.doesNotMatch(authContext, /err\.status\s*===\s*403/);
    assert.match(authContext, /err\.status\s*===\s*401/);
  });

  it('hides unauthorized portals via permission-based canAccessPortal in SidebarDirectory and AppHeader without rendering locked items', () => {
    const sidebar = fs.readFileSync(
      path.join(webRoot, 'components/navigation/sidebar-directory.tsx'),
      'utf8',
    );
    const header = fs.readFileSync(
      path.join(webRoot, 'components/navigation/app-header.tsx'),
      'utf8',
    );

    assert.match(sidebar, /NAV_ITEMS\.filter\(/);
    assert.match(sidebar, /canAccessPortal\(/);
    assert.doesNotMatch(sidebar, /Chưa gán vai trò/);

    assert.match(header, /ROLE_NAV_ITEMS\.filter\(/);
    assert.match(header, /canAccessPortal\(/);
    assert.doesNotMatch(header, />Khóa</);
    assert.match(header, /canViewNotifications && \(\s*<NotificationBellDialog/);
  });

  it('isolates workspace data-fetching hooks inside permission-based AuthGuard so unauthorized routes fire zero API calls', () => {
    const guardedWorkspaces = [
      { file: 'app/admin/workspace.tsx', hook: '= useAdminData(', portal: 'SYSTEM_ADMIN' },
      { file: 'app/owner/owner-workspace.tsx', hook: '= useOwnerData(', portal: 'DOCUMENT_OWNER' },
      {
        file: 'app/reader/reader-workspace.tsx',
        hook: '= useReaderCatalog()',
        portal: 'DOCUMENT_READER',
      },
      {
        file: 'app/security/security-workspace.tsx',
        hook: '= useSecurityData()',
        portal: 'SECURITY_OFFICER',
      },
      { file: 'app/auditor/auditor-workspace.tsx', hook: '= useAuditorData()', portal: 'AUDITOR' },
      { file: 'app/sessions/page.tsx', hook: 'const loadActiveSessions =' },
    ];

    for (const { file, hook, portal } of guardedWorkspaces) {
      const content = fs.readFileSync(path.join(webRoot, file), 'utf8');
      const guardIdx = content.indexOf('<AuthGuard');
      const hookIdx = content.indexOf(hook);
      assert.ok(
        guardIdx > -1 && hookIdx > guardIdx,
        `${file} must render <AuthGuard> in outer wrapper before invoking ${hook} inside authorized content component`,
      );
      if (portal) {
        assert.match(
          content,
          new RegExp(`<AuthGuard\\s+requiredPortal="${portal}"`, 'u'),
          `${file} must gate via permission-based requiredPortal="${portal}" instead of hardcoded requiredRole`,
        );
      }
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
    assert.match(rolePermModal, /isPermissionSodCompatibleWithSelection\(/);
    assert.doesNotMatch(rolePermModal, /font-mono/);
  });
});
