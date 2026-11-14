/**
 * Thuật toán: Bộ dữ liệu giả lập kiểm thử ủy quyền `SYSTEM_ADMIN` & Trần đặc quyền RBAC
 * Mục đích: Khởi tạo mock giao dịch CSDL, `AuthorizationService` nghiêm ngặt và danh tính quản trị viên cho bài test phân tách trách nhiệm (SoD).
 */
import { ForbiddenException } from '@nestjs/common';

export function createSysAdminDelegationHarness() {
  let overlappingRoles = [];
  const docReaderRole = {
    id: 2n,
    code: 'DOCUMENT_READER',
    is_active: true,
    role_permissions: [
      {
        permission_id: 201n,
        permissions: { id: 201n, code: 'DOCUMENT_VIEW', resource_type: 'DOCUMENT', action: 'VIEW' },
      },
    ],
  };
  const mockDb = {
    $transaction: async (fn) =>
      fn({
        user: { findUnique: async () => ({ id: 88n, status: 'ACTIVE', department_id: 10n }) },
        role: { findFirst: async () => docReaderRole },
        userRole: {
          findMany: async () => overlappingRoles,
          create: async ({ data }) => ({ id: 901n, ...data }),
        },
        department: { findFirst: async () => ({ id: 10n, is_active: true }) },
      }),
  };
  const makeGrant = (code, resource, action, roleCode) => ({
    permissionId: 1n,
    code,
    resource,
    action,
    roleId: 1n,
    roleCode,
    scopeDepartmentId: null,
    validTo: null,
  });
  const strictAuthz = {
    effectiveGrants: async (uid) =>
      uid === 1n
        ? [
            makeGrant('ROLE_MANAGE', 'ROLE', 'MANAGE', 'SYSTEM_ADMIN'),
            makeGrant('USER_MANAGE', 'USER', 'MANAGE', 'SYSTEM_ADMIN'),
          ]
        : [makeGrant('ROLE_MANAGE', 'ROLE', 'MANAGE', 'CUSTOM_DELEGATED_ADMIN')],
    assertPermission: async () => undefined,
    assertCanDelegate: async () => {
      throw new ForbiddenException('Cannot delegate permissions outside the administrator grant.');
    },
    departmentWithinScope: async () => true,
    invalidateUser: async () => undefined,
  };
  return {
    mockDb,
    strictAuthz,
    audit: { record: async () => undefined },
    setOverlappingRoles: (next) => {
      overlappingRoles = next;
    },
    sysAdmin: {
      userId: 1n,
      sessionId: 's-sys',
      username: 'sysadmin',
      roles: ['SYSTEM_ADMIN'],
      mfa: true,
    },
    customAdmin: {
      userId: 2n,
      sessionId: 's-custom',
      username: 'delegated.admin',
      roles: ['CUSTOM_DELEGATED_ADMIN'],
      mfa: true,
    },
    ctx: { ip: '10.0.0.1', correlationId: 'corr-sod-sysadmin' },
    input: {
      roleId: 2n,
      scopeDepartmentId: 10n,
      validFrom: new Date('2026-10-01T00:00:00Z'),
      validTo: null,
    },
  };
}
