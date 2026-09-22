import { createDatabaseClient } from '../src/client.js';
import { withSerializableTransaction } from '../src/transaction.js';

const client = createDatabaseClient();
const fixedSeedTime = new Date('2026-01-01T00:00:00.000Z');
const disabledPasswordHash = '!AUTHENTICATION_NOT_CONFIGURED_DEMO_ACCOUNT!';

const classificationLevels = [
  { code: 'INTERNAL', name: 'Nội bộ', rank: 1, allow_download: true },
  { code: 'CONFIDENTIAL', name: 'Mật', rank: 2, allow_download: true },
  { code: 'SECRET', name: 'Tối mật', rank: 3, allow_download: false },
  { code: 'TOP_SECRET', name: 'Tuyệt mật', rank: 4, allow_download: false },
] as const;

const systemRoles = [
  ['SYSTEM_ADMIN', 'Quản trị viên hệ thống'],
  ['SECURITY_OFFICER', 'Nhân viên bảo mật'],
  ['AUDITOR', 'Kiểm toán viên'],
  ['DOCUMENT_OWNER', 'Chủ sở hữu tài liệu'],
  ['DOCUMENT_READER', 'Người đọc tài liệu'],
] as const;

const permissions = [
  ['USER_MANAGE', 'USER', 'MANAGE'],
  ['DEPARTMENT_MANAGE', 'DEPARTMENT', 'MANAGE'],
  ['ROLE_MANAGE', 'ROLE', 'MANAGE'],
  ['ATTRIBUTE_MANAGE', 'ATTRIBUTE', 'MANAGE'],
  ['POLICY_MANAGE', 'POLICY', 'MANAGE'],
  ['POLICY_SIMULATE', 'POLICY', 'SIMULATE'],
  ['WATERMARK_CONFIG_MANAGE', 'WATERMARK_CONFIG', 'MANAGE'],
  ['SYSTEM_HEALTH_VIEW', 'SYSTEM_HEALTH', 'VIEW'],
  ['DOCUMENT_UPLOAD', 'DOCUMENT', 'UPLOAD'],
  ['DOCUMENT_CLASSIFY', 'DOCUMENT', 'CLASSIFY'],
  ['DOCUMENT_VERSION_CREATE', 'DOCUMENT_VERSION', 'CREATE'],
  ['DOCUMENT_ARCHIVE', 'DOCUMENT', 'ARCHIVE'],
  ['DOCUMENT_DISCOVER', 'DOCUMENT', 'DISCOVER'],
  ['DOCUMENT_VIEW', 'DOCUMENT', 'VIEW'],
  ['DOCUMENT_DOWNLOAD', 'DOCUMENT', 'DOWNLOAD'],
  ['ACCESS_REQUEST_CREATE', 'ACCESS_REQUEST', 'CREATE'],
  ['ACCESS_REQUEST_VIEW_OWN', 'ACCESS_REQUEST', 'VIEW_OWN'],
  ['ACCESS_REQUEST_CANCEL', 'ACCESS_REQUEST', 'CANCEL'],
  ['ACCESS_REQUEST_DECIDE', 'ACCESS_REQUEST', 'DECIDE'],
  ['ACCESS_GRANT_CREATE', 'ACCESS_GRANT', 'CREATE'],
  ['ACCESS_GRANT_REVOKE', 'ACCESS_GRANT', 'REVOKE'],
  ['ACCESS_GRANT_VIEW', 'ACCESS_GRANT', 'VIEW'],
  ['AUDIT_VIEW', 'AUDIT_LOG', 'VIEW'],
  ['AUDIT_EXPORT', 'AUDIT_LOG', 'EXPORT'],
  ['ALERT_VIEW', 'SECURITY_ALERT', 'VIEW'],
  ['ALERT_MANAGE', 'SECURITY_ALERT', 'MANAGE'],
  ['WATERMARK_TRACE', 'WATERMARK_INSTANCE', 'TRACE'],
  ['INCIDENT_CREATE', 'INCIDENT_REPORT', 'CREATE'],
  ['INCIDENT_MANAGE', 'INCIDENT_REPORT', 'MANAGE'],
  ['NOTIFICATION_VIEW', 'NOTIFICATION', 'VIEW'],
  ['SYSTEM_REPORT_EXPORT', 'SYSTEM_REPORT', 'EXPORT'],
  ['ACCESS_SESSION_TERMINATE', 'ACCESS_SESSION', 'TERMINATE'],
] as const;

const rolePermissionCodes: Record<(typeof systemRoles)[number][0], readonly string[]> = {
  SYSTEM_ADMIN: [
    'USER_MANAGE',
    'DEPARTMENT_MANAGE',
    'ROLE_MANAGE',
    'ATTRIBUTE_MANAGE',
    'POLICY_MANAGE',
    'POLICY_SIMULATE',
    'WATERMARK_CONFIG_MANAGE',
    'SYSTEM_HEALTH_VIEW',
  ],
  SECURITY_OFFICER: [
    'AUDIT_VIEW',
    'ALERT_VIEW',
    'ALERT_MANAGE',
    'WATERMARK_TRACE',
    'INCIDENT_CREATE',
    'INCIDENT_MANAGE',
    'ACCESS_SESSION_TERMINATE',
    'POLICY_SIMULATE',
  ],
  AUDITOR: ['AUDIT_VIEW', 'AUDIT_EXPORT', 'ALERT_VIEW', 'WATERMARK_TRACE', 'SYSTEM_REPORT_EXPORT'],
  DOCUMENT_OWNER: [
    'DOCUMENT_UPLOAD',
    'DOCUMENT_CLASSIFY',
    'DOCUMENT_VERSION_CREATE',
    'DOCUMENT_ARCHIVE',
    'ACCESS_REQUEST_DECIDE',
    'ACCESS_GRANT_CREATE',
    'ACCESS_GRANT_REVOKE',
    'ACCESS_GRANT_VIEW',
    'AUDIT_VIEW',
  ],
  DOCUMENT_READER: [
    'DOCUMENT_DISCOVER',
    'DOCUMENT_VIEW',
    'DOCUMENT_DOWNLOAD',
    'ACCESS_REQUEST_CREATE',
    'ACCESS_REQUEST_VIEW_OWN',
    'ACCESS_REQUEST_CANCEL',
    'NOTIFICATION_VIEW',
  ],
};

async function seed(): Promise<void> {
  await withSerializableTransaction(
    async (transaction) => {
      const seedActor = await transaction.user.upsert({
        where: { username: 'system.seed' },
        update: { full_name: 'System Seed Actor' },
        create: {
          username: 'system.seed',
          email: 'system.seed@local.invalid',
          password_hash: disabledPasswordHash,
          full_name: 'System Seed Actor',
          status: 'DISABLED',
          disabled_at: fixedSeedTime,
        },
      });

      const headquarters = await transaction.department.upsert({
        where: { code: 'HEAD_OFFICE' },
        update: { name: 'Khối văn phòng' },
        create: { code: 'HEAD_OFFICE', name: 'Khối văn phòng' },
      });
      const securityDepartment = await transaction.department.upsert({
        where: { code: 'INFORMATION_SECURITY' },
        update: { name: 'Phòng An toàn thông tin', parent_id: headquarters.id },
        create: {
          code: 'INFORMATION_SECURITY',
          name: 'Phòng An toàn thông tin',
          parent_id: headquarters.id,
        },
      });

      await transaction.businessCategory.upsert({
        where: { code: 'GENERAL_OPERATIONS' },
        update: { name: 'Nghiệp vụ chung', department_id: headquarters.id },
        create: {
          code: 'GENERAL_OPERATIONS',
          name: 'Nghiệp vụ chung',
          department_id: headquarters.id,
        },
      });
      await transaction.businessCategory.upsert({
        where: { code: 'SECURITY_OPERATIONS' },
        update: { name: 'An toàn thông tin', department_id: securityDepartment.id },
        create: {
          code: 'SECURITY_OPERATIONS',
          name: 'An toàn thông tin',
          department_id: securityDepartment.id,
        },
      });

      for (const level of classificationLevels) {
        await transaction.classificationLevel.upsert({
          where: { code: level.code },
          update: {
            name: level.name,
            rank: level.rank,
            allow_download: level.allow_download,
            require_watermark: true,
          },
          create: { ...level, require_watermark: true },
        });
      }

      const roleByCode = new Map<string, bigint>();
      for (const [code, name] of systemRoles) {
        const role = await transaction.role.upsert({
          where: { code },
          update: { name, is_system_role: true, is_active: true },
          create: {
            code,
            name,
            is_system_role: true,
            created_by: seedActor.id,
          },
        });
        roleByCode.set(code, role.id);
      }

      const permissionByCode = new Map<string, bigint>();
      for (const [code, resource_type, action] of permissions) {
        const permission = await transaction.permission.upsert({
          where: { code },
          update: { name: code, resource_type, action },
          create: { code, name: code, resource_type, action },
        });
        permissionByCode.set(code, permission.id);
      }

      for (const [roleCode, permissionCodes] of Object.entries(rolePermissionCodes)) {
        const roleId = roleByCode.get(roleCode);
        if (roleId === undefined) throw new Error('Seed role map is incomplete.');
        for (const permissionCode of permissionCodes) {
          const permissionId = permissionByCode.get(permissionCode);
          if (permissionId === undefined) throw new Error('Seed permission map is incomplete.');
          await transaction.rolePermission.upsert({
            where: { role_id_permission_id: { role_id: roleId, permission_id: permissionId } },
            update: { granted_by: seedActor.id },
            create: {
              role_id: roleId,
              permission_id: permissionId,
              granted_by: seedActor.id,
            },
          });
        }
      }

      const clearance = await transaction.attributeDefinition.upsert({
        where: { code: 'CLEARANCE_LEVEL' },
        update: { name: 'Cấp độ thẩm tra', is_required: true, is_active: true },
        create: {
          code: 'CLEARANCE_LEVEL',
          name: 'Cấp độ thẩm tra',
          scope: 'USER',
          value_type: 'ENUM',
          is_required: true,
          created_by: seedActor.id,
        },
      });

      const attributeDefinitions = [
        ['SUBJECT_DEPARTMENT', 'Phòng ban chủ thể', 'USER', 'STRING', true, false],
        ['EMPLOYMENT_STATUS', 'Trạng thái làm việc', 'USER', 'ENUM', true, false],
        ['PROJECT', 'Dự án', 'USER', 'STRING', false, true],
        ['CLASSIFICATION_RANK', 'Hạng phân loại tài liệu', 'RESOURCE', 'NUMBER', true, false],
        ['RESOURCE_OWNER', 'Chủ sở hữu tài liệu', 'RESOURCE', 'STRING', true, false],
        ['RESOURCE_DEPARTMENT', 'Phòng ban tài liệu', 'RESOURCE', 'STRING', true, false],
        ['RESOURCE_CATEGORY', 'Danh mục tài liệu', 'RESOURCE', 'STRING', true, false],
        ['RESOURCE_STATUS', 'Trạng thái tài liệu', 'RESOURCE', 'ENUM', true, false],
        ['CURRENT_TIME', 'Thời điểm truy cập', 'ENVIRONMENT', 'DATE', true, false],
        ['SOURCE_IP', 'Địa chỉ IP nguồn', 'ENVIRONMENT', 'STRING', true, false],
        ['TRUSTED_NETWORK', 'Mạng tin cậy', 'ENVIRONMENT', 'BOOLEAN', true, false],
        ['DEVICE_TRUST', 'Thiết bị tin cậy', 'ENVIRONMENT', 'BOOLEAN', true, false],
        ['MFA', 'Xác thực đa yếu tố', 'ENVIRONMENT', 'BOOLEAN', true, false],
        ['RISK_SCORE', 'Điểm rủi ro', 'ENVIRONMENT', 'NUMBER', true, false],
      ] as const;
      for (const [code, name, scope, valueType, required, multiValue] of attributeDefinitions) {
        await transaction.attributeDefinition.upsert({
          where: { code },
          update: {
            name,
            scope,
            value_type: valueType,
            is_required: required,
            is_multi_value: multiValue,
            is_active: true,
          },
          create: {
            code,
            name,
            scope,
            value_type: valueType,
            is_required: required,
            is_multi_value: multiValue,
            created_by: seedActor.id,
          },
        });
      }

      const clearanceOptionByCode = new Map<string, bigint>();
      for (const level of classificationLevels) {
        const option = await transaction.attributeOption.upsert({
          where: {
            attribute_definition_id_value_code: {
              attribute_definition_id: clearance.id,
              value_code: level.code,
            },
          },
          update: {
            display_name: level.name,
            numeric_rank: level.rank,
            sort_order: level.rank,
            is_active: true,
          },
          create: {
            attribute_definition_id: clearance.id,
            value_code: level.code,
            display_name: level.name,
            numeric_rank: level.rank,
            sort_order: level.rank,
          },
        });
        clearanceOptionByCode.set(level.code, option.id);
      }

      // Production deliberately receives no demo identities. Local/test identities stay disabled
      // and carry a non-authenticatable marker, never a shared weak password.
      if (process.env['NODE_ENV'] === 'production') return;

      const demoUsers = [
        [
          'admin.demo',
          'admin.demo@local.invalid',
          'Quản trị viên demo',
          'SYSTEM_ADMIN',
          'INTERNAL',
        ],
        [
          'security.demo',
          'security.demo@local.invalid',
          'Bảo mật demo',
          'SECURITY_OFFICER',
          'TOP_SECRET',
        ],
        ['auditor.demo', 'auditor.demo@local.invalid', 'Kiểm toán demo', 'AUDITOR', 'SECRET'],
        ['owner.demo', 'owner.demo@local.invalid', 'Chủ tài liệu demo', 'DOCUMENT_OWNER', 'SECRET'],
        [
          'reader.demo',
          'reader.demo@local.invalid',
          'Người đọc demo',
          'DOCUMENT_READER',
          'INTERNAL',
        ],
      ] as const;

      for (const [username, email, full_name, roleCode, clearanceCode] of demoUsers) {
        const departmentId =
          roleCode === 'SECURITY_OFFICER' || roleCode === 'AUDITOR'
            ? securityDepartment.id
            : headquarters.id;
        const user = await transaction.user.upsert({
          where: { username },
          update: { full_name, department_id: departmentId },
          create: {
            username,
            email,
            password_hash: disabledPasswordHash,
            full_name,
            department_id: departmentId,
            status: 'DISABLED',
            disabled_at: fixedSeedTime,
            created_by: seedActor.id,
          },
        });

        const roleId = roleByCode.get(roleCode);
        const optionId = clearanceOptionByCode.get(clearanceCode);
        if (roleId === undefined || optionId === undefined) {
          throw new Error('Demo assignment seed map is incomplete.');
        }

        const existingRole = await transaction.userRole.findFirst({
          where: { user_id: user.id, role_id: roleId, valid_to: null },
          select: { id: true },
        });
        if (!existingRole) {
          await transaction.userRole.create({
            data: {
              user_id: user.id,
              role_id: roleId,
              valid_from: fixedSeedTime,
              assigned_by: seedActor.id,
            },
          });
        }

        const existingClearance = await transaction.userAttributeAssignment.findFirst({
          where: {
            user_id: user.id,
            attribute_definition_id: clearance.id,
            valid_to: null,
          },
          select: { id: true },
        });
        if (!existingClearance) {
          await transaction.userAttributeAssignment.create({
            data: {
              user_id: user.id,
              attribute_definition_id: clearance.id,
              option_id: optionId,
              valid_from: fixedSeedTime,
              assigned_by: seedActor.id,
            },
          });
        }
      }
    },
    { client },
  );
}

try {
  await seed();
  console.log('Database seed completed without exposing demo credentials.');
} finally {
  await client.$disconnect();
}
