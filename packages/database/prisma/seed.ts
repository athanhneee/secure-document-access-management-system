import { config as loadEnvironment } from 'dotenv';
import path from 'node:path';
import { createDatabaseClient } from '../src/client.js';
import { withSerializableTransaction } from '../src/transaction.js';
import {
  attributeDefinitions,
  classificationLevels,
  disabledPasswordHash,
  employmentStatusOptions,
  fixedSeedTime,
  permissions,
  rolePermissionCodes,
  systemRoles,
} from './seed-catalog.js';
import { seedNonProductionDemoFixtures } from './seed-demo-fixtures.js';

loadEnvironment({
  path: [
    path.resolve(import.meta.dirname, '../../../.env'),
    path.resolve(import.meta.dirname, '../../../.local/dev.env'),
  ],
  quiet: true,
});

const client = createDatabaseClient();

/**
 * Thuật toán: Gieo dữ liệu từ điển nền tảng lũy đẳng ở mức cô lập `SERIALIZABLE` (Idempotent Serializable Baseline Seeding).
 * Cập nhật/tạo mới phòng ban, hạng độ mật, cấu hình đóng dấu mặc định, vai trò hệ thống, quyền hạt nhân,
 * ma trận phân quyền, định nghĩa & tùy chọn thuộc tính ABAC (`CLEARANCE_LEVEL`, `EMPLOYMENT_STATUS`) và
 * (chỉ ở môi trường phi sản xuất) tài khoản mẫu khóa cứng trong một giao dịch khả tuần tự duy nhất.
 */
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

      // CONFLICT-RESOLVED: Đồng bộ thang bậc phân loại độ mật CSDL (INTERNAL: 1 .. TOP_SECRET: 4) với ClassificationRank trong @sda/contracts.
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

      const existingDefaultWatermark = await transaction.watermarkConfig.findFirst({
        where: { is_default: true, classification_level_id: null },
        select: { id: true },
      });
      if (!existingDefaultWatermark) {
        await transaction.watermarkConfig.create({
          data: {
            name: 'Cấu hình đóng dấu mặc định toàn hệ thống',
            classification_level_id: null,
            is_default: true,
            is_visible: true,
            template_text:
              'CONFIDENTIAL | {username} ({employeeCode}) | {documentCode} | {timestamp} | {shortToken}',
            opacity_percent: 25,
            rotation_degrees: -30,
            font_size: 12,
            color_hex: '#808080',
            include_qr_code: true,
            is_active: true,
            created_by: seedActor.id,
          },
        });
      }

      const roleByCode = new Map<string, bigint>();
      for (const [code, name] of systemRoles) {
        const role = await transaction.role.upsert({
          where: { code },
          update: { name, is_system_role: true, is_active: true },
          create: { code, name, is_system_role: true, created_by: seedActor.id },
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
            create: { role_id: roleId, permission_id: permissionId, granted_by: seedActor.id },
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

      let employmentStatusAttributeId: bigint | undefined;
      for (const [code, name, scope, valueType, required, multiValue] of attributeDefinitions) {
        const definition = await transaction.attributeDefinition.upsert({
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
        if (code === 'EMPLOYMENT_STATUS') {
          employmentStatusAttributeId = definition.id;
        }
      }
      if (employmentStatusAttributeId === undefined) {
        throw new Error('EMPLOYMENT_STATUS attribute definition is missing from seed catalog.');
      }

      const clearanceOptionByCode = new Map<string, bigint>();
      // CONFLICT-RESOLVED: Đồng bộ thang bậc phân loại độ mật CSDL (INTERNAL: 1 .. TOP_SECRET: 4) với ClassificationRank trong @sda/contracts.
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

      // CONFLICT-RESOLVED: Khởi tạo lũy đẳng tập giá trị hợp lệ cho thuộc tính EMPLOYMENT_STATUS đồng bộ với kịch bản Supabase SQL.
      for (const [valueCode, displayName, numericRank, sortOrder] of employmentStatusOptions) {
        await transaction.attributeOption.upsert({
          where: {
            attribute_definition_id_value_code: {
              attribute_definition_id: employmentStatusAttributeId,
              value_code: valueCode,
            },
          },
          update: {
            display_name: displayName,
            numeric_rank: numericRank,
            sort_order: sortOrder,
            is_active: true,
          },
          create: {
            attribute_definition_id: employmentStatusAttributeId,
            value_code: valueCode,
            display_name: displayName,
            numeric_rank: numericRank,
            sort_order: sortOrder,
          },
        });
      }

      if (process.env['NODE_ENV'] === 'production') return;

      await seedNonProductionDemoFixtures({
        transaction,
        seedActorId: seedActor.id,
        headquartersId: headquarters.id,
        securityDepartmentId: securityDepartment.id,
        clearanceAttributeId: clearance.id,
        roleByCode,
        clearanceOptionByCode,
      });
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
