/**
 * Module: Khởi Tạo Danh Tính Mẫu Phi Sản Xuất Không Thể Xác Thực (`Zero-Static-Secret Demo Fixtures`)
 * Thuật toán: Cấp Phát Lũy Đẳng Tài Khoản Mẫu Vô Hiệu Hóa & Gán Quyền/Cấp Thẩm Tra Có Hiệu Lực Thời Gian (`Idempotent Temporal Seed Provisioning`).
 *   1. Duyệt danh sách `demoUsers`, định tuyến phòng ban theo nguyên tắc Phân Tách Trách Nhiệm (SoD): `SECURITY_OFFICER` và `AUDITOR` thuộc phòng An ninh, các vai trò còn lại thuộc Trụ sở chính.
 *   2. Thực thi `upsert` tài khoản ở trạng thái `DISABLED` với chuỗi `disabledPasswordHash` không thể khớp Argon2id để ngăn chặn đăng nhập bằng mật khẩu tĩnh.
 *   3. Kiểm tra bản ghi đang hiệu lực (`valid_to IS NULL`) trước khi chèn `user_roles` và `user_attribute_assignments` nhằm đảm bảo tính lũy đẳng tuyệt đối khi chạy lại `pnpm db:seed`.
 */
import type { Prisma } from '../src/index.js';
import { demoUsers, disabledPasswordHash, fixedSeedTime } from './seed-catalog.js';

export interface SeedDemoFixturesInput {
  transaction: Prisma.TransactionClient;
  seedActorId: bigint;
  headquartersId: bigint;
  securityDepartmentId: bigint;
  clearanceAttributeId: bigint;
  roleByCode: ReadonlyMap<string, bigint>;
  clearanceOptionByCode: ReadonlyMap<string, bigint>;
}

/**
 * Thuật toán: Khởi tạo lũy đẳng các tài khoản mẫu bị khóa xác thực mặc định (chỉ chạy ngoài môi trường `production`),
 * liên kết vai trò hệ thống và thuộc tính cấp độ mật (`CLEARANCE_LEVEL`) không sinh dòng trùng lặp theo thời gian.
 */
export async function seedNonProductionDemoFixtures(input: SeedDemoFixturesInput): Promise<void> {
  const {
    transaction,
    seedActorId,
    headquartersId,
    securityDepartmentId,
    clearanceAttributeId,
    roleByCode,
    clearanceOptionByCode,
  } = input;

  for (const [username, email, full_name, roleCode, clearanceCode] of demoUsers) {
    const departmentId =
      roleCode === 'SECURITY_OFFICER' || roleCode === 'AUDITOR'
        ? securityDepartmentId
        : headquartersId;
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
        created_by: seedActorId,
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
          assigned_by: seedActorId,
        },
      });
    }

    const existingClearance = await transaction.userAttributeAssignment.findFirst({
      where: {
        user_id: user.id,
        attribute_definition_id: clearanceAttributeId,
        valid_to: null,
      },
      select: { id: true },
    });
    if (!existingClearance) {
      await transaction.userAttributeAssignment.create({
        data: {
          user_id: user.id,
          attribute_definition_id: clearanceAttributeId,
          option_id: optionId,
          valid_from: fixedSeedTime,
          assigned_by: seedActorId,
        },
      });
    }
  }
}
