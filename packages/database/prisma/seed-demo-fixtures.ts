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
 * Algorithm: Idempotent non-authenticatable demo fixture provisioning (non-production only).
 * Upserts disabled demo users with invalid password hashes and attaches missing active role and
 * clearance attribute assignments without creating duplicate temporal rows on repeated seed runs.
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
