/**
 * @module GrantTargetSodHelper
 * Algorithm: Principal Target Eligibility, Separation-of-Duties (SoD) & Linked Request Verification.
 */
import { BadRequestException, ForbiddenException, NotFoundException } from '@nestjs/common';
import type { getDatabaseClient } from '@sda/database';
import { AppErrorCode, type CreateAccessGrantInput } from '@sda/contracts';
import { isPrivilegedSeparationRoleOrCapability } from '../rbac/permission-matrix.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

/**
 * Algorithm / Thuật toán: Xác thực chủ thể nhận quyền (`USER`/`ROLE`), quy tắc Phân tách nhiệm vụ (SoD) và liên kết `accessRequestId`.
 *   1. Với `USER`: kiểm tra tài khoản tồn tại, đang `ACTIVE`, và không giữ vai trò quản trị/SOC/kiểm toán (kể cả Custom Role mang quyền quản trị/SOC/kiểm toán).
 *   2. Với `ROLE`: kiểm tra vai trò tồn tại, đang kích hoạt và cấm cấp quyền nội dung cho vai trò hệ thống hoặc Custom Role mang quyền quản trị/SOC/kiểm toán.
 *   3. Với `accessRequestId`: xác minh yêu cầu đang `PENDING` khớp chính xác tài liệu và người nhận.
 */
export async function validateGrantTargetAndSod(
  database: PrismaClient,
  input: CreateAccessGrantInput,
  now: Date,
): Promise<void> {
  if (input.principalType === 'USER') {
    if (!input.principalUserId) {
      throw new BadRequestException({
        errorCode: AppErrorCode.GRANT_PRINCIPAL_INVALID,
        message: 'principalUserId is required when principalType is USER.',
      });
    }
    const targetUser = await database.user.findUnique({
      where: { id: input.principalUserId },
      select: { id: true, status: true },
    });
    if (!targetUser) {
      throw new NotFoundException({
        errorCode: AppErrorCode.USER_NOT_ACTIVE,
        message: 'Target user was not found.',
      });
    }
    if (targetUser.status !== 'ACTIVE') {
      throw new BadRequestException({
        errorCode: AppErrorCode.USER_NOT_ACTIVE,
        message: 'Target user account is not active.',
      });
    }
    if (typeof database.userRole?.findMany === 'function') {
      const recipientRoles = await database.userRole.findMany({
        where: {
          user_id: input.principalUserId,
          OR: [{ valid_to: null }, { valid_to: { gt: now } }],
          roles: { is_active: true },
        },
        include: {
          roles: {
            select: {
              code: true,
              role_permissions: {
                select: {
                  permissions: { select: { code: true, resource_type: true, action: true } },
                },
              },
            },
          },
        },
      });
      // CONFLICT-RESOLVED: Kiểm tra Phân tách Nhiệm vụ trên cả mã vai trò lẫn tập quyền thực tế của Custom Role khi cấp AccessGrant cho USER (HIGH-01).
      const holdsPrivilegedCapability = recipientRoles.some((r) => {
        const roleObj = (
          r as {
            roles?: {
              code?: string;
              role_permissions?: Array<{
                permissions?: { code: string; resource_type?: string; action?: string };
              }>;
            };
          }
        ).roles;
        if (!roleObj) return false;
        const perms = (roleObj.role_permissions ?? [])
          .map((rp) => rp.permissions)
          .filter((p): p is NonNullable<typeof p> => Boolean(p));
        return isPrivilegedSeparationRoleOrCapability(roleObj.code, perms);
      });
      if (holdsPrivilegedCapability) {
        throw new ForbiddenException({
          errorCode: AppErrorCode.FORBIDDEN,
          message:
            'Separation of duties: cannot grant document content access to privileged administrative, security, or auditor accounts.',
        });
      }
    }
  } else if (input.principalType === 'ROLE') {
    if (!input.principalRoleId) {
      throw new BadRequestException({
        errorCode: AppErrorCode.GRANT_PRINCIPAL_INVALID,
        message: 'principalRoleId is required when principalType is ROLE.',
      });
    }
    const targetRole = await database.role.findUnique({
      where: { id: input.principalRoleId },
      select: {
        id: true,
        code: true,
        is_active: true,
        role_permissions: {
          select: {
            permissions: { select: { code: true, resource_type: true, action: true } },
          },
        },
      },
    });
    if (!targetRole) {
      throw new NotFoundException({
        errorCode: AppErrorCode.ROLE_NOT_ACTIVE,
        message: 'Target role was not found.',
      });
    }
    if (!targetRole.is_active) {
      throw new BadRequestException({
        errorCode: AppErrorCode.ROLE_NOT_ACTIVE,
        message: 'Target role is not active.',
      });
    }
    const targetRolePerms = (
      (
        targetRole as {
          role_permissions?: Array<{
            permissions?: { code: string; resource_type?: string; action?: string };
          }>;
        }
      ).role_permissions ?? []
    )
      .map((rp) => rp.permissions)
      .filter((p): p is NonNullable<typeof p> => Boolean(p));
    // CONFLICT-RESOLVED: Chặn cấp AccessGrant cho cả vai trò hệ thống lẫn Custom Role mang quyền quản trị/SOC/kiểm toán (HIGH-01).
    if (isPrivilegedSeparationRoleOrCapability(targetRole.code, targetRolePerms)) {
      throw new ForbiddenException({
        errorCode: AppErrorCode.FORBIDDEN,
        message:
          'Separation of duties: cannot grant document content access to privileged administrative, security, or auditor roles.',
      });
    }
  }

  if (input.accessRequestId && typeof database.accessRequest?.findUnique === 'function') {
    const linkedRequest = await database.accessRequest.findUnique({
      where: { id: input.accessRequestId },
      select: { id: true, document_id: true, requester_id: true, status: true },
    });
    if (
      !linkedRequest ||
      linkedRequest.document_id !== input.documentId ||
      linkedRequest.status !== 'PENDING' ||
      input.principalType !== 'USER' ||
      linkedRequest.requester_id !== input.principalUserId
    ) {
      throw new BadRequestException({
        errorCode: AppErrorCode.VALIDATION_FAILED,
        message:
          'Linked accessRequestId must be a PENDING request for the same document and recipient user.',
      });
    }
  }
}
