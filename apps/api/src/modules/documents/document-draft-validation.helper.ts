/**
 * Module: Document Draft Department & Retention Validation Helper
 * Thuật toán: Kiểm Định Phòng Ban Hoạt Động, Thẩm Quyền Ghi Theo Phòng Ban & Ngày Lưu Trữ Lịch Gregorian ISO.
 *   1. Xác minh phòng ban đích tồn tại và có trạng thái `is_active: true`.
 *   2. Cưỡng chế quyền RBAC theo phạm vi phòng ban đích (`MANAGE`, `CLASSIFY`, hoặc `UPLOAD` khi tạo mới) chống BOLA liên phòng ban.
 *   3. Kiểm định chuỗi ngày `YYYY-MM-DD` hợp lệ theo lịch Gregorian trước khi lưu cột `retention_until`.
 */
import { BadRequestException, ForbiddenException } from '@nestjs/common';
import type { getDatabaseClient } from '@sda/database';
import { AppErrorCode, isNotPastIsoCalendarDate, isValidIsoCalendarDate } from '@sda/contracts';
import type { AuthPrincipal } from '../auth/auth.types.js';
import type { AuthorizationService } from '../rbac/authorization.service.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

/**
 * Thuật toán: Xác minh phòng ban đích tồn tại và đang hoạt động (`is_active === true`).
 */
export async function assertActiveDepartment(
  database: PrismaClient,
  departmentId: bigint,
): Promise<void> {
  const dept = await database.department.findUnique({ where: { id: departmentId } });
  if (!dept || !dept.is_active) {
    throw new BadRequestException({
      errorCode: AppErrorCode.VALIDATION_FAILED,
      message: 'Target department does not exist or is inactive.',
    });
  }
}

/**
 * Thuật toán: Kiểm định thẩm quyền phòng ban đích khi khởi tạo dự thảo hoặc di chuyển phòng ban tài liệu.
 */
export async function assertDepartmentWriteScope(
  authorization: AuthorizationService | undefined,
  principal: AuthPrincipal,
  targetDepartmentId: bigint,
  allowUploadAction: boolean,
): Promise<void> {
  if (!authorization || typeof authorization.hasPermission !== 'function') return;
  const scope = { targetDepartmentId };
  const [canManage, canClassify, canUpload] = await Promise.all([
    authorization.hasPermission(principal, 'DOCUMENT', 'MANAGE', scope),
    authorization.hasPermission(principal, 'DOCUMENT', 'CLASSIFY', scope),
    allowUploadAction
      ? authorization.hasPermission(principal, 'DOCUMENT', 'UPLOAD', scope)
      : Promise.resolve(false),
  ]);
  if (!canManage && !canClassify && !canUpload) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
      message: 'Caller is not authorized to create or place documents in the target department.',
    });
  }
}

/**
 * Thuật toán: Phân tích ngày hạn lưu trữ ISO `YYYY-MM-DD` có kiểm định ngày lịch Gregorian thực
 * và từ chối ngày trong quá khứ (`< ngày hiện tại UTC`).
 */
export function parseIsoRetentionDate(isoDate: string, referenceDate: Date = new Date()): Date {
  if (!isValidIsoCalendarDate(isoDate)) {
    throw new BadRequestException({
      errorCode: AppErrorCode.RETENTION_DATE_INVALID,
      message: 'Invalid retention date format or impossible calendar date.',
    });
  }
  if (!isNotPastIsoCalendarDate(isoDate, referenceDate)) {
    throw new BadRequestException({
      errorCode: AppErrorCode.RETENTION_DATE_INVALID,
      message: 'Retention date cannot be in the past.',
    });
  }
  const retDate = new Date(`${isoDate}T00:00:00.000Z`);
  if (Number.isNaN(retDate.getTime())) {
    throw new BadRequestException({
      errorCode: AppErrorCode.RETENTION_DATE_INVALID,
      message: 'Invalid retention date format.',
    });
  }
  return retDate;
}
