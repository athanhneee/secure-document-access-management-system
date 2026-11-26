/**
 * Module: Export Workspace Path Resolution, Ownership Authorization & Cross-Department Scope Guard
 * Thuật toán: Chuẩn Hóa Thư Mục Xuất Báo Cáo Dùng Chung API/Worker & Kiểm Định Quyền Truy Cập/Phạm Vi Phòng Ban Chéo (`ExportAccessPolicy`).
 *   1. Định vị thư mục `.local/exports` neo theo gốc workspace (`path.resolve(import.meta.dirname, '../../../../../.local/exports')`) để `@sda/api` và `@sda/worker` luôn đọc/ghi cùng một đường dẫn vật lý.
 *   2. Kiểm chứng quyền sở hữu tác vụ xuất báo cáo hoặc vai trò giám sát tương ứng với miền dữ liệu (`AUDIT_LOGS`, `SECURITY_ALERTS`, `INCIDENT_REPORTS`, `SYSTEM_REPORT`).
 *   3. Khi tra cứu/tải chéo người dùng, bắt buộc đối chiếu bao đóng phòng ban `allowedDepartmentIds` với cả `filter_params.departmentId` và phòng ban của người tạo tác vụ.
 */
import { BadRequestException, ForbiddenException } from '@nestjs/common';
import * as path from 'node:path';
import { AppErrorCode, type ExportType } from '@sda/contracts';
import type { AuthPrincipal } from '../auth/auth.types.js';
import type { AuthorizationService } from '../rbac/authorization.service.js';
import { resolveExportAuthorizationScope } from './export-filter-scope.helper.js';

/**
 * Thuật toán: Định vị thư mục lưu trữ tệp xuất báo cáo nhất quán giữa `@sda/api` và `@sda/worker` tại gốc monorepo (`.local/exports`) trừ khi có biến môi trường `EXPORT_STORAGE_DIR`.
 */
export function resolveWorkspaceExportDir(): string {
  return path.resolve(
    process.env['EXPORT_STORAGE_DIR']?.trim() ||
      path.resolve(import.meta.dirname, '../../../../../.local/exports'),
  );
}

/**
 * Thuật toán: Kiểm tra quyền sở hữu tác vụ xuất báo cáo hoặc vai trò giám sát tương ứng theo miền dữ liệu.
 * Khi `authorization` có mặt, cho phép các Vai trò Tùy chỉnh (Custom Roles) đi tiếp sang bước đối chiếu quyền RBAC thực tế `resolveExportAuthorizationScope`.
 */
export function assertExportJobAccess(
  job: { requester_user_id: bigint; export_type: string },
  actor: AuthPrincipal,
  authorization?: AuthorizationService,
): void {
  if (job.requester_user_id === actor.userId) return;
  if (authorization) return;
  const roles = actor.roles ?? [];
  if (roles.includes('SYSTEM_ADMIN')) return;
  if (job.export_type === 'AUDIT_LOGS' && roles.includes('AUDITOR')) return;
  if (
    (job.export_type === 'SECURITY_ALERTS' ||
      job.export_type === 'INCIDENT_REPORTS' ||
      job.export_type === 'SYSTEM_REPORT') &&
    roles.includes('SECURITY_OFFICER')
  ) {
    return;
  }

  throw new ForbiddenException({
    errorCode: AppErrorCode.EXPORT_UNAUTHORIZED,
    message: 'You are not authorized to access or download this export job.',
  });
}

/**
 * Thuật toán: Tái thẩm định quyền RBAC `EXPORT` trực tiếp (hỗ trợ Custom Roles qua `AuthorizationService`), trạng thái hoạt động `ACTIVE` của tài khoản
 * và phạm vi phòng ban ngay tại thời điểm tải xuống tệp báo cáo nhạy cảm (BUG-111).
 */
export async function assertLiveExportDownloadAuthorization(
  database: {
    user?: {
      findUnique: (args: {
        where: { id: bigint };
        select: { status?: true; department_id?: true };
      }) => Promise<{ status?: string; department_id?: bigint | null } | null>;
    };
  },
  authorization: AuthorizationService | undefined,
  job: { requester_user_id: bigint; export_type: string; filter_params?: unknown },
  actor: AuthPrincipal,
): Promise<void> {
  if (typeof database?.user?.findUnique === 'function') {
    const liveUser = await database.user.findUnique({
      where: { id: actor.userId },
      select: { status: true },
    });
    if (liveUser && liveUser.status !== undefined && liveUser.status !== 'ACTIVE') {
      throw new ForbiddenException({
        errorCode: AppErrorCode.EXPORT_UNAUTHORIZED,
        message: 'User account is no longer active to download export artifacts.',
      });
    }
  }

  if (!authorization) return;

  const liveAllowedDepartmentIds = await resolveExportAuthorizationScope(
    authorization,
    actor,
    job.export_type as ExportType,
  );
  if (liveAllowedDepartmentIds === null) return;

  const filterParams =
    job.filter_params && typeof job.filter_params === 'object' && !Array.isArray(job.filter_params)
      ? (job.filter_params as Record<string, unknown>)
      : null;
  const rawFilterDept = filterParams?.['departmentId'];
  if (rawFilterDept !== undefined && rawFilterDept !== null && rawFilterDept !== '') {
    if (
      !/^\d+$/.test(String(rawFilterDept)) ||
      !liveAllowedDepartmentIds.includes(BigInt(String(rawFilterDept)))
    ) {
      throw new ForbiddenException({
        errorCode: AppErrorCode.EXPORT_UNAUTHORIZED,
        message: 'Your current department scope no longer covers this export artifact.',
      });
    }
    return;
  }

  const persistedAllowed = filterParams?.['__allowedDepartmentIds'];
  if (Array.isArray(persistedAllowed) && persistedAllowed.length > 0) {
    const allStillCovered = persistedAllowed.every(
      (id) => /^\d+$/.test(String(id)) && liveAllowedDepartmentIds.includes(BigInt(String(id))),
    );
    if (!allStillCovered) {
      throw new ForbiddenException({
        errorCode: AppErrorCode.EXPORT_UNAUTHORIZED,
        message: 'Your current department scope no longer covers all departments in this export.',
      });
    }
    return;
  }

  throw new ForbiddenException({
    errorCode: AppErrorCode.EXPORT_UNAUTHORIZED,
    message: 'Your current department scope no longer covers an unrestricted global export.',
  });
}

/**
 * Thuật toán: Ràng buộc phạm vi phòng ban khi quản trị viên/kiểm toán viên tra cứu hoặc tải tác vụ xuất của người dùng khác (HIGH-13).
 */
export async function assertCrossUserExportScope(
  database: {
    user?: {
      findUnique: (args: {
        where: { id: bigint };
        select: { department_id: true };
      }) => Promise<{ department_id: bigint | null } | null>;
    };
  },
  authorization: AuthorizationService | undefined,
  job: { requester_user_id: bigint; export_type: string; filter_params?: unknown },
  actor: AuthPrincipal,
): Promise<void> {
  if (job.requester_user_id === actor.userId) return;
  // CONFLICT-RESOLVED: Bắt buộc kiểm tra phạm vi phòng ban cho cả getExportJob và downloadExportJob khi truy cập chéo người dùng (HIGH-13)
  const allowedDepartmentIds = await resolveExportAuthorizationScope(
    authorization,
    actor,
    job.export_type as ExportType,
  );
  if (allowedDepartmentIds === null) return;

  const filterParams =
    job.filter_params && typeof job.filter_params === 'object' && !Array.isArray(job.filter_params)
      ? (job.filter_params as Record<string, unknown>)
      : null;
  const rawFilterDept = filterParams?.['departmentId'];
  // CONFLICT-RESOLVED: Chặn kiểm toán viên phạm vi phòng ban tải chéo tác vụ xuất đa phòng ban khi `filterParams.departmentId` để trống hoặc không hợp lệ (HIGH-07).
  if (
    rawFilterDept === undefined ||
    rawFilterDept === null ||
    rawFilterDept === '' ||
    !/^\d+$/.test(String(rawFilterDept)) ||
    !allowedDepartmentIds.includes(BigInt(String(rawFilterDept)))
  ) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.EXPORT_UNAUTHORIZED,
      message: 'Export job filter scope must explicitly target an authorized department.',
    });
  }

  const requester = await database.user?.findUnique({
    where: { id: job.requester_user_id },
    select: { department_id: true },
  });
  if (
    !requester ||
    requester.department_id === null ||
    !allowedDepartmentIds.includes(requester.department_id)
  ) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.EXPORT_UNAUTHORIZED,
      message: 'Export job belongs to a department outside your authorized scope.',
    });
  }
}

/**
 * Thuật toán: Kiểm tra hạn sống TTL và trạng thái sẵn sàng hoàn tất trước khi cho phép tải tệp báo cáo.
 */
export function assertExportJobReadyForDownload(job: {
  expires_at: Date;
  status: string;
  error_message: string | null;
}): void {
  if (job.expires_at < new Date() || job.status === 'EXPIRED') {
    throw new BadRequestException({
      errorCode: AppErrorCode.EXPORT_JOB_EXPIRED,
      message: 'This export job has expired. Please initiate a new export request.',
    });
  }
  if (job.status === 'PENDING' || job.status === 'PROCESSING') {
    throw new BadRequestException({
      errorCode: AppErrorCode.EXPORT_JOB_PENDING,
      message: 'Export job is still processing. Please try again shortly.',
    });
  }
  if (job.status === 'FAILED') {
    throw new BadRequestException({
      errorCode: AppErrorCode.INTERNAL_SERVER_ERROR,
      message: `Export job failed: ${job.error_message ?? 'Unknown error'}`,
    });
  }
}
