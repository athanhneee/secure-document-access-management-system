/**
 * @module GrantRetentionBoundsHelper
 * Algorithm: Document Retention Ceiling & Access Duration Upper-Bound Enforcement (`O(1)`).
 * Tái sử dụng hàm tính trần UTC từ `@sda/contracts` để cưỡng chế mọi yêu cầu xin quyền (`access_requests`)
 * cũng như giấy phép (`access_grants`) không vượt quá ngày hạn lưu trữ bảo mật `documents.retention_until`.
 */
import { BadRequestException } from '@nestjs/common';
import {
  AppErrorCode,
  DEFAULT_GRANT_MAX_DURATION_DAYS,
  formatRetentionDateIso,
  resolveRetentionCeilingUtc,
} from '@sda/contracts';

export { formatRetentionDateIso, resolveRetentionCeilingUtc };

/**
 * Algorithm / Thuật toán: Chuẩn hóa trần số ngày cấp quyền tối đa (`GRANT_MAX_DURATION_DAYS`) và đổi sang mili-giây dùng chung giữa bước tạo mới và hợp nhất/gia hạn (BUG-123).
 */
export function resolveGrantDurationCeiling(maxDurationDays?: number): {
  effectiveMaxDays: number;
  maxDurationMs: number;
} {
  const effectiveMaxDays =
    typeof maxDurationDays === 'number' && Number.isFinite(maxDurationDays) && maxDurationDays >= 1
      ? Math.floor(maxDurationDays)
      : DEFAULT_GRANT_MAX_DURATION_DAYS;
  return {
    effectiveMaxDays,
    maxDurationMs: effectiveMaxDays * 86_400_000,
  };
}

/**
 * Algorithm / Thuật toán: Kiểm định thống nhất trần thời lượng cấp quyền tối đa cho cả tạo mới (`CREATE`) và hợp nhất/gia hạn (`EXTEND`) (BUG-123).
 *   - `CREATE`: đối chiếu `validUntil - validFrom <= maxDurationMs`.
 *   - `EXTEND`: đối chiếu khoảng hiệu lực còn lại từ `max(validFrom, now)` đến `validUntil` không vượt `maxDurationMs`.
 */
export function assertWithinMaxGrantDuration(params: {
  validFrom: Date;
  validUntil: Date;
  now: Date;
  maxDurationDays?: number;
  mode: 'CREATE' | 'EXTEND';
}): { effectiveMaxDays: number; maxDurationMs: number } {
  const { validFrom, validUntil, now, maxDurationDays, mode } = params;
  const { effectiveMaxDays, maxDurationMs } = resolveGrantDurationCeiling(maxDurationDays);
  const baselineMs =
    mode === 'EXTEND' ? Math.max(validFrom.getTime(), now.getTime()) : validFrom.getTime();

  if (validUntil.getTime() - baselineMs > maxDurationMs) {
    throw new BadRequestException({
      errorCode: AppErrorCode.GRANT_DURATION_EXCEEDED,
      message:
        mode === 'EXTEND'
          ? `Extended grant duration cannot exceed ${effectiveMaxDays} days from effective start.`
          : `Grant duration cannot exceed ${effectiveMaxDays} days.`,
    });
  }

  return { effectiveMaxDays, maxDurationMs };
}

/**
 * Algorithm / Thuật toán: Cưỡng chế bất biến trần thời hạn lưu trữ tài liệu (`targetUntil <= retentionCeilingUtc` và `now <= retentionCeilingUtc`).
 * Cơ chế hoạt động:
 *   1. Nếu tài liệu không đặt `retention_until` (`null`/`undefined`), bỏ qua kiểm tra.
 *   2. Nếu thời điểm hiện tại `now` đã vượt quá cuối ngày `retention_until`, từ chối tạo mới yêu cầu hoặc cấp quyền.
 *   3. Nếu mốc kết thúc đề nghị/cấp quyền `targetUntil` vượt quá cuối ngày `retention_until`, từ chối với mã `GRANT_DURATION_EXCEEDED`.
 */
export function assertWithinDocumentRetention(params: {
  retentionUntil: Date | string | null | undefined;
  targetUntil: Date;
  now: Date;
  context: 'REQUEST' | 'GRANT';
}): Date | null {
  const { retentionUntil, targetUntil, now, context } = params;
  const ceiling = resolveRetentionCeilingUtc(retentionUntil);
  if (!ceiling) return null;
  const isoDate = formatRetentionDateIso(retentionUntil) ?? ceiling.toISOString().substring(0, 10);

  if (now.getTime() > ceiling.getTime()) {
    throw new BadRequestException({
      errorCode: AppErrorCode.GRANT_DURATION_EXCEEDED,
      message:
        context === 'REQUEST'
          ? `Document retention period expired on ${isoDate}; new access requests are not allowed.`
          : `Document retention period expired on ${isoDate}; new access grants are not allowed.`,
      details: { retentionUntil: isoDate, reasonCode: 'DOCUMENT_RETENTION_EXPIRED' },
    });
  }

  if (targetUntil.getTime() > ceiling.getTime()) {
    throw new BadRequestException({
      errorCode: AppErrorCode.GRANT_DURATION_EXCEEDED,
      message:
        context === 'REQUEST'
          ? `Requested access end time cannot exceed document retention date (${isoDate}).`
          : `Grant expiration cannot exceed document retention date (${isoDate}).`,
      details: { retentionUntil: isoDate, reasonCode: 'EXCEEDS_DOCUMENT_RETENTION' },
    });
  }

  return ceiling;
}
