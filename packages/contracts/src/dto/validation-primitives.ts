/**
 * Module: Shared Boundary Validation Primitives (`@sda/contracts`)
 * Cung cấp các lược đồ Zod kiểm định số nguyên 64-bit PostgreSQL `BIGINT` và ngày lịch Gregorian thực.
 */
import { z } from 'zod';

/** Giới hạn trên của kiểu `BIGINT` có dấu trong PostgreSQL ($2^{63} - 1$). */
export const MAX_PG_BIGINT = 9223372036854775807n;

/**
 * Thuật toán: Kiểm định tính hợp lệ ngày lịch Gregorian theo chuẩn ISO-8601 `YYYY-MM-DD` (Round-Trip UTC Calendar Check).
 * Cơ chế hoạt động:
 *   1. Kiểm tra định dạng chuỗi đúng 10 ký tự số `YYYY-MM-DD`.
 *   2. Tách `year`, `month`, `day` và dựng mốc `Date.UTC(year, month - 1, day)`.
 *   3. Đối chiếu ngược `getUTCFullYear()`, `getUTCMonth() + 1`, `getUTCDate()` để loại bỏ các ngày tràn lịch
 *      như `2026-02-31`, `2025-02-29` hoặc `2026-04-31` mà biểu thức chính quy thông thường bỏ lọt.
 */
export function isValidIsoCalendarDate(value: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}$/u.test(value)) {
    return false;
  }
  const [yearStr, monthStr, dayStr] = value.split('-');
  const year = Number(yearStr);
  const month = Number(monthStr);
  const day = Number(dayStr);
  if (!Number.isInteger(year) || !Number.isInteger(month) || !Number.isInteger(day)) {
    return false;
  }
  if (month < 1 || month > 12 || day < 1 || day > 31) {
    return false;
  }
  const probe = new Date(Date.UTC(year, month - 1, day));
  return (
    !Number.isNaN(probe.getTime()) &&
    probe.getUTCFullYear() === year &&
    probe.getUTCMonth() === month - 1 &&
    probe.getUTCDate() === day
  );
}

/**
 * Thuật toán: Chuẩn hóa và kiểm định khóa định danh nguyên dương 64-bit (`1 <= x <= 9223372036854775807`).
 * Chặn tràn số `BIGINT` PostgreSQL (HTTP 500 `22003 numeric field overflow`) ngay tại biên xác thực DTO.
 */
// CONFLICT-RESOLVED: Bổ sung cận trên 64-bit PostgreSQL BIGINT (2^63 - 1) và từ chối kiểu boolean/chuỗi rỗng khi ép kiểu sang BigInt.
export const PositiveBigIntSchema = z
  .union([
    z.bigint(),
    z.number().int().positive(),
    z
      .string()
      .trim()
      .regex(/^[1-9]\d*$/u),
  ])
  .transform((val) => BigInt(val))
  .pipe(
    z.bigint().positive().max(MAX_PG_BIGINT, 'Identifier exceeds PostgreSQL 64-bit BIGINT range'),
  );

export const StrictIsoCalendarDateSchema = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}$/u, 'Date must be in YYYY-MM-DD format')
  .refine(isValidIsoCalendarDate, 'Invalid calendar date');

export const IsoDateOrDateTimeSchema = z
  .string()
  .datetime({ offset: true })
  .or(StrictIsoCalendarDateSchema);
