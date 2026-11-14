/**
 * Module: Chuẩn Hóa & Phân Loại Lỗi Cơ Sở Dữ Liệu Không Rò Rỉ SQL (`@sda/database`)
 * Thuật toán: Duyệt Cây Nguyên Nhân Giới Hạn Độ Sâu & Ánh Xạ Mã Lỗi SQLSTATE/Prisma An Toàn (`Bounded-Depth Error Taxonomy Mapper`).
 *   - Trích xuất mã lỗi chuẩn (`code`, `sqlState`, `originalCode`) tối đa 3 tầng nhân quả (`cause`, `driverAdapterError`) để tránh vòng lặp tham chiếu.
 *   - Phân tách lỗi xung đột giao dịch có thể thử lại (`P2034`, `40001` serialization failure, `40P01` deadlock) với lỗi ràng buộc toàn vẹn (`23xxx`, `P2002..P2004`), không tìm thấy (`P2025`) và mất kết nối (`57P01..57P03`).
 *   - Tuyệt đối không phơi bày câu lệnh SQL gốc, tên bảng nội bộ hoặc thông điệp driver ra ngoài thông báo lỗi.
 */
import { Prisma } from './generated/prisma/client.js';

export type SafeDatabaseErrorCode =
  | 'DATABASE_CONFLICT'
  | 'DATABASE_CONSTRAINT'
  | 'DATABASE_NOT_FOUND'
  | 'DATABASE_UNAVAILABLE'
  | 'DATABASE_OPERATION_FAILED';

export class DatabaseError extends Error {
  readonly code: SafeDatabaseErrorCode;
  readonly retryable: boolean;

  constructor(code: SafeDatabaseErrorCode, message: string, retryable = false) {
    super(message);
    this.name = 'DatabaseError';
    this.code = code;
    this.retryable = retryable;
  }
}

export class DatabaseConflictError extends DatabaseError {
  constructor() {
    super('DATABASE_CONFLICT', 'The database operation conflicted with another change.', true);
    this.name = 'DatabaseConflictError';
  }
}

export class DatabaseConstraintError extends DatabaseError {
  constructor() {
    super('DATABASE_CONSTRAINT', 'The database rejected data that violates an integrity rule.');
    this.name = 'DatabaseConstraintError';
  }
}

export class DatabaseNotFoundError extends DatabaseError {
  constructor() {
    super('DATABASE_NOT_FOUND', 'The requested database record was not found.');
    this.name = 'DatabaseNotFoundError';
  }
}

export class DatabaseUnavailableError extends DatabaseError {
  constructor() {
    super('DATABASE_UNAVAILABLE', 'The database is temporarily unavailable.', true);
    this.name = 'DatabaseUnavailableError';
  }
}

const retryableTransactionCodes = new Set(['P2034', '40001', '40P01']);

/**
 * Thuật toán: Duyệt đệ quy cây nguyên nhân lỗi giới hạn độ sâu `depth <= 3` để trích xuất mã lỗi Prisma hoặc PostgreSQL `SQLSTATE`.
 */
function extractDatabaseCode(error: unknown, depth = 0): string | undefined {
  if (depth > 3 || typeof error !== 'object' || error === null) return undefined;
  const record = error as Record<string, unknown>;
  for (const key of ['code', 'sqlState', 'originalCode'] as const) {
    if (typeof record[key] === 'string') return record[key];
  }
  for (const key of ['cause', 'driverAdapterError'] as const) {
    const nestedCode = extractDatabaseCode(record[key], depth + 1);
    if (nestedCode) return nestedCode;
  }
  return undefined;
}

/**
 * Thuật toán: Kiểm tra nhanh `O(1)` xem lỗi giao dịch có thuộc tập xung đột tuần tự hóa / khóa chết cho phép thử lại (`P2034`, `40001`, `40P01`) hay không.
 */
export function isRetryableTransactionError(error: unknown): boolean {
  return retryableTransactionCodes.has(extractDatabaseCode(error) ?? '');
}

/**
 * Thuật toán: Phân biệt lỗi tầng vận hành cơ sở dữ liệu (Prisma/PostgreSQL driver) với ngoại lệ nghiệp vụ do ứng dụng chủ động ném bên trong giao dịch.
 */
export function isDatabaseOperationError(error: unknown): boolean {
  if (error instanceof DatabaseError) return true;
  if (
    error instanceof Prisma.PrismaClientKnownRequestError ||
    error instanceof Prisma.PrismaClientUnknownRequestError ||
    error instanceof Prisma.PrismaClientInitializationError ||
    error instanceof Prisma.PrismaClientRustPanicError
  ) {
    return true;
  }
  const code = extractDatabaseCode(error);
  return code !== undefined && (/^P\d{4}$/u.test(code) || /^[0-9A-Z]{5}$/u.test(code));
}

/**
 * Thuật toán: Ánh xạ tất định mã lỗi `SQLSTATE` / Prisma sang hệ phân loại `DatabaseError` chuẩn hóa mà không làm lộ siêu dữ liệu nhạy cảm của truy vấn.
 */
export function mapDatabaseError(error: unknown): DatabaseError {
  if (error instanceof DatabaseError) return error;
  const code = extractDatabaseCode(error);
  if (code && retryableTransactionCodes.has(code)) return new DatabaseConflictError();
  if (error instanceof Prisma.PrismaClientKnownRequestError) {
    if (error.code === 'P2002' || error.code === 'P2003' || error.code === 'P2004') {
      return new DatabaseConstraintError();
    }
    if (error.code === 'P2025') return new DatabaseNotFoundError();
  }
  if (code?.startsWith('23')) return new DatabaseConstraintError();
  if (
    error instanceof Prisma.PrismaClientInitializationError ||
    error instanceof Prisma.PrismaClientRustPanicError ||
    code === '57P01' ||
    code === '57P02' ||
    code === '57P03'
  ) {
    return new DatabaseUnavailableError();
  }
  return new DatabaseError(
    'DATABASE_OPERATION_FAILED',
    'The database operation could not be completed.',
  );
}
