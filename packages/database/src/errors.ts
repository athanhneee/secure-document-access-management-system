/**
 * Module: Chuẩn Hóa & Phân Loại Lỗi Cơ Sở Dữ Liệu Không Rò Rỉ SQL (`@sda/database`)
 * Thuật toán: Duyệt Cây Nguyên Nhân Chống Vòng Lặp & Ánh Xạ Mã Lỗi SQLSTATE / Driver Adapter / Prisma 7 An Toàn (`Bounded-Depth Graph Error Mapper`).
 *   - Duyệt toàn bộ cây `meta` / `driverAdapterError` / `cause` / `error` (tối đa `maxDepth = 6` kèm `Set<object>` chống tham chiếu vòng).
 *   - Ưu tiên mã PostgreSQL `SQLSTATE` 5 ký tự (`40001`, `40P01`, `23505`, `23502`, `57P01`, `53300`, ...) và `kind` của `@prisma/adapter-pg`
 *     hơn mã vỏ bọc ngoài (`P2010`, `P2039`) của Prisma 7.
 *   - Tuyệt đối không phơi bày `originalMessage`, `detail`, câu lệnh SQL gốc hoặc đối tượng `cause` ra ngoài `DatabaseError`.
 */
import { Prisma } from './generated/prisma/client.js';

export type SafeDatabaseErrorCode =
  | 'DATABASE_CONFLICT'
  | 'DATABASE_UNIQUE_VIOLATION'
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
  constructor(
    code: SafeDatabaseErrorCode = 'DATABASE_CONSTRAINT',
    message = 'The database rejected data that violates an integrity rule.',
  ) {
    super(code, message);
    this.name = 'DatabaseConstraintError';
  }
}

export class UniqueConstraintError extends DatabaseConstraintError {
  constructor() {
    super(
      'DATABASE_UNIQUE_VIOLATION',
      'A record with the same unique identifier or key already exists.',
    );
    this.name = 'UniqueConstraintError';
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

const MAX_ERROR_TRAVERSAL_DEPTH = 6;
const PRISMA_SHELL_CODES = new Set(['P2010', 'P2039']);
const RETRYABLE_SQLSTATES = new Set(['40001', '40P01']);
const RETRYABLE_ADAPTER_KINDS = new Set(['TransactionWriteConflict']);
const UNIQUE_ADAPTER_KINDS = new Set(['UniqueConstraintViolation']);
const CONSTRAINT_ADAPTER_KINDS = new Set([
  'NullConstraintViolation',
  'ForeignKeyConstraintViolation',
  'CheckConstraintViolation',
  'ExclusionConstraintViolation',
]);
const UNAVAILABLE_ADAPTER_KINDS = new Set([
  'TooManyConnections',
  'ConnectionClosed',
  'DatabaseNotReachable',
  'DatabaseDoesNotExist',
  'SocketTimeout',
  'PoolTimeout',
  'TlsConnectionError',
  'AuthenticationFailed',
  'Postgres::ConnectionError',
]);
const UNAVAILABLE_PRISMA_CODES = new Set(['P1001', 'P1002', 'P1008', 'P1017', 'P2024', 'P2037']);
const CONSTRAINT_PRISMA_CODES = new Set(['P2003', 'P2004', 'P2011']);

interface ExtractedDatabaseSignals {
  sqlStates: string[];
  prismaCodes: string[];
  adapterKinds: string[];
  hasDriverAdapterMarker: boolean;
}

function isPrismaErrorCode(code: string): boolean {
  return /^P[1-9]\d{3}$/u.test(code);
}

function isPostgresSqlState(code: string): boolean {
  return /^[0-9A-Z]{5}$/u.test(code) && !isPrismaErrorCode(code);
}

function isUnavailableSqlState(code: string): boolean {
  return (
    code === '53300' ||
    code.startsWith('53') ||
    code === '57P01' ||
    code === '57P02' ||
    code === '57P03' ||
    code === '57014' ||
    code.startsWith('08')
  );
}

/**
 * Thuật toán: Duyệt đồ thị nguyên nhân lỗi giới hạn độ sâu `maxDepth = 6` có `Set<object>` chống chu trình,
 * thu thập đầy đủ `SQLSTATE`, `kind` của `@prisma/adapter-pg` và mã `Pxxxx` trên toàn bộ nhánh `meta` / `driverAdapterError` / `cause`.
 */
function inspectDatabaseErrorGraph(error: unknown): ExtractedDatabaseSignals {
  const signals: ExtractedDatabaseSignals = {
    sqlStates: [],
    prismaCodes: [],
    adapterKinds: [],
    hasDriverAdapterMarker: false,
  };
  const visited = new Set<object>();

  const visit = (node: unknown, depth: number): void => {
    if (depth > MAX_ERROR_TRAVERSAL_DEPTH || typeof node !== 'object' || node === null) {
      return;
    }
    if (visited.has(node)) {
      return;
    }
    visited.add(node);

    const record = node as Record<string, unknown>;
    if (record['name'] === 'DriverAdapterError') {
      signals.hasDriverAdapterMarker = true;
    }

    for (const key of ['originalCode', 'sqlState', 'code'] as const) {
      const raw = record[key];
      if (typeof raw === 'string') {
        const normalized = raw.trim().toUpperCase();
        if (isPostgresSqlState(normalized)) {
          if (!signals.sqlStates.includes(normalized)) {
            signals.sqlStates.push(normalized);
          }
        } else if (isPrismaErrorCode(normalized)) {
          if (!signals.prismaCodes.includes(normalized)) {
            signals.prismaCodes.push(normalized);
          }
        }
      }
    }

    const rawKind = record['kind'];
    if (typeof rawKind === 'string' && rawKind.trim().length > 0) {
      const trimmedKind = rawKind.trim();
      if (!signals.adapterKinds.includes(trimmedKind)) {
        signals.adapterKinds.push(trimmedKind);
      }
    } else if (typeof rawKind === 'object' && rawKind !== null) {
      visit(rawKind, depth + 1);
    }

    for (const branchKey of ['driverAdapterError', 'meta', 'cause', 'error'] as const) {
      if (branchKey in record) {
        if (branchKey === 'driverAdapterError' && record[branchKey] !== undefined) {
          signals.hasDriverAdapterMarker = true;
        }
        visit(record[branchKey], depth + 1);
      }
    }
  };

  visit(error, 0);
  return signals;
}

/**
 * Thuật toán: Trích xuất mã lỗi ưu tiên `SQLSTATE` 5 ký tự của PostgreSQL hơn mã vỏ bọc `P2010`/`P2039` của Prisma 7.
 */
export function extractDatabaseCode(error: unknown): string | undefined {
  const signals = inspectDatabaseErrorGraph(error);
  if (signals.sqlStates.length > 0) {
    return signals.sqlStates[0];
  }
  const nonShellPrisma = signals.prismaCodes.find((code) => !PRISMA_SHELL_CODES.has(code));
  if (nonShellPrisma) {
    return nonShellPrisma;
  }
  return signals.prismaCodes[0];
}

/**
 * Thuật toán: Kiểm tra xem lỗi giao dịch có thuộc tập xung đột tuần tự hóa / khóa chết cho phép thử lại (`40001`, `40P01`, `TransactionWriteConflict`, `P2034`) hay không.
 */
export function isRetryableTransactionError(error: unknown): boolean {
  const signals = inspectDatabaseErrorGraph(error);
  if (signals.sqlStates.some((code) => RETRYABLE_SQLSTATES.has(code))) {
    return true;
  }
  if (signals.adapterKinds.some((kind) => RETRYABLE_ADAPTER_KINDS.has(kind))) {
    return true;
  }
  const hasKnownNonRetryableAdapterKind = signals.adapterKinds.some(
    (kind) =>
      UNIQUE_ADAPTER_KINDS.has(kind) ||
      CONSTRAINT_ADAPTER_KINDS.has(kind) ||
      UNAVAILABLE_ADAPTER_KINDS.has(kind),
  );
  if (signals.sqlStates.length > 0 || hasKnownNonRetryableAdapterKind) {
    return false;
  }
  return signals.prismaCodes.includes('P2034');
}

/**
 * Thuật toán: Phân biệt lỗi tầng vận hành cơ sở dữ liệu (Prisma / `@prisma/adapter-pg` / PostgreSQL driver) với ngoại lệ nghiệp vụ do ứng dụng chủ động ném bên trong giao dịch.
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
  const signals = inspectDatabaseErrorGraph(error);
  return (
    signals.sqlStates.length > 0 ||
    signals.prismaCodes.length > 0 ||
    signals.adapterKinds.length > 0 ||
    signals.hasDriverAdapterMarker
  );
}

/**
 * Thuật toán: Ánh xạ tất định mã lỗi `SQLSTATE` / adapter `kind` / Prisma sang hệ phân loại `DatabaseError` chuẩn hóa mà không làm lộ siêu dữ liệu nhạy cảm của truy vấn.
 */
export function mapDatabaseError(error: unknown): DatabaseError {
  if (error instanceof DatabaseError) return error;
  const signals = inspectDatabaseErrorGraph(error);

  // 1. Prioritize 5-character PostgreSQL SQLSTATE codes over outer Prisma wrapper shells (P2010 / P2039)
  for (const sqlState of signals.sqlStates) {
    if (RETRYABLE_SQLSTATES.has(sqlState)) {
      return new DatabaseConflictError();
    }
    if (sqlState === '23505') {
      return new UniqueConstraintError();
    }
    if (sqlState.startsWith('23')) {
      return new DatabaseConstraintError();
    }
    if (isUnavailableSqlState(sqlState)) {
      return new DatabaseUnavailableError();
    }
  }

  // 2. Prioritize @prisma/adapter-pg / driver-adapter-utils kind classifications over outer shells
  for (const kind of signals.adapterKinds) {
    if (RETRYABLE_ADAPTER_KINDS.has(kind)) {
      return new DatabaseConflictError();
    }
    if (UNIQUE_ADAPTER_KINDS.has(kind)) {
      return new UniqueConstraintError();
    }
    if (CONSTRAINT_ADAPTER_KINDS.has(kind)) {
      return new DatabaseConstraintError();
    }
    if (UNAVAILABLE_ADAPTER_KINDS.has(kind)) {
      return new DatabaseUnavailableError();
    }
  }

  // 3. Map specific Prisma client error codes
  for (const prismaCode of signals.prismaCodes) {
    if (prismaCode === 'P2034') {
      return new DatabaseConflictError();
    }
    if (prismaCode === 'P2002') {
      return new UniqueConstraintError();
    }
    if (CONSTRAINT_PRISMA_CODES.has(prismaCode)) {
      return new DatabaseConstraintError();
    }
    if (prismaCode === 'P2025') {
      return new DatabaseNotFoundError();
    }
    if (UNAVAILABLE_PRISMA_CODES.has(prismaCode)) {
      return new DatabaseUnavailableError();
    }
  }

  if (signals.prismaCodes.includes('P2039') || signals.prismaCodes.includes('P2028')) {
    return new DatabaseConflictError();
  }

  if (
    error instanceof Prisma.PrismaClientInitializationError ||
    error instanceof Prisma.PrismaClientRustPanicError
  ) {
    return new DatabaseUnavailableError();
  }

  return new DatabaseError(
    'DATABASE_OPERATION_FAILED',
    'The database operation could not be completed.',
  );
}
