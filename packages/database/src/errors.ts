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

/** Covers Prisma's portable conflict code and PostgreSQL serialization/deadlock SQLSTATEs. */
export function isRetryableTransactionError(error: unknown): boolean {
  return retryableTransactionCodes.has(extractDatabaseCode(error) ?? '');
}

/** Distinguishes driver/Prisma failures from application exceptions thrown inside a transaction. */
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

/** Maps only stable error codes; raw SQL, driver messages and metadata are never exposed. */
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
