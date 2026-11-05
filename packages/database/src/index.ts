export {
  buildPgPoolConfig,
  createDatabaseClient,
  disconnectDatabase,
  getDatabaseClient,
} from './client.js';
export {
  DatabaseConflictError,
  DatabaseConstraintError,
  DatabaseError,
  DatabaseNotFoundError,
  DatabaseUnavailableError,
  isDatabaseOperationError,
  mapDatabaseError,
} from './errors.js';
export {
  withSerializableTransaction,
  type SerializableTransactionOptions,
  type TransactionOperation,
} from './transaction.js';
export * from './generated/prisma/enums.js';
export type * from './generated/prisma/models.js';
export { Prisma } from './generated/prisma/client.js';

/**
 * Total business tables defined across `prisma/schema/*.prisma` (31 baseline domain tables
 * + 8 hardened auth/MFA, audit-anchor, SOC detection, outbox, and async-export tables).
 */
export const businessTableCount = 39;
