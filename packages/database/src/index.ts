export { createDatabaseClient, disconnectDatabase, getDatabaseClient } from './client.js';
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

export const businessTableCount = 31;
