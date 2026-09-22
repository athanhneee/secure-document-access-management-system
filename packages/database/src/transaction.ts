import { randomInt } from 'node:crypto';
import { Prisma, type PrismaClient } from './generated/prisma/client.js';
import { getDatabaseClient } from './client.js';
import {
  DatabaseConflictError,
  isDatabaseOperationError,
  isRetryableTransactionError,
  mapDatabaseError,
} from './errors.js';

export type TransactionOperation<T> = (transaction: Prisma.TransactionClient) => Promise<T>;

export interface SerializableTransactionOptions {
  client?: PrismaClient;
  maxRetries?: number;
  maxWaitMs?: number;
  timeoutMs?: number;
  baseDelayMs?: number;
}

function retryDelay(baseDelayMs: number, attempt: number): number {
  const exponential = Math.min(baseDelayMs * 2 ** attempt, 1_000);
  return exponential + randomInt(0, Math.max(1, Math.floor(exponential / 4)));
}

export async function withSerializableTransaction<T>(
  operation: TransactionOperation<T>,
  options: SerializableTransactionOptions = {},
): Promise<T> {
  const client = options.client ?? getDatabaseClient();
  const maxRetries = options.maxRetries ?? 3;
  if (!Number.isInteger(maxRetries) || maxRetries < 0 || maxRetries > 5) {
    throw new RangeError('maxRetries must be an integer between 0 and 5.');
  }

  for (let attempt = 0; attempt <= maxRetries; attempt += 1) {
    try {
      return await client.$transaction(operation, {
        isolationLevel: Prisma.TransactionIsolationLevel.Serializable,
        maxWait: options.maxWaitMs ?? 5_000,
        timeout: options.timeoutMs ?? 15_000,
      });
    } catch (error) {
      if (!isDatabaseOperationError(error)) throw error;
      if (!isRetryableTransactionError(error)) throw mapDatabaseError(error);
      if (attempt === maxRetries) throw new DatabaseConflictError();
      await new Promise((resolve) =>
        setTimeout(resolve, retryDelay(options.baseDelayMs ?? 25, attempt)),
      );
    }
  }

  throw new DatabaseConflictError();
}
