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

/**
 * Thuật toán: Tính độ trễ thử lại lũy thừa có trần kết hợp nhiễu ngẫu nhiên mật mã (Capped Exponential Backoff + CSPRNG Jitter).
 * Algorithm: Capped exponential backoff with CSPRNG jitter.
 * Computes `min(base * 2^attempt, 1000ms) + uniform_random(0, exponential / 4)` to
 * decorrelate contending `SERIALIZABLE` transactions under write bursts.
 */
function retryDelay(baseDelayMs: number, attempt: number): number {
  const exponential = Math.min(baseDelayMs * 2 ** attempt, 1_000);
  return exponential + randomInt(0, Math.max(1, Math.floor(exponential / 4)));
}

/**
 * Thuật toán: Vòng lặp thử lại giao dịch mức cô lập `SERIALIZABLE` cho lỗi xung đột tạm thời (`40001`, `40P01`, `P2034`).
 * Algorithm: Bounded `SERIALIZABLE` transaction retry loop.
 * Executes `operation` at PostgreSQL `Serializable` isolation and retries transient
 * serialization/deadlock failures (`40001`, `40P01`, `P2034`) up to `maxRetries` before
 * escalating to `DatabaseConflictError`.
 */
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
