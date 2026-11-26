import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  DatabaseConflictError,
  DatabaseConstraintError,
  DatabaseUnavailableError,
  UniqueConstraintError,
  extractDatabaseCode,
  isDatabaseOperationError,
  isRetryableTransactionError,
  mapDatabaseError,
} from '../../dist/errors.js';
import { withSerializableTransaction } from '../../dist/transaction.js';

test('unknown database errors are mapped without leaking SQL or values', () => {
  const mapped = mapDatabaseError(
    new Error("SELECT password_hash FROM users WHERE username='sensitive-user'"),
  );
  assert.equal(mapped.code, 'DATABASE_OPERATION_FAILED');
  assert.equal(mapped.retryable, false);
  assert.doesNotMatch(mapped.message, /SELECT|password_hash|sensitive-user/iu);
  assert.equal(mapped.cause, undefined);
});

test('PostgreSQL SQLSTATEs map to stable errors without carrying driver details', () => {
  const serialization = mapDatabaseError({ code: '40001', detail: 'sensitive row value' });
  const deadlock = mapDatabaseError({ cause: { originalCode: '40P01', message: 'raw SQL' } });
  const uniqueViolation = mapDatabaseError({ code: '23505', detail: 'Key (email)=(a@b.c) exists' });
  const constraint = mapDatabaseError({ code: '23514', detail: 'secret check expression' });
  const fkConstraint = mapDatabaseError({ code: '23503', detail: 'foreign key detail' });
  const unavailable = mapDatabaseError({ code: '57P03', message: 'server details' });

  assert.ok(serialization instanceof DatabaseConflictError);
  assert.ok(deadlock instanceof DatabaseConflictError);
  assert.ok(uniqueViolation instanceof UniqueConstraintError);
  assert.ok(uniqueViolation instanceof DatabaseConstraintError);
  assert.equal(uniqueViolation.code, 'DATABASE_UNIQUE_VIOLATION');
  assert.ok(constraint instanceof DatabaseConstraintError);
  assert.equal(constraint instanceof UniqueConstraintError, false);
  assert.ok(fkConstraint instanceof DatabaseConstraintError);
  assert.equal(fkConstraint instanceof UniqueConstraintError, false);
  assert.ok(unavailable instanceof DatabaseUnavailableError);
  for (const mapped of [
    serialization,
    deadlock,
    uniqueViolation,
    constraint,
    fkConstraint,
    unavailable,
  ]) {
    assert.equal(mapped.cause, undefined);
    assert.doesNotMatch(mapped.message, /sensitive|raw SQL|secret|server details|email/iu);
  }
});

test('[BUG-075] Prisma 7 @prisma/adapter-pg nested driverAdapterError under P2010/P2039 preserves retries, maps constraints/pool errors, handles cycles, and leaks zero SQL', async () => {
  // 1. Serialization failure 40001 wrapped inside P2010 / P2039 meta.driverAdapterError.cause.originalCode
  const wrapped40001 = {
    code: 'P2010',
    message: 'Raw query failed. Code: `40001`. Message: `SELECT secret_token FROM sessions`',
    meta: {
      driverAdapterError: {
        name: 'DriverAdapterError',
        cause: {
          originalCode: '40001',
          originalMessage: 'could not serialize access due to concurrent update on users',
          kind: 'TransactionWriteConflict',
        },
      },
    },
  };
  assert.equal(extractDatabaseCode(wrapped40001), '40001');
  assert.equal(isDatabaseOperationError(wrapped40001), true);
  assert.equal(isRetryableTransactionError(wrapped40001), true);

  let attempts = 0;
  const txRes = await withSerializableTransaction(async () => 'ok-after-adapter-retry', {
    client: {
      async $transaction(fn) {
        attempts++;
        if (attempts < 3) throw wrapped40001;
        return fn({});
      },
    },
    maxRetries: 3,
    baseDelayMs: 0,
  });
  assert.equal(txRes, 'ok-after-adapter-retry');
  assert.equal(attempts, 3);

  // 2. Unique violation 23505 & UniqueConstraintViolation wrapped in P2039 + cyclic reference guard
  const cyclicUniqueErr = {
    code: 'P2039',
    meta: {
      driverAdapterError: {
        name: 'DriverAdapterError',
        cause: {
          originalCode: '23505',
          originalMessage:
            'duplicate key value violates unique constraint "users_email_key" (secret@sda.local)',
          kind: 'UniqueConstraintViolation',
        },
      },
    },
  };
  cyclicUniqueErr.meta.self = cyclicUniqueErr;
  const mappedUnique = mapDatabaseError(cyclicUniqueErr);
  assert.ok(mappedUnique instanceof UniqueConstraintError);
  assert.equal(mappedUnique.code, 'DATABASE_UNIQUE_VIOLATION');
  assert.equal(mappedUnique.cause, undefined);
  assert.doesNotMatch(mappedUnique.message, /users_email_key|secret@sda\.local/iu);
  assert.equal(isRetryableTransactionError(cyclicUniqueErr), false);

  // 3. NOT NULL violation (23502 / P2011 / NullConstraintViolation)
  for (const err of [
    { code: 'P2011', meta: { constraint: 'password_hash' } },
    { code: 'P2010', meta: { driverAdapterError: { cause: { originalCode: '23502' } } } },
    { meta: { driverAdapterError: { cause: { kind: 'NullConstraintViolation' } } } },
  ]) {
    const mapped = mapDatabaseError(err);
    assert.ok(mapped instanceof DatabaseConstraintError);
    assert.equal(mapped.code, 'DATABASE_CONSTRAINT');
    assert.equal(mapped.cause, undefined);
  }

  // 4. Connection / Pool exhaustion codes (P1001, P1008, P1017, P2024, P2037, 53300, 57P01, TooManyConnections)
  for (const err of [
    { code: 'P1001', message: 'Can not reach postgres://admin:fixture-password@10.0.0.5:5432' },
    { code: 'P1008', message: 'Operations timed out' },
    { code: 'P1017', message: 'Server closed connection' },
    { code: 'P2024', message: 'Timed out fetching connection from pool' },
    { code: 'P2037', message: 'Too many connections' },
    { code: 'P2039', meta: { driverAdapterError: { cause: { originalCode: '53300' } } } },
    { code: 'P2010', meta: { driverAdapterError: { cause: { originalCode: '57P01' } } } },
    { meta: { driverAdapterError: { cause: { kind: 'TooManyConnections' } } } },
  ]) {
    const mapped = mapDatabaseError(err);
    assert.ok(mapped instanceof DatabaseUnavailableError);
    assert.equal(mapped.code, 'DATABASE_UNAVAILABLE');
    assert.equal(mapped.retryable, true);
    assert.equal(mapped.cause, undefined);
    assert.doesNotMatch(mapped.message, /fixture-password|10\.0\.0\.5/iu);
  }
});
