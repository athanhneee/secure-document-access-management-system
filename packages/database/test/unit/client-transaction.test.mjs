import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { disconnectDatabase, getDatabaseClient } from '../../dist/client.js';
import { DatabaseConflictError } from '../../dist/errors.js';
import { withSerializableTransaction } from '../../dist/transaction.js';

const originalDatabaseUrl = process.env.DATABASE_URL;
const originalNodeEnvironment = process.env.NODE_ENV;

after(async () => {
  await disconnectDatabase();
  if (originalDatabaseUrl === undefined) delete process.env.DATABASE_URL;
  else process.env.DATABASE_URL = originalDatabaseUrl;
  if (originalNodeEnvironment === undefined) delete process.env.NODE_ENV;
  else process.env.NODE_ENV = originalNodeEnvironment;
});

test('database client is a singleton during development hot reload', async () => {
  process.env.NODE_ENV = 'development';
  process.env.DATABASE_URL = 'postgresql://127.0.0.1:5432/unit';

  assert.equal(getDatabaseClient(), getDatabaseClient());
  await disconnectDatabase();
});

test('serializable transaction retries Prisma conflicts and PostgreSQL deadlocks only to the limit', async () => {
  let attempts = 0;
  const eventuallySuccessfulClient = {
    async $transaction(operation) {
      attempts += 1;
      if (attempts === 1) throw { code: 'P2034', message: 'must not escape' };
      if (attempts === 2) throw { cause: { code: '40P01', message: 'must not escape' } };
      return operation({});
    },
  };

  const result = await withSerializableTransaction(async () => 'committed', {
    client: eventuallySuccessfulClient,
    maxRetries: 2,
    baseDelayMs: 0,
  });
  assert.equal(result, 'committed');
  assert.equal(attempts, 3);

  const alwaysConflictingClient = {
    async $transaction() {
      throw { code: '40001', message: 'SELECT private_data' };
    },
  };
  await assert.rejects(
    withSerializableTransaction(async () => undefined, {
      client: alwaysConflictingClient,
      maxRetries: 1,
      baseDelayMs: 0,
    }),
    (error) =>
      error instanceof DatabaseConflictError &&
      !/SELECT|private_data/u.test(error.message) &&
      error.retryable,
  );
});

test('serializable transaction validates its retry budget', async () => {
  await assert.rejects(
    withSerializableTransaction(async () => undefined, {
      client: { $transaction: async () => undefined },
      maxRetries: 6,
    }),
    RangeError,
  );
});

test('serializable transaction preserves application exceptions from the operation', async () => {
  const applicationError = new Error('safe application decision');
  const client = {
    async $transaction(operation) {
      return operation({});
    },
  };
  await assert.rejects(
    withSerializableTransaction(
      async () => {
        throw applicationError;
      },
      { client },
    ),
    (error) => error === applicationError,
  );
});
