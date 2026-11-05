import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import {
  buildPgPoolConfig,
  businessTableCount,
  disconnectDatabase,
  getDatabaseClient,
} from '../../dist/index.js';
import { DatabaseConflictError } from '../../dist/errors.js';
import { withSerializableTransaction } from '../../dist/transaction.js';

const originalDatabaseUrl = process.env.DATABASE_URL;
const originalNodeEnvironment = process.env.NODE_ENV;
const originalDbSsl = process.env.DATABASE_SSL;
const originalRejectUnauthorized = process.env.DATABASE_SSL_REJECT_UNAUTHORIZED;
const originalDbCaCert = process.env.DATABASE_CA_CERT;

after(async () => {
  await disconnectDatabase();
  if (originalDatabaseUrl === undefined) delete process.env.DATABASE_URL;
  else process.env.DATABASE_URL = originalDatabaseUrl;
  if (originalNodeEnvironment === undefined) delete process.env.NODE_ENV;
  else process.env.NODE_ENV = originalNodeEnvironment;
  if (originalDbSsl === undefined) delete process.env.DATABASE_SSL;
  else process.env.DATABASE_SSL = originalDbSsl;
  if (originalRejectUnauthorized === undefined) delete process.env.DATABASE_SSL_REJECT_UNAUTHORIZED;
  else process.env.DATABASE_SSL_REJECT_UNAUTHORIZED = originalRejectUnauthorized;
  if (originalDbCaCert === undefined) delete process.env.DATABASE_CA_CERT;
  else process.env.DATABASE_CA_CERT = originalDbCaCert;
});

test('businessTableCount matches all 39 Prisma business models', () => {
  assert.equal(businessTableCount, 39);
});

test('buildPgPoolConfig enforces TLS certificate verification by default and blocks CWE-295 in production', () => {
  delete process.env.DATABASE_SSL_REJECT_UNAUTHORIZED;
  delete process.env.DATABASE_CA_CERT;
  process.env.NODE_ENV = 'production';
  process.env.DATABASE_SSL = 'true';

  const secureCfg = buildPgPoolConfig(
    'postgresql://app_user:test-placeholder@db.internal:5432/secure_docs?schema=public&sslmode=require',
  );
  assert.equal(secureCfg.schema, 'public');
  assert.equal(secureCfg.poolConfig.ssl?.rejectUnauthorized, true);
  assert.equal(secureCfg.poolConfig.ssl?.minVersion, 'TLSv1.2');

  process.env.DATABASE_CA_CERT =
    '-----BEGIN CERTIFICATE-----\\nTEST_ROOT_CA\\n-----END CERTIFICATE-----';
  const caCfg = buildPgPoolConfig(
    'postgresql://app_user:test-placeholder@db.internal:5432/secure_docs',
  );
  assert.equal(caCfg.poolConfig.ssl?.rejectUnauthorized, true);
  assert.match(String(caCfg.poolConfig.ssl?.ca), /BEGIN CERTIFICATE/);
  delete process.env.DATABASE_CA_CERT;

  delete process.env.DATABASE_SSL;
  const prodDefaultCfg = buildPgPoolConfig(
    'postgresql://app_user:test-placeholder@db.internal:5432/secure_docs?schema=public',
  );
  assert.equal(prodDefaultCfg.poolConfig.ssl?.rejectUnauthorized, true);
  assert.equal(prodDefaultCfg.poolConfig.ssl?.minVersion, 'TLSv1.2');

  process.env.DATABASE_SSL = 'false';
  assert.throws(
    () => buildPgPoolConfig('postgresql://app_user:test-placeholder@db.internal:5432/secure_docs'),
    /CWE-319/u,
  );
  delete process.env.DATABASE_SSL;

  assert.throws(
    () =>
      buildPgPoolConfig(
        'postgresql://app_user:test-placeholder@db.internal:5432/secure_docs?sslmode=disable',
      ),
    /CWE-319/u,
  );

  process.env['DATABASE_SSL_REJECT_UNAUTHORIZED'] = String(false);
  assert.throws(
    () => buildPgPoolConfig('postgresql://app_user:test-placeholder@db.internal:5432/secure_docs'),
    /CWE-295/u,
  );
  delete process.env.DATABASE_SSL_REJECT_UNAUTHORIZED;

  assert.throws(
    () =>
      buildPgPoolConfig(
        'postgresql://app_user:test-placeholder@db.internal:5432/secure_docs?sslmode=no-verify',
      ),
    /CWE-295/u,
  );

  process.env.NODE_ENV = 'development';
  const supabaseCfg = buildPgPoolConfig(
    'postgresql://postgres:test-placeholder@db.projectref.supabase.co:5432/postgres',
  );
  assert.equal(supabaseCfg.poolConfig.ssl?.rejectUnauthorized, true);
  assert.equal(supabaseCfg.poolConfig.ssl?.minVersion, 'TLSv1.2');
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
