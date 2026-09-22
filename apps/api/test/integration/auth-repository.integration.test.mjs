import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { after, before, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import pg from 'pg';

for (const line of readFileSync(
  new URL('../../../../.local/dev.env', import.meta.url),
  'utf8',
).split(/\r?\n/u)) {
  const separator = line.indexOf('=');
  if (separator > 0) process.env[line.slice(0, separator)] ??= line.slice(separator + 1);
}

const sourceUrl = new URL(process.env.DATABASE_URL);
const adminUrl = new URL(sourceUrl);
adminUrl.pathname = '/postgres';
adminUrl.search = '';
const databaseName = `sda_auth_${randomUUID().replaceAll('-', '')}`;
const targetUrl = new URL(sourceUrl);
targetUrl.pathname = `/${databaseName}`;
let database;
let repository;
let disconnectDatabase;

async function adminQuery(sql) {
  const client = new pg.Client({ connectionString: adminUrl.toString() });
  await client.connect();
  try {
    await client.query(sql);
  } finally {
    await client.end();
  }
}

before(async () => {
  assert.match(databaseName, /^sda_auth_[a-f0-9]{32}$/u);
  await adminQuery(`DROP DATABASE IF EXISTS "${databaseName}" WITH (FORCE)`);
  await adminQuery(`CREATE DATABASE "${databaseName}"`);
  const prismaCli = fileURLToPath(import.meta.resolve('prisma')).replace(
    /[\\/]build[\\/]types\.js$/u,
    '/build/index.js',
  );
  const migration = spawnSync(
    process.execPath,
    [prismaCli, 'migrate', 'deploy', '--config', 'prisma.config.ts'],
    {
      cwd: fileURLToPath(new URL('../../../../packages/database/', import.meta.url)),
      encoding: 'utf8',
      env: { ...process.env, DATABASE_URL: targetUrl.toString(), NODE_ENV: 'test' },
      shell: false,
    },
  );
  assert.equal(migration.status, 0, 'auth integration migrations must apply');
  process.env.DATABASE_URL = targetUrl.toString();
  const authModule = await import('../../dist/modules/auth/auth.repository.js');
  ({ disconnectDatabase } = await import('@sda/database'));
  repository = new authModule.AuthRepository();
  database = new pg.Client({ connectionString: targetUrl.toString() });
  await database.connect();
});

after(async () => {
  await database?.end();
  await disconnectDatabase?.();
  await adminQuery(`DROP DATABASE IF EXISTS "${databaseName}" WITH (FORCE)`);
});

test('refresh rotation rejects reuse, revokes the family and creates an alert', async () => {
  const user = await database.query(
    `INSERT INTO users(username,email,password_hash,full_name,status)
     VALUES ('active.auth','active.auth@example.invalid','argon2-fixture','Active auth','ACTIVE') RETURNING id`,
  );
  const sessionId = randomUUID();
  const familyId = randomUUID();
  const oldToken = 'old-refresh-token-value';
  await repository.createSession({
    userId: user.rows[0].id,
    sessionId,
    familyId,
    refreshTokenId: randomUUID(),
    refreshTokenHash: createHash('sha256').update(oldToken).digest('hex'),
    refreshExpiresAt: new Date(Date.now() + 3_600_000),
    sessionExpiresAt: new Date(Date.now() + 3_600_000),
    mfaVerified: true,
    context: { ip: '192.0.2.1', correlationId: randomUUID() },
  });
  const replacement = {
    id: randomUUID(),
    hash: createHash('sha256').update('replacement-refresh-token').digest('hex'),
    expiresAt: new Date(Date.now() + 3_600_000),
  };
  const rotated = await repository.rotateRefreshToken(
    createHash('sha256').update(oldToken).digest('hex'),
    replacement,
  );
  assert.equal(rotated.kind, 'rotated');

  const reuse = await repository.rotateRefreshToken(
    createHash('sha256').update(oldToken).digest('hex'),
    {
      id: randomUUID(),
      hash: createHash('sha256').update('must-not-survive').digest('hex'),
      expiresAt: new Date(Date.now() + 3_600_000),
    },
  );
  assert.equal(reuse.kind, 'reuse');
  const state = await database.query(
    `SELECT
       (SELECT status::text FROM auth_sessions WHERE id=$1) AS session_status,
       (SELECT count(*)::int FROM refresh_tokens WHERE token_family_id=$2 AND revoked_at IS NULL) AS live_tokens,
       (SELECT count(*)::int FROM security_alerts WHERE detected_user_id=$3 AND alert_type='REFRESH_TOKEN_REUSE') AS alerts`,
    [sessionId, familyId, user.rows[0].id],
  );
  assert.deepEqual(state.rows[0], { session_status: 'REVOKED', live_tokens: 0, alerts: 1 });
});

test('DISABLED account cannot refresh and its family is revoked', async () => {
  const user = await database.query(
    `INSERT INTO users(username,email,password_hash,full_name,status,disabled_at)
     VALUES ('disabled.auth','disabled.auth@example.invalid','argon2-fixture','Disabled auth','DISABLED',now()) RETURNING id`,
  );
  const sessionId = randomUUID();
  const familyId = randomUUID();
  const tokenHash = createHash('sha256').update('disabled-refresh-token').digest('hex');
  await repository.createSession({
    userId: user.rows[0].id,
    sessionId,
    familyId,
    refreshTokenId: randomUUID(),
    refreshTokenHash: tokenHash,
    refreshExpiresAt: new Date(Date.now() + 3_600_000),
    sessionExpiresAt: new Date(Date.now() + 3_600_000),
    mfaVerified: true,
    context: { ip: '192.0.2.2', correlationId: randomUUID() },
  });
  const result = await repository.rotateRefreshToken(tokenHash, {
    id: randomUUID(),
    hash: createHash('sha256').update('disabled-replacement').digest('hex'),
    expiresAt: new Date(Date.now() + 3_600_000),
  });
  assert.equal(result.kind, 'disabled');
  const session = await database.query('SELECT status::text FROM auth_sessions WHERE id=$1', [
    sessionId,
  ]);
  assert.equal(session.rows[0].status, 'REVOKED');
});
