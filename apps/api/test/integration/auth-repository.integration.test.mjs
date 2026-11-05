import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { after, before, test } from 'node:test';
import { createEphemeralDatabaseHarness } from '../helpers/postgres-integration-harness.mjs';

const dbHarness = createEphemeralDatabaseHarness('sda_auth', { coerceBigIntId: true });
let repository;

before(async () => {
  const ready = await dbHarness.setup();
  if (!ready) return;
  const authModule = await import('../../dist/modules/auth/auth.repository.js');
  repository = new authModule.AuthRepository();
});

after(async () => {
  await dbHarness.teardown();
});

test('refresh rotation rejects reuse, revokes the family and creates an alert', async (t) => {
  if (!dbHarness.dbAvailable) {
    t.skip('Live PostgreSQL server not reachable at 127.0.0.1:5432 (run pnpm infra:up)');
    return;
  }
  const user = await dbHarness.insertOne(
    `INSERT INTO users(username,email,password_hash,full_name,status)
     VALUES ('active.auth','active.auth@example.invalid','argon2-fixture','Active auth','ACTIVE') RETURNING id`,
  );
  const sessionId = randomUUID();
  const familyId = randomUUID();
  const oldToken = 'old-refresh-token-value';
  await repository.createSession({
    userId: user.id,
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
  const state = await dbHarness.sql.query(
    `SELECT
       (SELECT status::text FROM auth_sessions WHERE id=$1) AS session_status,
       (SELECT count(*)::int FROM refresh_tokens WHERE token_family_id=$2 AND revoked_at IS NULL) AS live_tokens,
       (SELECT count(*)::int FROM security_alerts WHERE detected_user_id=$3 AND alert_type='REFRESH_TOKEN_REUSE') AS alerts`,
    [sessionId, familyId, user.id],
  );
  assert.deepEqual(state.rows[0], { session_status: 'REVOKED', live_tokens: 0, alerts: 1 });
});

test('DISABLED account cannot refresh and its family is revoked', async (t) => {
  if (!dbHarness.dbAvailable) {
    t.skip('Live PostgreSQL server not reachable at 127.0.0.1:5432 (run pnpm infra:up)');
    return;
  }
  const user = await dbHarness.insertOne(
    `INSERT INTO users(username,email,password_hash,full_name,status,disabled_at)
     VALUES ('disabled.auth','disabled.auth@example.invalid','argon2-fixture','Disabled auth','DISABLED',now()) RETURNING id`,
  );
  const sessionId = randomUUID();
  const familyId = randomUUID();
  const tokenHash = createHash('sha256').update('disabled-refresh-token').digest('hex');
  await repository.createSession({
    userId: user.id,
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
  const session = await dbHarness.sql.query('SELECT status::text FROM auth_sessions WHERE id=$1', [
    sessionId,
  ]);
  assert.equal(session.rows[0].status, 'REVOKED');
});
