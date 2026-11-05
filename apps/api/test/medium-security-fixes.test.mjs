import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { BadRequestException, ForbiddenException } from '@nestjs/common';
import { CsrfService } from '../dist/modules/auth/csrf.service.js';
import { PasswordService } from '../dist/modules/auth/password.service.js';
import { executeResetPassword } from '../dist/modules/auth/auth-password.helper.js';
import { evaluatePolicy } from '../dist/modules/abac/policy-engine.js';
import { matchesCondition } from '../dist/modules/abac/policy-condition-matcher.js';
import { AccessSessionsService } from '../dist/modules/access-sessions/access-sessions.service.js';

test('[MEDIUM-01] CsrfService handles multi-byte UTF-8 safely without RangeError & PasswordService throws 400 BadRequestException', async () => {
  const csrf = new CsrfService({ corsOrigins: ['http://localhost:3000'] });
  const asciiCookie = 'a'.repeat(32);
  // '€' is 1 UTF-16 code unit (.length === 32) but 3 UTF-8 bytes (byteLength === 96)
  const multibyteHeader = '€'.repeat(32);
  assert.equal(asciiCookie.length, multibyteHeader.length);

  assert.throws(
    () =>
      csrf.assertRequest({
        headers: { origin: 'http://localhost:3000', 'x-csrf-token': multibyteHeader },
        cookies: { sda_csrf: asciiCookie },
      }),
    (err) => err instanceof ForbiddenException,
  );

  const passwords = new PasswordService();
  assert.throws(
    () => passwords.validate('short'),
    (err) => err instanceof BadRequestException && err.message.includes('PASSWORD_LENGTH'),
  );
  assert.throws(
    () => passwords.validate('SafePrefix_officer.alpha_2026!', ['officer.alpha']),
    (err) =>
      err instanceof BadRequestException && err.message.includes('PASSWORD_CONTAINS_IDENTIFIER'),
  );

  let consumed = false;
  await assert.rejects(
    executeResetPassword(
      {
        repository: {
          findPasswordResetOwner: async () => ({
            userId: 9n,
            username: 'auditor.nguyen',
            email: 'nguyen.sec@agency.gov.vn',
          }),
          consumePasswordReset: async () => {
            consumed = true;
            return 9n;
          },
        },
        passwords,
        tokens: { hashOpaqueToken: (t) => t },
        rateLimit: {},
        audit: { record: async () => {} },
        mailer: {},
        resetTtl: 900,
      },
      'opaque-reset-token',
      'ResetWith_auditor.nguyen_Inside!',
      { ip: '127.0.0.1', correlationId: 'c1' },
    ),
    (err) => err instanceof BadRequestException,
  );
  assert.equal(
    consumed,
    false,
    'Reset token must not be consumed when new credential fails policy',
  );
});

test('[MEDIUM-02] ABAC policy engine does not coerce plain strings like "dept-2" or "1" via Date.parse()', () => {
  // Direct condition matcher checks: in V8, Date.parse("dept-2") === 980985600000 and Date.parse("1") === 978307200000.
  assert.equal(
    matchesCondition(
      { id: 'c-dept', attribute: 'subject.departmentId', operator: 'GTE', expected: 100 },
      { 'subject.departmentId': 'dept-2' },
    ),
    false,
  );
  assert.equal(
    matchesCondition(
      { id: 'c-num-str', attribute: 'subject.departmentId', operator: 'GTE', expected: 100 },
      { 'subject.departmentId': '1' },
    ),
    false,
  );
  assert.equal(
    matchesCondition(
      {
        id: 'c-iso',
        attribute: 'environment.currentTime',
        operator: 'GTE',
        expected: '2026-01-01T00:00:00.000Z',
      },
      { 'environment.currentTime': '2026-06-01T09:00:00.000Z' },
    ),
    true,
  );

  const compiledPolicy = {
    version: '1',
    requiredAttributes: [],
    rules: [
      {
        id: 'r1',
        code: 'RISK_SCORE_SPOOF_CHECK',
        effect: 'PERMIT',
        priority: 10,
        targetResource: 'DOCUMENT',
        targetAction: 'VIEW',
        combiningAlgorithm: 'DENY_OVERRIDES',
        validFrom: '2020-01-01T00:00:00.000Z',
        validTo: null,
        obligations: [],
        groups: [
          {
            id: 1,
            conditions: [
              {
                id: 'c1',
                attribute: 'environment.riskScore',
                operator: 'GTE',
                expected: 100,
              },
            ],
          },
        ],
      },
    ],
  };

  // Runtime string "dept-2" or "1" must never be coerced into a 2001 epoch timestamp >= 100
  for (const spoofedValue of ['dept-2', '1']) {
    const result = evaluatePolicy(compiledPolicy, {
      resourceType: 'DOCUMENT',
      action: 'VIEW',
      subject: {
        clearanceRank: 3,
        departmentId: 'dept-2',
        employmentStatus: 'ACTIVE',
        projects: [],
      },
      resource: {
        classificationRank: 1,
        ownerId: '10',
        departmentId: 'dept-2',
        category: 'GENERAL',
        status: 'ACTIVE',
      },
      environment: {
        currentTime: '2026-06-01T09:00:00.000Z',
        ip: '10.0.0.5',
        trustedNetwork: true,
        deviceTrust: true,
        mfa: true,
        riskScore: spoofedValue,
      },
    });

    assert.equal(result.decision, 'DENY');
    assert.equal(result.reasonCode, 'DEFAULT_DENY');
  }
});

test('[MEDIUM-03] Scripts use parameterized SQL, compose hides Redis CLI secret, CSP drops unsafe-inline & login removes static credential', () => {
  const repoRoot = path.resolve(import.meta.dirname, '../../..');

  for (const relPath of [
    'scripts/helpers/backup-restore-fixtures.mjs',
    'scripts/lib/load-test-scenarios.mjs',
    'scripts/lib/profile-schema-seed.mjs',
  ]) {
    const content = fs.readFileSync(path.join(repoRoot, relPath), 'utf8');
    assert.doesNotMatch(
      content,
      /'\$\{/,
      `${relPath} must not interpolate '${'${...}'}' into SQL string literals`,
    );
  }

  const composeYaml = fs.readFileSync(path.join(repoRoot, 'infra/compose.yaml'), 'utf8');
  assert.doesNotMatch(composeYaml, /--requirepass/);
  assert.doesNotMatch(composeYaml, /redis-cli\s+-a/);

  const nextConfig = fs.readFileSync(path.join(repoRoot, 'apps/web/next.config.ts'), 'utf8');
  const nextProxy = fs.readFileSync(path.join(repoRoot, 'apps/web/proxy.ts'), 'utf8');
  assert.doesNotMatch(nextConfig, /unsafe-inline/);
  assert.doesNotMatch(nextProxy, /unsafe-inline/);

  const demoPanel = fs.readFileSync(
    path.join(repoRoot, 'apps/web/app/login/login-demo-panel.tsx'),
    'utf8',
  );
  assert.doesNotMatch(demoPanel, /DemoPass/);
});

test('[MEDIUM-04] AccessSessionsService validates UUID (400), writes audit log on termination & preserves 64-bit BigInt precision', async () => {
  const auditEvents = [];
  const sessionUuid = randomUUID();
  const docUuid = randomUUID();
  const largeSnowflakeId = 9007199254740993n; // > Number.MAX_SAFE_INTEGER

  const mockDb = {
    accessSession: {
      findMany: async () => [
        {
          id: sessionUuid,
          access_grant_id: randomUUID(),
          document_version_id: largeSnowflakeId,
          user_id: largeSnowflakeId,
          ip_address: '10.10.1.5',
          user_agent: 'Mozilla/5.0',
          status: 'ACTIVE',
          started_at: new Date('2026-05-01T10:00:00.000Z'),
          last_activity_at: new Date('2026-05-01T10:05:00.000Z'),
          ended_at: null,
          terminated_reason: null,
          users: { id: largeSnowflakeId, username: 'reader.one', full_name: 'Reader One' },
          document_versions: {
            id: largeSnowflakeId,
            version_no: 2,
            document: { id: docUuid, document_code: 'DOC-001', title: 'Secret Plan' },
          },
        },
      ],
      findUnique: async ({ where }) =>
        where.id === sessionUuid
          ? {
              id: sessionUuid,
              status: 'ACTIVE',
              user_id: largeSnowflakeId,
              document_versions: { document_id: docUuid },
            }
          : null,
      update: async ({ where, data }) => ({
        id: where.id,
        status: data.status,
      }),
    },
  };

  const mockAuditWriter = {
    writeLog: async (event, ctx) => {
      auditEvents.push({ event, ctx });
    },
  };

  const service = new AccessSessionsService(mockDb, mockAuditWriter);

  // 1. Invalid UUID throws 400 BadRequestException instead of Prisma 500
  await assert.rejects(
    service.terminateSession('not-a-valid-uuid'),
    (err) => err instanceof BadRequestException,
  );

  // 2. Precision preserved for 64-bit BigInt (> 2^53 - 1)
  const listed = await service.listSessions();
  assert.equal(listed.data[0].documentVersionId, '9007199254740993');
  assert.equal(listed.data[0].userId, '9007199254740993');

  // 3. Termination records ACCESS_SESSION_TERMINATED in SECURITY audit partition
  const terminated = await service.terminateSession(
    sessionUuid,
    'Emergency SOC containment',
    {
      userId: 2n,
      username: 'sec.officer',
      departmentId: 1n,
      sessionId: randomUUID(),
      roles: ['SECURITY_OFFICER'],
      mfa: true,
    },
    { ip: '10.10.0.99', correlationId: 'corr-soc-1' },
  );
  assert.equal(terminated.status, 'TERMINATED');
  assert.equal(auditEvents.length, 1);
  assert.equal(auditEvents[0].event.action, 'ACCESS_SESSION_TERMINATED');
  assert.equal(auditEvents[0].event.chainPartition, 'SECURITY');
  assert.equal(auditEvents[0].event.documentId, docUuid);
  assert.equal(auditEvents[0].event.details.targetUserId, '9007199254740993');
});
