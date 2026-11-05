import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { ForbiddenException } from '@nestjs/common';
import { activateMfaAuthSession } from '../dist/modules/auth/auth-session.repository.js';
import { ExportJobService } from '../dist/modules/reports/export-job.service.js';

test('[HIGH-04] activateMfaAuthSession rotates sessionId & token_family_id and revokes pre-MFA refresh tokens', async () => {
  const preMfaSessionId = randomUUID();
  const preMfaFamilyId = randomUUID();
  const revokedFamilies = [];
  const createdSessions = [];
  const createdTokens = [];

  const mockDb = {
    $transaction: async (fn) =>
      fn({
        authSession: {
          findFirst: async () => ({
            id: preMfaSessionId,
            user_id: 7n,
            token_family_id: preMfaFamilyId,
            ip_address: '127.0.0.1',
            user_agent: 'TestAgent',
            status: 'ACTIVE',
            expires_at: new Date(Date.now() + 60_000),
          }),
          updateMany: async () => ({ count: 1 }),
          create: async ({ data }) => createdSessions.push(data),
        },
        refreshToken: {
          updateMany: async ({ where }) => revokedFamilies.push(where.token_family_id),
          create: async ({ data }) => createdTokens.push(data),
        },
      }),
  };

  const rotatedId = await activateMfaAuthSession(mockDb, preMfaSessionId, 7n, {
    id: randomUUID(),
    hash: 'h'.repeat(64),
    expiresAt: new Date(Date.now() + 3600_000),
  });

  assert.ok(rotatedId);
  assert.notEqual(rotatedId, preMfaSessionId);
  assert.deepEqual(revokedFamilies, [preMfaFamilyId]);
  assert.equal(createdSessions.length, 1);
  assert.notEqual(createdSessions[0].token_family_id, preMfaFamilyId);
  assert.equal(createdTokens[0].auth_session_id, rotatedId);
  assert.equal(createdTokens[0].token_family_id, createdSessions[0].token_family_id);
});

test('[HIGH-05] ExportJobService enforces per-type RBAC permissions and applies department-scoped filterParams', async () => {
  let capturedWhere = null;
  const jobs = new Map();
  const mockDb = {
    asyncExportJob: {
      create: async ({ data }) => {
        const row = { ...data, created_at: new Date(), completed_at: null, row_count: 0 };
        jobs.set(data.id, row);
        return row;
      },
      update: async ({ where, data }) => {
        const existing = jobs.get(where.id);
        const next = { ...existing, ...data };
        jobs.set(where.id, next);
        return next;
      },
      findUnique: async ({ where }) => jobs.get(where.id) ?? null,
    },
    auditLog: {
      findMany: async ({ where }) => {
        capturedWhere = where;
        return [];
      },
    },
  };

  const mockAuthorization = {
    hasPermission: async (_actor, resource, action) =>
      resource === 'AUDIT_LOG' && action === 'EXPORT',
    visibleDepartmentIds: async () => [10n],
  };

  const auditorActor = {
    userId: 55n,
    username: 'auditor.dept10',
    departmentId: 10n,
    sessionId: randomUUID(),
    roles: ['AUDITOR'],
    mfa: true,
  };

  const service = new ExportJobService(mockDb, undefined, mockAuthorization);

  // 1. AUDITOR with only AUDIT_LOG:EXPORT cannot export INCIDENT_REPORTS
  await assert.rejects(
    service.createExportJob(
      { exportType: 'INCIDENT_REPORTS', format: 'CSV', filterParams: {} },
      auditorActor,
    ),
    (err) => err instanceof ForbiddenException,
  );

  // 2. Requesting out-of-scope departmentId=99 is rejected
  await assert.rejects(
    service.createExportJob(
      { exportType: 'AUDIT_LOGS', format: 'JSON', filterParams: { departmentId: '99' } },
      auditorActor,
    ),
    (err) => err instanceof ForbiddenException,
  );

  // 3. Valid filterParams + department scope are applied to Prisma query
  await service.processExportJob(
    (
      await service.createExportJob(
        {
          exportType: 'AUDIT_LOGS',
          format: 'JSON',
          filterParams: { action: 'DOCUMENT_DOWNLOADED', from: '2026-01-01', to: '2026-12-31' },
        },
        auditorActor,
      )
    ).id,
    {
      exportType: 'AUDIT_LOGS',
      format: 'JSON',
      filterParams: { action: 'DOCUMENT_DOWNLOADED', from: '2026-01-01', to: '2026-12-31' },
    },
    auditorActor,
    'corr-1',
    [10n],
  );

  assert.ok(capturedWhere);
  assert.equal(capturedWhere.action, 'DOCUMENT_DOWNLOADED');
  assert.ok(capturedWhere.occurred_at?.gte instanceof Date);
  assert.ok(Array.isArray(capturedWhere.OR));
});

test('[HIGH-06] Migration 20261105133000 enforces FORCE RLS, explicit policies, service_role least privilege & TRUNCATE triggers', () => {
  const migrationPath = path.resolve(
    import.meta.dirname,
    '../../../packages/database/prisma/migrations/20261105133000_rls_policies_and_audit_truncate_guard/migration.sql',
  );
  const sql = fs.readFileSync(migrationPath, 'utf8');
  assert.match(sql, /BEFORE TRUNCATE ON public\.audit_logs/);
  assert.match(sql, /BEFORE TRUNCATE ON public\.audit_anchors/);
  assert.match(sql, /FORCE ROW LEVEL SECURITY/);
  assert.match(sql, /CREATE POLICY p_zero_trust_postgrest_deny.*AS RESTRICTIVE/);
  assert.match(sql, /CREATE POLICY p_zero_trust_backend_allow.*AS PERMISSIVE/);
  assert.match(sql, /GRANT SELECT, INSERT ON TABLE public\.%I TO service_role/);
  assert.doesNotMatch(sql, /GRANT ALL ON TABLE/);
});
