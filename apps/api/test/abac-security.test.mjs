import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { BadRequestException } from '@nestjs/common';
import { AppErrorCode } from '@sda/contracts';
import { HttpExceptionFilter } from '../dist/common/filters/http-exception.filter.js';
import { buildGrantSubjectAttributes } from '../dist/modules/access-grants/grant-pip.helper.js';
import { queryActiveUserSessions } from '../dist/modules/auth/auth-sessions-management.helper.js';
import { buildPepSubjectAttributes } from '../dist/modules/documents/pep-context-builder.js';
import {
  canSimulatePolicy,
  SYSTEM_ROLE_PERMISSION_MATRIX,
} from '../dist/modules/rbac/permission-matrix.js';

test('only system admin and security officer receive POLICY/SIMULATE', () => {
  const allowed = Object.entries(SYSTEM_ROLE_PERMISSION_MATRIX)
    .filter(([, permissions]) => permissions.includes('POLICY_SIMULATE'))
    .map(([role]) => role)
    .sort();
  assert.deepEqual(allowed, ['SECURITY_OFFICER', 'SYSTEM_ADMIN']);
  assert.equal(canSimulatePolicy(['SYSTEM_ADMIN']), true);
  assert.equal(canSimulatePolicy(['SECURITY_OFFICER']), true);
  assert.equal(canSimulatePolicy(['CUSTOM_POLICY_OPERATOR']), false);
  assert.equal(canSimulatePolicy(['AUDITOR']), false);
});

test('simulate is permission-gated, audited, and policy modules contain no dynamic code execution', async () => {
  const controller = await readFile(
    new URL('../src/modules/abac/abac.controller.ts', import.meta.url),
    'utf8',
  );
  const service = await readFile(
    new URL('../src/modules/abac/abac.service.ts', import.meta.url),
    'utf8',
  );
  const sources = await Promise.all(
    [
      'abac.types.ts',
      'attribute-registry.ts',
      'policy-compiler.ts',
      'policy-engine.ts',
      'policy-validator.ts',
    ].map((name) => readFile(new URL(`../src/modules/abac/${name}`, import.meta.url), 'utf8')),
  );
  assert.match(controller, /@RequirePermission\('POLICY', 'SIMULATE', true\)/u);
  assert.match(service, /action: 'POLICY_SIMULATED'/u);
  assert.match(service, /resourceDocumentId/u);
  assert.doesNotMatch(service, /title|description|documentContent|fileContent/u);
  for (const source of sources) {
    assert.doesNotMatch(source, /\beval\s*\(|\bFunction\s*\(|node:vm|child_process/u);
  }
});

/**
 * Thuật toán kiểm thử: PIP đồng bộ `subject.employmentStatus` với từ điển ABAC (`EMPLOYMENT_STATUS`),
 * giữ fallback `user.status`, trả `mfaVerified` trong danh sách phiên và bảo toàn thông điệp `400 VALIDATION_FAILED`.
 */
test('PIP employmentStatus syncs ABAC dictionary with user.status fallback, sessions include mfaVerified & 400 errors preserve safe messages', async () => {
  const now = new Date('2026-11-01T00:00:00Z');
  let attrRows = [
    {
      attribute_definitions: { code: 'PROJECT', is_active: true },
      attribute_options: { value_code: 'PRJ-01', is_active: true },
    },
    {
      attribute_definitions: { code: 'EMPLOYMENT_STATUS', is_active: true },
      attribute_options: { value_code: 'CONTRACTOR', is_active: true },
    },
  ];
  const mockDb = {
    user: { findUnique: async () => ({ department_id: 5n, status: 'ACTIVE' }) },
    userAttributeAssignment: {
      findFirst: async () => ({
        attribute_definitions: { is_active: true },
        attribute_options: { numeric_rank: 2, is_active: true },
      }),
      findMany: async () => attrRows,
    },
  };

  const pepExplicit = await buildPepSubjectAttributes(mockDb, 7n, now);
  const grantExplicit = await buildGrantSubjectAttributes(mockDb, 7n, now);
  assert.equal(pepExplicit.employmentStatus, 'CONTRACTOR');
  assert.equal(grantExplicit.employmentStatus, 'CONTRACTOR');
  assert.deepEqual(pepExplicit.projects, ['PRJ-01']);

  attrRows = [{ value_text: 'PRJ-LEGACY' }];
  const pepFallback = await buildPepSubjectAttributes(mockDb, 7n, now);
  assert.equal(pepFallback.employmentStatus, 'ACTIVE');
  assert.deepEqual(pepFallback.projects, ['PRJ-LEGACY']);

  const sessions = await queryActiveUserSessions(
    {
      authSession: {
        findMany: async () => [
          {
            id: 's-1',
            ip_address: '10.0.0.1',
            user_agent: 'UA',
            created_at: now,
            last_seen_at: now,
            expires_at: new Date(now.getTime() + 60_000),
            mfa_verified_at: now,
          },
          {
            id: 's-2',
            ip_address: '10.0.0.2',
            user_agent: null,
            created_at: now,
            last_seen_at: now,
            expires_at: new Date(now.getTime() + 60_000),
            mfa_verified_at: null,
          },
        ],
      },
    },
    7n,
    's-1',
  );
  assert.equal(sessions[0].mfaVerified, true);
  assert.equal(sessions[1].mfaVerified, false);

  let sentEnvelope = null;
  const reply = {
    status: () => reply,
    header: () => reply,
    send: (body) => {
      sentEnvelope = body;
      return reply;
    },
  };
  const host = {
    switchToHttp: () => ({
      getResponse: () => reply,
      getRequest: () => ({ headers: {}, correlationId: 'corr-400' }),
    }),
  };
  new HttpExceptionFilter().catch(
    new BadRequestException({ formErrors: [], fieldErrors: { token: ['Invalid token format'] } }),
    host,
  );
  assert.equal(sentEnvelope.errorCode, AppErrorCode.VALIDATION_FAILED);
  assert.equal(sentEnvelope.message, 'token: Invalid token format');
  assert.doesNotMatch(sentEnvelope.message, /unexpected internal error/i);
});
