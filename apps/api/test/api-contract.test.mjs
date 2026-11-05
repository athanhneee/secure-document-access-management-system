/**
 * Module: Real API Contract, Exception Envelope & Safe DTO Projection Tests
 * Thuật toán: Kiểm chứng trực tiếp `HttpExceptionFilter`, `presentUserRecord` và các lược đồ `@sda/contracts` thật
 *   (thay thế hoàn toàn các hàm giả lập nội bộ trước đây).
 */
import 'reflect-metadata';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { BadRequestException } from '@nestjs/common';
import {
  IdParamSchema,
  UuidParamSchema,
  PositiveBigIntSchema,
  CreateDocumentDraftSchema,
  RevokeAccessGrantSchema,
  CreateAccessRequestSchema,
  ListAccessGrantsSchema,
} from '../../../packages/contracts/dist/dto.js';
import { AppErrorCode } from '@sda/contracts';
import { HttpExceptionFilter } from '../dist/common/filters/http-exception.filter.js';
import { presentUserRecord } from '../dist/modules/users/users-clearance.helper.js';

function createCapturedHttpHost({
  url = '/api/v1/documents',
  headers = {},
  correlationId = undefined,
} = {}) {
  const captured = {
    statusCode: null,
    headers: {},
    body: null,
  };
  const reply = {
    status(code) {
      captured.statusCode = code;
      return reply;
    },
    header(name, value) {
      captured.headers[name.toLowerCase()] = value;
      return reply;
    },
    send(payload) {
      captured.body = payload;
      return reply;
    },
  };
  const request = { url, headers, correlationId };
  const host = {
    switchToHttp: () => ({
      getResponse: () => reply,
      getRequest: () => request,
    }),
  };
  return { host, captured };
}

// ── 1. Real HttpExceptionFilter Envelope & SQL/Stack Masking ──────────────────

test('API Contract — real HttpExceptionFilter formats validation errors and masks 500 internals', () => {
  const filter = new HttpExceptionFilter();

  // Case A: Explicit domain/validation BadRequestException
  const { host: badReqHost, captured: badReq } = createCapturedHttpHost({
    url: '/api/v1/documents?secret=1',
    headers: { 'x-correlation-id': 'corr-safe-001' },
  });
  filter.catch(
    new BadRequestException({
      errorCode: AppErrorCode.VALIDATION_FAILED,
      message: 'Request validation failed.',
      details: { fieldErrors: { title: ['Title is required'] } },
    }),
    badReqHost,
  );

  assert.equal(badReq.statusCode, 400);
  assert.equal(badReq.headers['cache-control'], 'no-store');
  assert.equal(badReq.headers['x-correlation-id'], 'corr-safe-001');
  assert.equal(badReq.body.errorCode, AppErrorCode.VALIDATION_FAILED);
  assert.equal(badReq.body.message, 'Request validation failed.');
  assert.deepEqual(badReq.body.details, { fieldErrors: { title: ['Title is required'] } });
  assert.equal(badReq.body.correlationId, 'corr-safe-001');
  assert.equal(typeof badReq.body.timestamp, 'string');

  // Case B: Raw unexpected internal error with SQL/Prisma details & CRLF correlation injection
  const { host: internalHost, captured: internalRes } = createCapturedHttpHost({
    url: '/api/v1/users',
    headers: { 'x-correlation-id': 'evil\r\nSet-Cookie: hacked=1' },
  });
  const sensitiveInternalError = new Error(
    'SELECT password_hash FROM users WHERE prisma_client = 1 at node_modules/@prisma/client',
  );
  filter.catch(sensitiveInternalError, internalHost);

  assert.equal(internalRes.statusCode, 500);
  assert.equal(internalRes.body.errorCode, AppErrorCode.INTERNAL_SERVER_ERROR);
  assert.notEqual(internalRes.headers['x-correlation-id'], 'evil\r\nSet-Cookie: hacked=1');
  const serialized = JSON.stringify(internalRes.body);
  assert.ok(!serialized.includes('node_modules'));
  assert.ok(!serialized.includes('SELECT '));
  assert.ok(!serialized.includes('password_hash'));
  assert.ok(!serialized.includes('prisma'));
});

// ── 2. Request Boundary Validation & Mass-Assignment Protection ───────────────

test('API Contract — strict schema rejects unknown/extra fields (mass-assignment protection)', () => {
  const payloadWithExtra = {
    title: 'Hop dong bao mat',
    departmentId: '1',
    isAdmin: true,
    bypassAudit: true,
  };

  const parsed = CreateDocumentDraftSchema.safeParse(payloadWithExtra);
  assert.ok(!parsed.success, 'Schema must reject unexpected fields.');
});

test('API Contract — path params and PositiveBigIntSchema enforce UUID and IEEE-754 safe 64-bit IDs', () => {
  const validUuid = randomUUID();
  assert.ok(UuidParamSchema.safeParse({ id: validUuid }).success);
  assert.ok(!UuidParamSchema.safeParse({ id: 'invalid-uuid-format' }).success);
  assert.ok(!UuidParamSchema.safeParse({ id: '../traversal/path' }).success);

  assert.ok(IdParamSchema.safeParse({ id: '42' }).success);
  assert.ok(!IdParamSchema.safeParse({ id: '-1' }).success);
  assert.ok(!IdParamSchema.safeParse({ id: '0' }).success);
  assert.ok(!IdParamSchema.safeParse({ id: 'abc' }).success);

  // [MED-03] Safe IEEE-754 integer check on numeric JSON inputs
  assert.equal(PositiveBigIntSchema.safeParse(Number.MAX_SAFE_INTEGER).data, 9007199254740991n);
  assert.ok(
    !PositiveBigIntSchema.safeParse(Number.MAX_SAFE_INTEGER + 1).success,
    'Must reject unsafe JS numbers exceeding Number.MAX_SAFE_INTEGER',
  );
  assert.equal(PositiveBigIntSchema.safeParse('9007199254740993').data, 9007199254740993n);
});

// ── 3. Pagination Bounds & Denial-of-Service Protection ───────────────────────

test('API Contract — enforces safe pagination limits and rejects unbounded page size', () => {
  const validPage = ListAccessGrantsSchema.safeParse({ page: '1', pageSize: '20' });
  assert.ok(validPage.success);
  assert.equal(validPage.data.pageSize, 20);

  assert.ok(!ListAccessGrantsSchema.safeParse({ page: '0' }).success);
  assert.ok(!ListAccessGrantsSchema.safeParse({ page: '-5' }).success);

  const excessivePage = ListAccessGrantsSchema.safeParse({ pageSize: '1000000' });
  assert.ok(!excessivePage.success, 'Must reject pageSize > 50 to prevent memory exhaustion');

  assert.ok(ListAccessGrantsSchema.safeParse({ sort: 'granted_at', order: 'desc' }).success);
  assert.ok(!ListAccessGrantsSchema.safeParse({ sort: 'malicious_sql_injection;' }).success);
});

// ── 4. IDOR Resistance & Resource Isolation ───────────────────────────────────

test('API Contract — CreateAccessRequest relies on authenticated caller, not client-supplied user ID', () => {
  const requestBody = {
    documentId: randomUUID(),
    requestedAction: 'VIEW',
    reason: 'Can tham chieu tai lieu cho cong viec nghiep vu.',
    userId: '9999',
  };

  const parsed = CreateAccessRequestSchema.safeParse(requestBody);
  assert.ok(!parsed.success, 'Schema must reject spoofed userId field in request body.');
});

// ── 5. Optimistic Concurrency Contract ────────────────────────────────────────

test('API Contract — RevokeAccessGrant accepts optional expectedVersion for optimistic locking', () => {
  const validWithVersion = RevokeAccessGrantSchema.safeParse({
    reason: 'Thu hoi quyen theo quyet dinh lanh dao.',
    expectedVersion: 3,
  });
  assert.ok(validWithVersion.success);
  assert.equal(validWithVersion.data.expectedVersion, 3);

  assert.ok(
    !RevokeAccessGrantSchema.safeParse({
      reason: 'Thu hoi quyen theo quyet dinh lanh dao.',
      expectedVersion: -1,
    }).success,
  );
});

// ── 6. Real User DTO Allowlist Projection ─────────────────────────────────────

test('API Contract — real presentUserRecord enforces allowlist and strips all credentials', () => {
  const rawDbUser = {
    id: 10n,
    username: 'admin',
    email: 'admin@corp.test',
    full_name: 'System Administrator',
    department_id: 2n,
    status: 'ACTIVE',
    version: 4,
    password_hash: '$argon2id$v=19$m=65536,p=1,t=3$secret-hash',
    mfa_methods: [{ secret_encrypted: 'encrypted-totp-secret' }],
    refresh_tokens: [{ token_hash: 'secret-refresh-token-opaque' }],
    password_reset_tokens: [{ token_hash: 'reset-secret' }],
    created_by: 1n,
  };

  const serialized = presentUserRecord(rawDbUser);
  const jsonOutput = JSON.stringify(serialized);

  assert.ok(!jsonOutput.includes('password'));
  assert.ok(!jsonOutput.includes('secret-hash'));
  assert.ok(!jsonOutput.includes('refresh'));
  assert.ok(!jsonOutput.includes('secret-refresh-token'));
  assert.ok(!jsonOutput.includes('encrypted-totp-secret'));
  assert.ok(!jsonOutput.includes('createdBy'));
  assert.equal(serialized.id, '10');
  assert.equal(serialized.departmentId, '2');
  assert.equal(serialized.fullName, 'System Administrator');
  assert.equal(serialized.username, 'admin');
});
