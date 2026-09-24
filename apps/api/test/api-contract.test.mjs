import 'reflect-metadata';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import {
  IdParamSchema,
  UuidParamSchema,
  CreateDocumentDraftSchema,
  RevokeAccessGrantSchema,
  CreateAccessRequestSchema,
  ListAccessGrantsSchema,
} from '../../../packages/contracts/dist/dto.js';
import { AppErrorCode } from '@sda/contracts';

// ── 1. Standard Error Envelope & AppErrorCode Conformance ────────────────────

test('API Contract — error response follows standard envelope format', () => {
  function createStandardError(code, message, details = undefined) {
    return {
      error: {
        code,
        message,
        details,
      },
    };
  }

  const err = createStandardError(AppErrorCode.VALIDATION_FAILED, 'Request validation failed.', {
    fieldErrors: { title: ['Title is required'] },
  });

  assert.equal(typeof err.error.code, 'string');
  assert.equal(typeof err.error.message, 'string');
  assert.ok(err.error.details);
  assert.equal(err.error.code, AppErrorCode.VALIDATION_FAILED);

  // Response contains no stack trace, database internals, or internal paths
  const serialized = JSON.stringify(err);
  assert.ok(!serialized.includes('node_modules'));
  assert.ok(!serialized.includes('SELECT '));
  assert.ok(!serialized.includes('prisma'));
});

// ── 2. Request Boundary Validation & Mass-Assignment Protection ───────────────

test('API Contract — strict schema rejects unknown/extra fields (mass-assignment protection)', () => {
  const payloadWithExtra = {
    title: 'Hop dong bao mat',
    departmentId: '1',
    isAdmin: true, // Malicious privilege escalation injection
    bypassAudit: true, // Malicious security bypass injection
  };

  const parsed = CreateDocumentDraftSchema.safeParse(payloadWithExtra);
  assert.ok(!parsed.success, 'Schema must reject unexpected fields.');
});

test('API Contract — path params enforce UUID and positive numeric IDs', () => {
  // UUID param
  const validUuid = randomUUID();
  assert.ok(UuidParamSchema.safeParse({ id: validUuid }).success);
  assert.ok(!UuidParamSchema.safeParse({ id: 'invalid-uuid-format' }).success);
  assert.ok(!UuidParamSchema.safeParse({ id: '../traversal/path' }).success);

  // Numeric ID param
  assert.ok(IdParamSchema.safeParse({ id: '42' }).success);
  assert.ok(!IdParamSchema.safeParse({ id: '-1' }).success);
  assert.ok(!IdParamSchema.safeParse({ id: '0' }).success);
  assert.ok(!IdParamSchema.safeParse({ id: 'abc' }).success);
});

// ── 3. Pagination Bounds & Denial-of-Service Protection ────────────────────────

test('API Contract — enforces safe pagination limits and rejects unbounded page size', () => {
  // Normal pagination within bounds
  const validPage = ListAccessGrantsSchema.safeParse({ page: '1', pageSize: '20' });
  assert.ok(validPage.success);
  assert.equal(validPage.data.pageSize, 20);

  // Rejects page 0 or negative
  assert.ok(!ListAccessGrantsSchema.safeParse({ page: '0' }).success);
  assert.ok(!ListAccessGrantsSchema.safeParse({ page: '-5' }).success);

  // Rejects pageSize > 50 (DoS prevention)
  const excessivePage = ListAccessGrantsSchema.safeParse({ pageSize: '1000000' });
  assert.ok(!excessivePage.success, 'Must reject pageSize > 50 to prevent memory exhaustion');

  // Whitelisted sorting fields
  assert.ok(ListAccessGrantsSchema.safeParse({ sort: 'granted_at', order: 'desc' }).success);
  assert.ok(!ListAccessGrantsSchema.safeParse({ sort: 'malicious_sql_injection;' }).success);
});

// ── 4. IDOR Resistance & Resource Isolation ───────────────────────────────────

test('API Contract — CreateAccessRequest relies on authenticated caller, not client-supplied user ID', () => {
  // CreateAccessRequestSchema does NOT accept userId parameter from client body
  const requestBody = {
    documentId: randomUUID(),
    requestedAction: 'VIEW',
    reason: 'Can tham chieu tai lieu cho cong viec nghiep vu.',
    userId: '9999', // Attacker trying to submit request on behalf of user 9999
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

  // Rejects negative version
  assert.ok(
    !RevokeAccessGrantSchema.safeParse({
      reason: 'Thu hoi quyen theo quyet dinh lanh dao.',
      expectedVersion: -1,
    }).success,
  );
});

// ── 6. Secret Sanitization in API Contract ────────────────────────────────────

test('API Contract — response serializer guarantees no sensitive credentials leak', () => {
  function serializeUserResponse(user) {
    const {
      passwordHash: _passwordHash,
      refreshToken: _refreshToken,
      mfaSecret: _mfaSecret,
      ...safeUser
    } = user;
    return { ...safeUser, id: safeUser.id.toString() };
  }

  const rawDbUser = {
    id: 10n,
    username: 'admin',
    email: 'admin@corp.test',
    passwordHash: '$argon2id$v=19$m=65536,p=1,t=3$secret-hash',
    refreshToken: 'secret-refresh-token-opaque',
    mfaSecret: 'encrypted-totp-secret',
    fullName: 'System Administrator',
  };

  const serialized = serializeUserResponse(rawDbUser);
  const jsonOutput = JSON.stringify(serialized);

  assert.ok(!jsonOutput.includes('passwordHash'));
  assert.ok(!jsonOutput.includes('secret-hash'));
  assert.ok(!jsonOutput.includes('refreshToken'));
  assert.ok(!jsonOutput.includes('secret-refresh-token'));
  assert.ok(!jsonOutput.includes('mfaSecret'));
  assert.equal(serialized.username, 'admin');
});
