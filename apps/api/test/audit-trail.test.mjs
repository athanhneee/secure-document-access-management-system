import assert from 'node:assert/strict';
import { test } from 'node:test';
import './helpers/audit-trail-mocks.mjs';
import {
  QueryAuditLogsSchema,
  ExportAuditLogsSchema,
  CreateAuditAnchorSchema,
  VerifyAuditChainSchema,
} from '../../../packages/contracts/dist/dto.js';
import { canonicalizeJson } from '../dist/modules/audit/audit-canonicalizer.js';
import { AuditRedactionService } from '../dist/modules/audit/audit-redaction.service.js';

test('AuditCanonicalizer: Deterministic serialization regardless of key order', () => {
  const objA = { z: 100, b: 'hello', a: true, m: null };
  const objB = { a: true, m: null, z: 100, b: 'hello' };

  const canonA = canonicalizeJson(objA);
  const canonB = canonicalizeJson(objB);

  assert.equal(canonA, canonB);
  assert.equal(canonA, '{"a":true,"b":"hello","m":null,"z":100}');
});

test('AuditCanonicalizer: Nested objects and arrays sorted deterministically', () => {
  const nestedA = {
    user: { id: 'usr-1', name: 'Alice' },
    tags: ['sec', 'audit'],
    meta: { b: 2, a: 1 },
  };
  const nestedB = {
    meta: { a: 1, b: 2 },
    tags: ['sec', 'audit'],
    user: { name: 'Alice', id: 'usr-1' },
  };

  assert.equal(canonicalizeJson(nestedA), canonicalizeJson(nestedB));
  assert.equal(
    canonicalizeJson(nestedA),
    '{"meta":{"a":1,"b":2},"tags":["sec","audit"],"user":{"id":"usr-1","name":"Alice"}}',
  );
});

test('AuditCanonicalizer: Omission of undefined, function, and symbol values', () => {
  const obj = {
    valid: 'data',
    ignoredUndefined: undefined,
    ignoredFunc: () => {},
    ignoredSymbol: Symbol('test'),
  };

  assert.equal(canonicalizeJson(obj), '{"valid":"data"}');
});

test('AuditCanonicalizer: Primitives, BigInt, Date, and null handling', () => {
  assert.equal(canonicalizeJson(null), 'null');
  assert.equal(canonicalizeJson(true), 'true');
  assert.equal(canonicalizeJson(false), 'false');
  assert.equal(canonicalizeJson(42), '42');
  assert.equal(canonicalizeJson(1234567890123456789n), '"1234567890123456789"');

  const d = new Date('2026-09-23T12:00:00.000Z');
  assert.equal(canonicalizeJson(d), '"2026-09-23T12:00:00.000Z"');
});

test('AuditRedactionService: Recursively redacts sensitive blacklist keys', () => {
  const redaction = new AuditRedactionService();

  const details = {
    actionContext: 'user_login',
    password: 'test-secret-password-123',
    token: 'test-jwt-token-here',
    accessToken: 'test-raw-access-token',
    refreshToken: 'test-raw-refresh-token',
    dek: '0123456789abcdef0123456789abcdef',
    kek: 'abcdef0123456789abcdef0123456789',
    plaintext: 'Confidential document contents here',
    nested: {
      cookie: 'session_cookie=abc',
      totpSecret: 'JBSWY3DPEHPK3PXP',
      safeField: 12345,
    },
  };

  const scrubbed = redaction.sanitizeDetails(details);

  assert.equal(scrubbed.actionContext, 'user_login');
  assert.equal(scrubbed.password, '[REDACTED]');
  assert.equal(scrubbed.token, '[REDACTED]');
  assert.equal(scrubbed.accessToken, '[REDACTED]');
  assert.equal(scrubbed.refreshToken, '[REDACTED]');
  assert.equal(scrubbed.dek, '[REDACTED]');
  assert.equal(scrubbed.kek, '[REDACTED]');
  assert.equal(scrubbed.plaintext, '[REDACTED]');
  assert.equal(scrubbed.nested.cookie, '[REDACTED]');
  assert.equal(scrubbed.nested.totpSecret, '[REDACTED]');
  assert.equal(scrubbed.nested.safeField, 12345);
});

test('AuditRedactionService: Masks Bearer tokens and JWT strings embedded in values', () => {
  const redaction = new AuditRedactionService();

  const dummyJwt = [
    'eyJ' + 'hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
    'eyJ' + 'zdWIiOiIxMjM0NTY3ODkwIn0',
    'mockSignature',
  ].join('.');
  const details = {
    authHeader: `Bearer ${dummyJwt}`,
    reason: 'Failed authorization with Bearer abcdef1234567890',
  };

  const scrubbed = redaction.sanitizeDetails(details);
  assert.match(scrubbed.authHeader, /\[REDACTED_JWT\]/);
  assert.equal(scrubbed.reason, 'Failed authorization with Bearer [REDACTED]');
});

test('AuditRedactionService: Clamps and sanitizes user agent against log injection', () => {
  const redaction = new AuditRedactionService();

  const maliciousUa =
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\nINJECTED_HEADER: evil\u0000nullbyte';
  const sanitized = redaction.sanitizeUserAgent(maliciousUa);

  assert.doesNotMatch(sanitized, /[\r\n]/);
  assert.equal(sanitized.includes('\0'), false);

  const giantUa = 'A'.repeat(500);
  const clamped = redaction.sanitizeUserAgent(giantUa);
  assert.equal(clamped.length, 255);
  assert.ok(clamped.endsWith('...'));
});

test('Contracts: Audit schemas validation rules', () => {
  const validQuery = QueryAuditLogsSchema.safeParse({
    action: 'USER_LOGIN',
    outcome: 'SUCCESS',
    page: '1',
    pageSize: '50',
    sort: 'occurred_at',
    order: 'desc',
  });
  assert.equal(validQuery.success, true);

  const invalidOutcome = QueryAuditLogsSchema.safeParse({
    outcome: 'INVALID_STATUS',
  });
  assert.equal(invalidOutcome.success, false);

  const validExport = ExportAuditLogsSchema.safeParse({
    format: 'CSV',
    limit: 500,
  });
  assert.equal(validExport.success, true);

  const validAnchor = CreateAuditAnchorSchema.safeParse({
    chainPartition: 'DOCUMENT',
  });
  assert.equal(validAnchor.success, true);

  const validVerify = VerifyAuditChainSchema.safeParse({
    chainPartition: 'AUTH',
    fromSequence: '1',
    toSequence: '100',
  });
  assert.equal(validVerify.success, true);
});
