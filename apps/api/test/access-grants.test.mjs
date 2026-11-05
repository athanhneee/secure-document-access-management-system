import assert from 'node:assert/strict';
import { test } from 'node:test';
import { CreateAccessGrantSchema } from '../../../packages/contracts/dist/dto.js';
import { AppErrorCode } from '../../../packages/contracts/dist/error-codes.js';
import { validCreateGrant } from './helpers/access-grants-mocks.mjs';

test('CreateAccessGrantSchema — valid USER grant with VIEW', () => {
  const result = CreateAccessGrantSchema.safeParse(validCreateGrant());
  assert.ok(result.success, `Expected success, got: ${JSON.stringify(result.error?.flatten())}`);
  assert.equal(result.data.principalType, 'USER');
  assert.deepEqual(result.data.permissions, ['VIEW']);
});

test('CreateAccessGrantSchema — valid USER grant with VIEW + DOWNLOAD', () => {
  const result = CreateAccessGrantSchema.safeParse(
    validCreateGrant({ permissions: ['VIEW', 'DOWNLOAD'] }),
  );
  assert.ok(result.success);
  assert.deepEqual(result.data.permissions, ['VIEW', 'DOWNLOAD']);
});

test('CreateAccessGrantSchema — valid ROLE grant', () => {
  const result = CreateAccessGrantSchema.safeParse(
    validCreateGrant({
      principalType: 'ROLE',
      principalUserId: undefined,
      principalRoleId: '5',
    }),
  );
  assert.ok(result.success);
  assert.equal(result.data.principalType, 'ROLE');
  assert.equal(result.data.principalRoleId, 5n);
});

test('CreateAccessGrantSchema — rejects both USER and ROLE principal', () => {
  const result = CreateAccessGrantSchema.safeParse(
    validCreateGrant({
      principalType: 'USER',
      principalUserId: '1',
      principalRoleId: '5',
    }),
  );
  assert.ok(!result.success);
  const issues = result.error.flatten().formErrors;
  assert.ok(
    issues.length > 0 || Object.keys(result.error.flatten().fieldErrors).length > 0,
    'Expected validation errors for dual principal',
  );
});

test('CreateAccessGrantSchema — rejects USER type without principalUserId', () => {
  const result = CreateAccessGrantSchema.safeParse(
    validCreateGrant({ principalUserId: undefined }),
  );
  assert.ok(!result.success);
});

test('CreateAccessGrantSchema — rejects ROLE type without principalRoleId', () => {
  const result = CreateAccessGrantSchema.safeParse(
    validCreateGrant({
      principalType: 'ROLE',
      principalUserId: undefined,
    }),
  );
  assert.ok(!result.success);
});

test('CreateAccessGrantSchema — rejects validUntil before validFrom', () => {
  const now = new Date();
  const result = CreateAccessGrantSchema.safeParse(
    validCreateGrant({
      validFrom: new Date(now.getTime() + 86400 * 1000).toISOString(),
      validUntil: new Date(now.getTime() + 3600 * 1000).toISOString(),
    }),
  );
  assert.ok(!result.success);
  const flat = result.error.flatten();
  const hasTimeError =
    flat.fieldErrors.validUntil?.some((m) => m.includes('after')) ||
    flat.formErrors?.some((m) => m.includes('after'));
  assert.ok(hasTimeError, 'Expected validUntil after validFrom error');
});

test('CreateAccessGrantSchema — rejects validUntil equal to validFrom', () => {
  const ts = new Date().toISOString();
  const result = CreateAccessGrantSchema.safeParse(
    validCreateGrant({ validFrom: ts, validUntil: ts }),
  );
  assert.ok(!result.success);
});

test('CreateAccessGrantSchema — rejects empty permissions array', () => {
  const result = CreateAccessGrantSchema.safeParse(validCreateGrant({ permissions: [] }));
  assert.ok(!result.success);
});

test('CreateAccessGrantSchema — rejects invalid permission', () => {
  const result = CreateAccessGrantSchema.safeParse(validCreateGrant({ permissions: ['SHARE'] }));
  assert.ok(!result.success);
});

test('CreateAccessGrantSchema — rejects invalid documentId', () => {
  const result = CreateAccessGrantSchema.safeParse(validCreateGrant({ documentId: 'not-a-uuid' }));
  assert.ok(!result.success);
});

test('CreateAccessGrantSchema — rejects extra fields (strict mode)', () => {
  const result = CreateAccessGrantSchema.safeParse(validCreateGrant({ extraField: 'should-fail' }));
  assert.ok(!result.success);
});

test('AppErrorCode — includes all grant error codes', () => {
  const expectedCodes = [
    'GRANT_NOT_FOUND',
    'GRANT_ALREADY_REVOKED',
    'GRANT_OVERLAP_EXISTS',
    'GRANT_PRINCIPAL_INVALID',
    'GRANT_DOWNLOAD_FORBIDDEN',
    'GRANT_CLEARANCE_INSUFFICIENT',
    'GRANT_ABAC_DENIED',
    'GRANT_CONCURRENCY_CONFLICT',
    'GRANT_DURATION_EXCEEDED',
    'GRANT_TIME_RANGE_INVALID',
    'USER_NOT_ACTIVE',
    'ROLE_NOT_ACTIVE',
  ];

  for (const code of expectedCodes) {
    assert.equal(AppErrorCode[code], code, `Expected AppErrorCode.${code} to equal '${code}'`);
  }
});

test('CreateAccessGrantSchema — accepts exact ISO 8601 with timezone offset', () => {
  const result = CreateAccessGrantSchema.safeParse(
    validCreateGrant({
      validFrom: '2026-09-23T00:00:00+07:00',
      validUntil: '2026-12-23T00:00:00+07:00',
    }),
  );
  assert.ok(result.success);
});

test('CreateAccessGrantSchema — accepts UTC datetime', () => {
  const result = CreateAccessGrantSchema.safeParse(
    validCreateGrant({
      validFrom: '2026-09-23T00:00:00Z',
      validUntil: '2026-12-23T00:00:00Z',
    }),
  );
  assert.ok(result.success);
});

test('CreateAccessGrantSchema — rejects naive datetime without timezone', () => {
  const result = CreateAccessGrantSchema.safeParse(
    validCreateGrant({
      validFrom: '2026-09-23T00:00:00',
      validUntil: '2026-12-23T00:00:00',
    }),
  );
  assert.ok(!result.success, 'Should reject datetime without timezone offset');
});

test('Grant permissions — VIEW and DOWNLOAD are independent enums', () => {
  const viewOnly = CreateAccessGrantSchema.safeParse(validCreateGrant({ permissions: ['VIEW'] }));
  assert.ok(viewOnly.success);
  assert.ok(!viewOnly.data.permissions.includes('DOWNLOAD'));

  const downloadOnly = CreateAccessGrantSchema.safeParse(
    validCreateGrant({ permissions: ['DOWNLOAD'] }),
  );
  assert.ok(downloadOnly.success);
  assert.ok(!downloadOnly.data.permissions.includes('VIEW'));
});

test('CreateAccessGrantSchema — coerces string principalUserId to bigint', () => {
  const result = CreateAccessGrantSchema.safeParse(validCreateGrant({ principalUserId: '42' }));
  assert.ok(result.success);
  assert.equal(result.data.principalUserId, 42n);
});

test('CreateAccessGrantSchema — coerces string principalRoleId to bigint', () => {
  const result = CreateAccessGrantSchema.safeParse(
    validCreateGrant({
      principalType: 'ROLE',
      principalUserId: undefined,
      principalRoleId: '99',
    }),
  );
  assert.ok(result.success);
  assert.equal(result.data.principalRoleId, 99n);
});

test('CreateAccessGrantSchema — rejects non-positive principalUserId', () => {
  const result = CreateAccessGrantSchema.safeParse(validCreateGrant({ principalUserId: '0' }));
  assert.ok(!result.success);
});

test('CreateAccessGrantSchema — rejects negative principalRoleId', () => {
  const result = CreateAccessGrantSchema.safeParse(
    validCreateGrant({
      principalType: 'ROLE',
      principalUserId: undefined,
      principalRoleId: '-1',
    }),
  );
  assert.ok(!result.success);
});
