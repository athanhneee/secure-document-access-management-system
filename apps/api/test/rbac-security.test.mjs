import 'reflect-metadata';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthorizationCache } from '../dist/modules/rbac/authorization-cache.js';
import { AuthorizationGuard } from '../dist/modules/rbac/authorization.guard.js';
import {
  SYSTEM_ROLE_PERMISSION_MATRIX,
  systemRoleAllows,
} from '../dist/modules/rbac/permission-matrix.js';
import { REQUIRED_PERMISSION_METADATA } from '../dist/modules/rbac/require-permission.js';

test('authorization cache expires at role valid_to and invalidates immediately', () => {
  const cache = new AuthorizationCache();
  const grant = {
    permissionId: 1n,
    code: 'USER_MANAGE',
    resource: 'USER',
    action: 'MANAGE',
    roleId: 2n,
    roleCode: 'SCOPED_ADMIN',
    scopeDepartmentId: 3n,
    validTo: new Date(2_000),
  };
  cache.set(9n, [grant], 30_000, 1_000);
  assert.equal(cache.get(9n, 1_999)?.length, 1);
  assert.equal(cache.get(9n, 2_000), undefined, 'expired role must not survive cache TTL');
  cache.set(9n, [{ ...grant, validTo: null }], 30_000, 3_000);
  const generation = cache.currentGeneration();
  cache.invalidateUser(9n);
  assert.equal(cache.get(9n, 3_001), undefined);
  assert.equal(cache.currentGeneration(), generation + 1);
});

test('five-role matrix preserves least privilege and admin has no document content view', () => {
  assert.deepEqual(Object.keys(SYSTEM_ROLE_PERMISSION_MATRIX).sort(), [
    'AUDITOR',
    'DOCUMENT_OWNER',
    'DOCUMENT_READER',
    'SECURITY_OFFICER',
    'SYSTEM_ADMIN',
  ]);
  assert.equal(SYSTEM_ROLE_PERMISSION_MATRIX.SYSTEM_ADMIN.includes('DOCUMENT_VIEW'), false);
  assert.equal(systemRoleAllows('SYSTEM_ADMIN', ['USER_MANAGE', 'DEPARTMENT_MANAGE']), true);
  assert.equal(systemRoleAllows('SYSTEM_ADMIN', ['DOCUMENT_VIEW']), false);
  assert.equal(systemRoleAllows('AUDITOR', ['ROLE_MANAGE']), false);
  assert.equal(
    systemRoleAllows('DOCUMENT_OWNER', [
      'DOCUMENT_VIEW',
      'DOCUMENT_DOWNLOAD',
      'DOCUMENT_DISCOVER',
      'ACCESS_REQUEST_VIEW_OWN',
      'NOTIFICATION_VIEW',
    ]),
    true,
  );
});

test('authorization guard returns forbidden when resource/action permission is absent', async () => {
  const reflector = new Reflector();
  const handler = () => undefined;
  Reflect.defineMetadata(
    REQUIRED_PERMISSION_METADATA,
    { resource: 'ROLE', action: 'MANAGE', global: true },
    handler,
  );
  const guard = new AuthorizationGuard(reflector, {
    assertPermission: async () => {
      throw new ForbiddenException('missing');
    },
  });
  const context = {
    getHandler: () => handler,
    switchToHttp: () => ({ getRequest: () => ({ auth: { userId: 7n } }) }),
  };
  await assert.rejects(guard.canActivate(context), (error) => error.getStatus() === 403);
});

test('controllers declare resource/action permissions and contain no role string checks', async () => {
  const files = [
    new URL('../src/modules/users/users.controller.ts', import.meta.url),
    new URL('../src/modules/departments/departments.controller.ts', import.meta.url),
    new URL('../src/modules/rbac/rbac.controller.ts', import.meta.url),
  ];
  for (const file of files) {
    const source = await readFile(file, 'utf8');
    assert.match(source, /@RequirePermission\(/u);
    assert.doesNotMatch(source, /roles\.includes|SYSTEM_ADMIN|SECURITY_OFFICER|AUDITOR/u);
  }
});
