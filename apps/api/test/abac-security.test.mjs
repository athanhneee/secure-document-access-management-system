import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
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
