import assert from 'node:assert/strict';
import { test } from 'node:test';
import { validateDatabaseBaseline } from '../../../scripts/validate-database.mjs';

test('original SQL applies to a clean PostgreSQL engine and preserves security constraints', async () => {
  const result = await validateDatabaseBaseline();
  assert.equal(result.tableCount, 31);
  assert.equal(result.checks.length, 8);
});
