import assert from 'node:assert/strict';
import { test } from 'node:test';
import { isExplicitlyPublicEndpoint } from '../dist/index.js';

test('only an explicit boolean public declaration allows access', () => {
  assert.equal(isExplicitlyPublicEndpoint(true), true);
  for (const declaration of [undefined, null, false, 1, 'true', {}, { role: 'ADMIN' }]) {
    assert.equal(isExplicitlyPublicEndpoint(declaration), false);
  }
});
