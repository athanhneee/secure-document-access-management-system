import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  DatabaseConflictError,
  DatabaseConstraintError,
  DatabaseUnavailableError,
  mapDatabaseError,
} from '../../dist/errors.js';

test('unknown database errors are mapped without leaking SQL or values', () => {
  const mapped = mapDatabaseError(
    new Error("SELECT password_hash FROM users WHERE username='sensitive-user'"),
  );
  assert.equal(mapped.code, 'DATABASE_OPERATION_FAILED');
  assert.equal(mapped.retryable, false);
  assert.doesNotMatch(mapped.message, /SELECT|password_hash|sensitive-user/iu);
  assert.equal(mapped.cause, undefined);
});

test('PostgreSQL SQLSTATEs map to stable errors without carrying driver details', () => {
  const serialization = mapDatabaseError({ code: '40001', detail: 'sensitive row value' });
  const deadlock = mapDatabaseError({ cause: { originalCode: '40P01', message: 'raw SQL' } });
  const constraint = mapDatabaseError({ code: '23514', detail: 'secret check expression' });
  const unavailable = mapDatabaseError({ code: '57P03', message: 'server details' });

  assert.ok(serialization instanceof DatabaseConflictError);
  assert.ok(deadlock instanceof DatabaseConflictError);
  assert.ok(constraint instanceof DatabaseConstraintError);
  assert.ok(unavailable instanceof DatabaseUnavailableError);
  for (const mapped of [serialization, deadlock, constraint, unavailable]) {
    assert.equal(mapped.cause, undefined);
    assert.doesNotMatch(mapped.message, /sensitive|raw SQL|secret|server details/iu);
  }
});
