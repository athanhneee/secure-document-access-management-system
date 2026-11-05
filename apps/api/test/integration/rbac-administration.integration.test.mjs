import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { after, before, test } from 'node:test';
import { createRbacIntegrationHarness } from '../helpers/rbac-integration-harness.mjs';

const harness = createRbacIntegrationHarness();
const { dbHarness, state, principal } = harness;

before(async () => {
  await harness.setup();
});

after(async () => {
  await harness.teardown();
});

test('department trigger rejects parent-child cycles outside the API', async (t) => {
  if (!dbHarness.dbAvailable) {
    t.skip('Live PostgreSQL server not reachable at 127.0.0.1:5432 (run pnpm infra:up)');
    return;
  }
  await assert.rejects(
    dbHarness.sql.query('UPDATE departments SET parent_id=$1 WHERE id=$2', [
      state.oldDepartment.id,
      state.rootDepartment.id,
    ]),
    /cycle/u,
  );
});

test('user transfer expires old scoped grants and records safe before/after audit', async (t) => {
  if (!dbHarness.dbAvailable) {
    t.skip('Live PostgreSQL server not reachable at 127.0.0.1:5432 (run pnpm infra:up)');
    return;
  }
  const updated = await state.users.update(
    principal(),
    state.target.id,
    { expectedVersion: 0, departmentId: state.newDepartment.id },
    state.context,
  );
  assert.equal(updated.departmentId, String(state.newDepartment.id));
  const assignment = await dbHarness.sql.query(
    'SELECT valid_to FROM user_roles WHERE user_id=$1 AND scope_department_id=$2',
    [state.target.id, state.oldDepartment.id],
  );
  assert.ok(assignment.rows[0].valid_to instanceof Date);
  const audit = await dbHarness.sql.query(
    "SELECT details::text FROM audit_logs WHERE action='USER_UPDATED' AND object_id=$1",
    [String(state.target.id)],
  );
  assert.equal(audit.rowCount, 1);
  assert.doesNotMatch(audit.rows[0].details, /password|hash|token|secret/iu);
});

test('optimistic concurrency allows exactly one writer and one audit event', async (t) => {
  if (!dbHarness.dbAvailable) {
    t.skip('Live PostgreSQL server not reachable at 127.0.0.1:5432 (run pnpm infra:up)');
    return;
  }
  const first = state.users.update(
    principal(),
    state.target.id,
    { expectedVersion: 1, fullName: 'Concurrent A' },
    { ...state.context, correlationId: randomUUID() },
  );
  const second = state.users.update(
    principal(),
    state.target.id,
    { expectedVersion: 1, fullName: 'Concurrent B' },
    { ...state.context, correlationId: randomUUID() },
  );
  const settled = await Promise.allSettled([first, second]);
  assert.equal(settled.filter((result) => result.status === 'fulfilled').length, 1);
  assert.equal(settled.filter((result) => result.status === 'rejected').length, 1);
  const count = await dbHarness.sql.query(
    "SELECT count(*)::int AS count FROM audit_logs WHERE action='USER_UPDATED' AND object_id=$1",
    [String(state.target.id)],
  );
  assert.equal(count.rows[0].count, 2, 'one transfer audit plus one winning concurrent audit');
});
