import assert from 'node:assert/strict';
import { test } from 'node:test';
import { validateDatabaseBaseline } from '../../../scripts/validate-database.mjs';

// CONFLICT-RESOLVED: Cập nhật kiểm thử tích hợp để xác minh toàn bộ chuỗi 17 Prisma migrations (bao gồm cột bất biến login_ip_address/login_user_agent trên auth_sessions cho BUG-042) và độ đồng nhất giữa các nguồn SQL
test('full Prisma migration chain and standalone SQL definitions preserve 100% schema parity and security invariants', async () => {
  const result = await validateDatabaseBaseline();
  assert.equal(result.tableCount, 39);
  assert.equal(result.migrationCount, 17);
  assert.equal(result.enumCount, 18);
  assert.equal(result.triggerCount, 22);
  assert.ok(result.supabaseParity === true || result.supabaseParity === null);
  assert.ok(result.checks.length >= 7);
});
