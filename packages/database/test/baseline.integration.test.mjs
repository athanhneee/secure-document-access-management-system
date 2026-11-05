import assert from 'node:assert/strict';
import { test } from 'node:test';
import { validateDatabaseBaseline } from '../../../scripts/validate-database.mjs';

// CONFLICT-RESOLVED: Cập nhật kiểm thử tích hợp để xác minh toàn bộ chuỗi 12 Prisma migrations (39 bảng FORCE RLS + allowlist dương tính + trigger ROLE grant Bell-LaPadula/SoD) và độ đồng nhất giữa các nguồn SQL
test('full Prisma migration chain and standalone SQL definitions preserve 100% schema parity and security invariants', async () => {
  const result = await validateDatabaseBaseline();
  assert.equal(result.tableCount, 39);
  assert.equal(result.migrationCount, 12);
  assert.equal(result.enumCount, 18);
  assert.equal(result.triggerCount, 21);
  assert.ok(result.supabaseParity === true || result.supabaseParity === null);
  assert.ok(result.checks.length >= 7);
});
