import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  expireIdleAndElapsedAuthSessions,
  purgeExpiredAuthSessionsAndTokens,
  runAuthSessionCleanupCycle,
  startAuthSessionCleanupJob,
} from '../dist/auth-session-cleanup-job.js';

/**
 * Thuật toán: Kiểm Chứng Tác Vụ Nền Hết Hạn Nhàn Rỗi & Dọn Rác Phiên Đăng Nhập (`auth-session-cleanup-job`)
 * Mục đích: Đảm bảo worker tự động chuyển `auth_sessions` quá hạn/nhàn rỗi sang `EXPIRED`, thu hồi `refresh_tokens`
 * mồ côi và xóa lô cũ theo đúng thứ tự gỡ tự tham chiếu `parent_token_id` -> xóa `refresh_tokens` -> xóa `auth_sessions`.
 */

test('expireIdleAndElapsedAuthSessions — expires elapsed & idle auth sessions and revokes orphan refresh tokens', async () => {
  const now = new Date('2026-11-25T14:00:00.000Z');
  const authUpdateCalls = [];
  let tokenRevokeCall = null;

  const mockDb = {
    authSession: {
      updateMany: async (args) => {
        authUpdateCalls.push(args);
        return { count: authUpdateCalls.length === 1 ? 2 : 3 };
      },
    },
    refreshToken: {
      updateMany: async (args) => {
        tokenRevokeCall = args;
        return { count: 5 };
      },
    },
  };

  const result = await expireIdleAndElapsedAuthSessions({
    databaseClient: mockDb,
    idleTtlSeconds: 7200,
    now,
  });

  assert.deepEqual(result, {
    expiredAbsoluteCount: 2,
    expiredIdleCount: 3,
    revokedOrphanTokens: 5,
  });
  assert.equal(authUpdateCalls.length, 2);
  assert.equal(authUpdateCalls[0].data.status, 'EXPIRED');
  assert.equal(authUpdateCalls[0].data.revocation_reason, 'SESSION_EXPIRED');
  assert.equal(authUpdateCalls[1].data.status, 'EXPIRED');
  assert.equal(authUpdateCalls[1].data.revocation_reason, 'IDLE_SESSION_EXPIRED');
  assert.deepEqual(authUpdateCalls[1].where.last_seen_at, {
    lte: new Date('2026-11-25T12:00:00.000Z'),
  });
  assert.deepEqual(tokenRevokeCall.where.auth_sessions, { status: { not: 'ACTIVE' } });
});

test('purgeExpiredAuthSessionsAndTokens — clears self-FK parent_token_id before deleting tokens and sessions', async () => {
  const now = new Date('2026-11-25T14:00:00.000Z');
  const ops = [];

  const tx = {
    authSession: {
      findMany: async (args) => {
        ops.push({ op: 'findSessions', take: args.take, where: args.where });
        return [{ id: 'old-sess-1' }, { id: 'old-sess-2' }];
      },
      deleteMany: async (args) => {
        ops.push({ op: 'deleteSessions', ids: args.where.id.in });
        return { count: 2 };
      },
    },
    refreshToken: {
      updateMany: async (args) => {
        ops.push({ op: 'clearParentFk', ids: args.where.auth_session_id.in, data: args.data });
        return { count: 4 };
      },
      deleteMany: async (args) => {
        ops.push({ op: 'deleteTokens', ids: args.where.auth_session_id.in });
        return { count: 6 };
      },
    },
  };

  const mockDb = {
    $transaction: async (fn) => fn(tx),
    authSession: tx.authSession,
    refreshToken: tx.refreshToken,
  };

  const res = await purgeExpiredAuthSessionsAndTokens({
    databaseClient: mockDb,
    retentionDays: 30,
    batchSize: 100,
    now,
  });

  assert.deepEqual(res, { purgedSessions: 2, purgedRefreshTokens: 6 });
  assert.deepEqual(
    ops.map((o) => o.op),
    ['findSessions', 'clearParentFk', 'deleteTokens', 'deleteSessions'],
  );
  assert.equal(ops[0].take, 100);
  assert.deepEqual(ops[1].data, { parent_token_id: null });
});

test('runAuthSessionCleanupCycle & startAuthSessionCleanupJob — runs end-to-end and stops cleanly on abort', async () => {
  const mockDb = {
    $transaction: async (fn) => fn(mockDb),
    authSession: {
      updateMany: async () => ({ count: 1 }),
      findMany: async () => [],
      deleteMany: async () => ({ count: 0 }),
    },
    refreshToken: {
      updateMany: async () => ({ count: 1 }),
      deleteMany: async () => ({ count: 0 }),
    },
  };
  const cycle = await runAuthSessionCleanupCycle({ databaseClient: mockDb });
  assert.equal(cycle.expiredAbsoluteCount, 1);
  assert.equal(cycle.expiredIdleCount, 1);
  assert.equal(cycle.purgedSessions, 0);

  const controller = new AbortController();
  startAuthSessionCleanupJob(600_000, controller.signal);
  controller.abort();
  await new Promise((resolve) => setTimeout(resolve, 30));
});
