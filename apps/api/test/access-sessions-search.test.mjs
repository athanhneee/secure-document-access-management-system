/**
 * Module: Unit Regression Tests for BUG-008 Safe INET Access Session Search
 * Verifies Prisma fallback never emits `ip_address.contains`, LIKE wildcard escaping,
 * and `$queryRaw` delegation with 64-bit BigInt precision preservation.
 */
import 'reflect-metadata';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import {
  buildAccessSessionPrismaSearchOr,
  escapeSqlLikePattern,
  normalizeSessionSearchTerm,
} from '../dist/modules/access-sessions/access-sessions-search.helper.js';
import { AccessSessionsService } from '../dist/modules/access-sessions/access-sessions.service.js';

test('BUG-008 helpers — normalizeSessionSearchTerm & escapeSqlLikePattern handle NUL bytes and LIKE wildcards', () => {
  assert.equal(normalizeSessionSearchTerm(undefined), '');
  assert.equal(normalizeSessionSearchTerm('   \u0000  '), '');
  assert.equal(normalizeSessionSearchTerm('  DOC-\u0000001  '), 'DOC-001');

  assert.equal(escapeSqlLikePattern('plain-text'), 'plain-text');
  assert.equal(escapeSqlLikePattern('100%_!test\\x'), '100!%!_!!test\\x');
});

test('BUG-008 helpers — buildAccessSessionPrismaSearchOr never uses ip_address.contains and gates ip_address.equals by net.isIP', () => {
  for (const nonIp of ['alice', 'DOC-001', '10.20.30', '10.20.30.0/24', 'fe80::1%eth0']) {
    const clauses = buildAccessSessionPrismaSearchOr(nonIp);
    assert.equal(
      clauses.some((clause) => 'ip_address' in clause),
      false,
      `Expected no ip_address filter for non-IP term "${nonIp}"`,
    );
  }

  for (const validIp of ['10.20.30.40', '127.0.0.1', '::1', '2001:db8::1']) {
    const clauses = buildAccessSessionPrismaSearchOr(validIp);
    const ipClause = clauses.find((clause) => 'ip_address' in clause);
    assert.deepEqual(ipClause, { ip_address: { equals: validIp } });
  }
});

test('BUG-008 AccessSessionsService — mock DB fallback without $queryRaw omits ip_address.contains', async () => {
  const capturedWheres = [];
  const mockDb = {
    accessSession: {
      findMany: async ({ where }) => {
        capturedWheres.push(where);
        return [];
      },
      count: async () => 0,
    },
  };

  const service = new AccessSessionsService(mockDb);

  await service.listSessions({ status: 'ALL', search: 'DOC-001' });
  assert.equal(capturedWheres.length, 1);
  assert.equal(
    capturedWheres[0].OR.some((clause) => 'ip_address' in clause),
    false,
  );

  await service.listSessions({ status: 'ACTIVE', search: '192.168.1.55' });
  assert.equal(capturedWheres.length, 2);
  assert.deepEqual(capturedWheres[1].OR[0], { ip_address: { equals: '192.168.1.55' } });
});

test('BUG-008 AccessSessionsService — delegates search to $queryRaw when available and preserves 64-bit BigInt IDs', async () => {
  const sessionId = randomUUID();
  const grantId = randomUUID();
  const docId = randomUUID();
  const rawCalls = [];
  let findManyCalled = false;

  const mockDb = {
    $queryRaw: async (sqlQuery) => {
      rawCalls.push(sqlQuery);
      if (rawCalls.length === 1) {
        return [
          {
            id: sessionId,
            access_grant_id: grantId,
            document_version_id: '9007199254740993',
            user_id: '9007199254740995',
            ip_address: '10.20.30.40',
            user_agent: 'Mozilla/5.0',
            status: 'ACTIVE',
            started_at: new Date('2026-11-25T10:00:00.000Z'),
            last_activity_at: new Date('2026-11-25T10:05:00.000Z'),
            ended_at: null,
            terminated_reason: null,
            username: 'soc.reader',
            full_name: 'SOC Reader',
            version_no: 3,
            document_id: docId,
            document_code: 'DOC-RAW-1',
            document_title: 'Raw Search Doc',
          },
        ];
      }
      return [{ total: 1n }];
    },
    accessSession: {
      findMany: async () => {
        findManyCalled = true;
        return [];
      },
      count: async ({ where }) => (where?.status === 'ACTIVE' ? 2 : 9),
    },
  };

  const service = new AccessSessionsService(mockDb);
  const res = await service.listSessions({
    status: 'ACTIVE',
    search: '10.20.30',
    page: 1,
    limit: 20,
  });

  assert.equal(findManyCalled, false);
  assert.equal(rawCalls.length, 2);
  assert.equal(res.total, 9);
  assert.equal(res.activeCount, 2);
  assert.equal(res.meta.total, 1);
  assert.equal(res.meta.totalPages, 1);
  assert.equal(res.meta.hasMore, false);
  assert.equal(res.data.length, 1);
  assert.equal(res.data[0].id, sessionId);
  assert.equal(res.data[0].documentVersionId, '9007199254740993');
  assert.equal(res.data[0].userId, '9007199254740995');
  assert.equal(res.data[0].ipAddress, '10.20.30.40');
  assert.equal(res.data[0].versionNo, 3);
});
