import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHmac, randomUUID } from 'node:crypto';

process.env.DATABASE_URL = 'postgresql://localhost:5432/secure_docs?schema=public';
process.env.NODE_ENV = 'test';

// ── Contract & Schema Imports ───────────────────────────────────────────────────
import {
  QueryAuditLogsSchema,
  ExportAuditLogsSchema,
  CreateAuditAnchorSchema,
  VerifyAuditChainSchema,
} from '../../../packages/contracts/dist/dto.js';
import { AppErrorCode } from '../../../packages/contracts/dist/error-codes.js';

// ── Service Imports ───────────────────────────────────────────────────────────
import { canonicalizeJson } from '../dist/modules/audit/audit-canonicalizer.js';
import { AuditRedactionService } from '../dist/modules/audit/audit-redaction.service.js';
import {
  AuditWriterService,
  AuditWriteException,
} from '../dist/modules/audit/audit-writer.service.js';
import { AuditVerifierService } from '../dist/modules/audit/audit-verifier.service.js';
import { AuditService } from '../dist/modules/audit/audit.service.js';

// ── Mock Helper ───────────────────────────────────────────────────────────────

function createMockConfig(overrides = {}) {
  const store = {
    AUDIT_INTEGRITY_KEY: 'test-integrity-key-32-chars-long-audit-key-00',
    DOCUMENT_AUDIT_HMAC_KEY: 'test-integrity-key-32-chars-long-audit-key-00',
    ...overrides,
  };
  return {
    get: (key) => store[key] ?? null,
  };
}

// ── 1. RFC 8785 JSON Canonicalization Scheme Tests ─────────────────────────────

test('AuditCanonicalizer: Deterministic serialization regardless of key order', () => {
  const objA = { z: 100, b: 'hello', a: true, m: null };
  const objB = { a: true, m: null, z: 100, b: 'hello' };

  const canonA = canonicalizeJson(objA);
  const canonB = canonicalizeJson(objB);

  assert.equal(canonA, canonB);
  assert.equal(canonA, '{"a":true,"b":"hello","m":null,"z":100}');
});

test('AuditCanonicalizer: Nested objects and arrays sorted deterministically', () => {
  const nestedA = {
    user: { id: 'usr-1', name: 'Alice' },
    tags: ['sec', 'audit'],
    meta: { b: 2, a: 1 },
  };
  const nestedB = {
    meta: { a: 1, b: 2 },
    tags: ['sec', 'audit'],
    user: { name: 'Alice', id: 'usr-1' },
  };

  assert.equal(canonicalizeJson(nestedA), canonicalizeJson(nestedB));
  assert.equal(
    canonicalizeJson(nestedA),
    '{"meta":{"a":1,"b":2},"tags":["sec","audit"],"user":{"id":"usr-1","name":"Alice"}}',
  );
});

test('AuditCanonicalizer: Omission of undefined, function, and symbol values', () => {
  const obj = {
    valid: 'data',
    ignoredUndefined: undefined,
    ignoredFunc: () => {},
    ignoredSymbol: Symbol('test'),
  };

  assert.equal(canonicalizeJson(obj), '{"valid":"data"}');
});

test('AuditCanonicalizer: Primitives, BigInt, Date, and null handling', () => {
  assert.equal(canonicalizeJson(null), 'null');
  assert.equal(canonicalizeJson(true), 'true');
  assert.equal(canonicalizeJson(false), 'false');
  assert.equal(canonicalizeJson(42), '42');
  assert.equal(canonicalizeJson(1234567890123456789n), '"1234567890123456789"');

  const d = new Date('2026-09-23T12:00:00.000Z');
  assert.equal(canonicalizeJson(d), '"2026-09-23T12:00:00.000Z"');
});

// ── 2. Audit Redaction Engine Tests ───────────────────────────────────────────

test('AuditRedactionService: Recursively redacts sensitive blacklist keys', () => {
  const redaction = new AuditRedactionService();

  const details = {
    actionContext: 'user_login',
    password: 'test-secret-password-123',
    token: 'test-jwt-token-here',
    accessToken: 'test-raw-access-token',
    refreshToken: 'test-raw-refresh-token',
    dek: '0123456789abcdef0123456789abcdef',
    kek: 'abcdef0123456789abcdef0123456789',
    plaintext: 'Confidential document contents here',
    nested: {
      cookie: 'session_cookie=abc',
      totpSecret: 'JBSWY3DPEHPK3PXP',
      safeField: 12345,
    },
  };

  const scrubbed = redaction.sanitizeDetails(details);

  assert.equal(scrubbed.actionContext, 'user_login');
  assert.equal(scrubbed.password, '[REDACTED]');
  assert.equal(scrubbed.token, '[REDACTED]');
  assert.equal(scrubbed.accessToken, '[REDACTED]');
  assert.equal(scrubbed.refreshToken, '[REDACTED]');
  assert.equal(scrubbed.dek, '[REDACTED]');
  assert.equal(scrubbed.kek, '[REDACTED]');
  assert.equal(scrubbed.plaintext, '[REDACTED]');
  assert.equal(scrubbed.nested.cookie, '[REDACTED]');
  assert.equal(scrubbed.nested.totpSecret, '[REDACTED]');
  assert.equal(scrubbed.nested.safeField, 12345);
});

test('AuditRedactionService: Masks Bearer tokens and JWT strings embedded in values', () => {
  const redaction = new AuditRedactionService();

  const details = {
    authHeader:
      'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThis',
    reason: 'Failed authorization with Bearer abcdef1234567890',
  };

  const scrubbed = redaction.sanitizeDetails(details);
  assert.match(scrubbed.authHeader, /\[REDACTED_JWT\]/);
  assert.equal(scrubbed.reason, 'Failed authorization with Bearer [REDACTED]');
});

test('AuditRedactionService: Clamps and sanitizes user agent against log injection', () => {
  const redaction = new AuditRedactionService();

  const maliciousUa =
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\nINJECTED_HEADER: evil\u0000nullbyte';
  const sanitized = redaction.sanitizeUserAgent(maliciousUa);

  assert.doesNotMatch(sanitized, /[\r\n]/);
  assert.equal(sanitized.includes('\0'), false);

  const giantUa = 'A'.repeat(500);
  const clamped = redaction.sanitizeUserAgent(giantUa);
  assert.equal(clamped.length, 255);
  assert.ok(clamped.endsWith('...'));
});

// ── 3. Audit Writer Service Tests ─────────────────────────────────────────────

test('AuditWriterService: Sequential recording with previous_hash and HMAC chaining', async () => {
  const redaction = new AuditRedactionService();
  const config = createMockConfig();
  const inMemoryLogs = [];

  const mockTx = {
    $executeRawUnsafe: async () => {},
    $queryRawUnsafe: async () => {
      if (inMemoryLogs.length === 0) return [];
      const last = inMemoryLogs[inMemoryLogs.length - 1];
      return [{ entry_hash: last.entry_hash, chain_sequence: last.chain_sequence }];
    },
    auditLog: {
      create: async ({ data }) => {
        inMemoryLogs.push(data);
        return {
          id: BigInt(inMemoryLogs.length),
          entry_hash: data.entry_hash,
          chain_partition: data.chain_partition,
          chain_sequence: data.chain_sequence,
        };
      },
    },
  };

  const writer = new AuditWriterService(config, redaction);
  const context = {
    ip: '192.168.1.100',
    userAgent: 'AuditClient/1.0',
    correlationId: randomUUID(),
  };

  // Record first event in DOCUMENT partition
  const entry1 = await writer.record(
    {
      action: 'DOCUMENT_CREATED',
      outcome: 'SUCCESS',
      objectType: 'DOCUMENT',
      objectId: 'doc-uuid-1',
      documentId: 'doc-uuid-1',
      actorUserId: 101n,
      actorUsername: 'alice',
      chainPartition: 'DOCUMENT',
    },
    context,
    mockTx,
  );

  assert.equal(entry1.chain_sequence, 1n);
  assert.equal(inMemoryLogs[0].previous_hash, null);
  assert.equal(inMemoryLogs[0].chain_partition, 'DOCUMENT');

  // Record second event in DOCUMENT partition
  const entry2 = await writer.record(
    {
      action: 'DOCUMENT_CLASSIFIED',
      outcome: 'SUCCESS',
      objectType: 'DOCUMENT',
      objectId: 'doc-uuid-1',
      documentId: 'doc-uuid-1',
      actorUserId: 101n,
      actorUsername: 'alice',
      chainPartition: 'DOCUMENT',
    },
    context,
    mockTx,
  );

  assert.equal(entry2.chain_sequence, 2n);
  assert.equal(inMemoryLogs[1].previous_hash, inMemoryLogs[0].entry_hash);
  assert.notEqual(inMemoryLogs[1].entry_hash, inMemoryLogs[0].entry_hash);
});

test('AuditWriterService: Partition isolation allows independent sequences', async () => {
  const redaction = new AuditRedactionService();
  const config = createMockConfig();
  const partitionMap = new Map();

  const mockTx = {
    $executeRawUnsafe: async () => {},
    $queryRawUnsafe: async (sql, partition) => {
      const logs = partitionMap.get(partition) ?? [];
      if (logs.length === 0) return [];
      const last = logs[logs.length - 1];
      return [{ entry_hash: last.entry_hash, chain_sequence: last.chain_sequence }];
    },
    auditLog: {
      create: async ({ data }) => {
        if (!partitionMap.has(data.chain_partition)) {
          partitionMap.set(data.chain_partition, []);
        }
        partitionMap.get(data.chain_partition).push(data);
        return {
          id: BigInt(Date.now()),
          entry_hash: data.entry_hash,
          chain_partition: data.chain_partition,
          chain_sequence: data.chain_sequence,
        };
      },
    },
  };

  const writer = new AuditWriterService(config, redaction);
  const context = { ip: '10.0.0.1', correlationId: randomUUID() };

  // Write to AUTH partition
  const authEntry1 = await writer.record(
    {
      action: 'USER_LOGIN',
      outcome: 'SUCCESS',
      objectType: 'USER',
      chainPartition: 'AUTH',
    },
    context,
    mockTx,
  );

  // Write to ACCESS_GRANT partition
  const grantEntry1 = await writer.record(
    {
      action: 'GRANT_CREATED',
      outcome: 'SUCCESS',
      objectType: 'ACCESS_GRANT',
      chainPartition: 'ACCESS_GRANT',
    },
    context,
    mockTx,
  );

  assert.equal(authEntry1.chain_sequence, 1n);
  assert.equal(grantEntry1.chain_sequence, 1n);
  assert.equal(partitionMap.get('AUTH').length, 1);
  assert.equal(partitionMap.get('ACCESS_GRANT').length, 1);
});

test('AuditWriterService: Does not swallow errors and throws AuditWriteException', async () => {
  const redaction = new AuditRedactionService();
  const config = createMockConfig();

  const failingTx = {
    $executeRawUnsafe: async () => {
      throw new Error('Database connection failed');
    },
  };

  const writer = new AuditWriterService(config, redaction);
  const context = { ip: '10.0.0.1', correlationId: randomUUID() };

  await assert.rejects(
    async () => {
      await writer.record(
        {
          action: 'CRITICAL_OP',
          outcome: 'SUCCESS',
          objectType: 'SYSTEM',
        },
        context,
        failingTx,
      );
    },
    (err) => {
      assert.ok(err instanceof AuditWriteException);
      assert.equal(err.code, AppErrorCode.AUDIT_WRITE_FAILED);
      return true;
    },
  );
});

// ── 4. Audit Verifier Service Tests ───────────────────────────────────────────

test('AuditVerifierService: Validates pristine chain successfully', async () => {
  const redaction = new AuditRedactionService();
  const config = createMockConfig();
  const writer = new AuditWriterService(config, redaction);

  const logs = [];
  const mockTx = {
    $executeRawUnsafe: async () => {},
    $queryRawUnsafe: async () => {
      if (logs.length === 0) return [];
      const last = logs[logs.length - 1];
      return [{ entry_hash: last.entry_hash, chain_sequence: last.chain_sequence }];
    },
    auditLog: {
      create: async ({ data }) => {
        const item = { ...data, id: BigInt(logs.length + 1) };
        logs.push(item);
        return item;
      },
    },
  };

  const context = { ip: '127.0.0.1', correlationId: randomUUID() };

  // Write 3 valid entries
  await writer.record(
    { action: 'EVENT_1', outcome: 'SUCCESS', objectType: 'DOC', chainPartition: 'P1' },
    context,
    mockTx,
  );
  await writer.record(
    { action: 'EVENT_2', outcome: 'DENIED', objectType: 'DOC', chainPartition: 'P1' },
    context,
    mockTx,
  );
  await writer.record(
    { action: 'EVENT_3', outcome: 'FAILED', objectType: 'DOC', chainPartition: 'P1' },
    context,
    mockTx,
  );

  const mockDatabase = {
    auditLog: {
      findMany: async () => logs,
    },
    auditAnchor: {
      findMany: async () => [],
    },
  };

  const verifier = new AuditVerifierService(writer, mockDatabase);

  const result = await verifier.verifyPartition('P1');

  assert.equal(result.valid, true);
  assert.equal(result.totalChecked, 3);
  assert.equal(result.violations.length, 0);
});

test('AuditVerifierService: Detects AUDIT_LOG_TAMPERED on protected field modification', async () => {
  const redaction = new AuditRedactionService();
  const config = createMockConfig();
  const writer = new AuditWriterService(config, redaction);

  const logs = [];
  const mockTx = {
    $executeRawUnsafe: async () => {},
    $queryRawUnsafe: async () => [],
    auditLog: {
      create: async ({ data }) => {
        const item = { ...data, id: 1n };
        logs.push(item);
        return item;
      },
    },
  };

  const context = { ip: '127.0.0.1', correlationId: randomUUID() };
  await writer.record(
    { action: 'ORIGINAL_ACTION', outcome: 'SUCCESS', objectType: 'DOC', chainPartition: 'P1' },
    context,
    mockTx,
  );

  // Tamper with action field
  const tamperedLogs = [{ ...logs[0], action: 'TAMPERED_ACTION' }];

  let alertCreated = false;
  const mockDatabase = {
    auditLog: {
      findMany: async () => tamperedLogs,
    },
    auditAnchor: {
      findMany: async () => [],
    },
    $transaction: async (fn) => {
      return await fn({
        securityAlert: {
          create: async ({ data }) => {
            alertCreated = true;
            assert.equal(data.severity, 'CRITICAL');
            assert.equal(data.alert_type, 'AUDIT_INTEGRITY_COMPROMISED');
          },
        },
        alertAuditLink: {
          create: async () => {},
        },
      });
    },
  };

  const verifier = new AuditVerifierService(writer, mockDatabase);

  const result = await verifier.verifyPartition('P1');

  assert.equal(result.valid, false);
  assert.equal(result.violations.length, 1);
  assert.equal(result.violations[0].code, AppErrorCode.AUDIT_LOG_TAMPERED);
  assert.equal(alertCreated, true);
});

test('AuditVerifierService: Detects AUDIT_SEQUENCE_GAP when log is missing/deleted', async () => {
  const redaction = new AuditRedactionService();
  const config = createMockConfig();
  const writer = new AuditWriterService(config, redaction);

  const logs = [
    {
      id: 1n,
      action: 'OP1',
      actor_user_id: null,
      actor_username: null,
      chain_algorithm: 'HMAC-SHA-256',
      chain_partition: 'P1',
      chain_sequence: 1n,
      correlation_id: randomUUID(),
      details: {},
      document_id: null,
      access_session_id: null,
      ip_address: null,
      object_type: 'DOC',
      object_id: null,
      occurred_at: new Date(),
      outcome: 'SUCCESS',
      previous_hash: null,
      reason_code: null,
      user_agent: null,
      hmac_key_version: 1,
      entry_hash: '',
    },
    {
      id: 3n,
      action: 'OP3',
      actor_user_id: null,
      actor_username: null,
      chain_algorithm: 'HMAC-SHA-256',
      chain_partition: 'P1',
      chain_sequence: 3n, // GAP: sequence 2 is missing!
      correlation_id: randomUUID(),
      details: {},
      document_id: null,
      access_session_id: null,
      ip_address: null,
      object_type: 'DOC',
      object_id: null,
      occurred_at: new Date(),
      outcome: 'SUCCESS',
      previous_hash: 'some-hash',
      reason_code: null,
      user_agent: null,
      hmac_key_version: 1,
      entry_hash: 'entry3',
    },
  ];

  // Set valid hash on first log
  const canon1 = canonicalizeJson({
    action: logs[0].action,
    actorUserId: null,
    actorUsername: null,
    chainAlgorithm: logs[0].chain_algorithm,
    chainPartition: logs[0].chain_partition,
    chainSequence: '1',
    correlationId: logs[0].correlation_id,
    details: logs[0].details,
    documentId: null,
    accessSessionId: null,
    ipAddress: null,
    objectType: logs[0].object_type,
    objectId: null,
    occurredAt: logs[0].occurred_at.toISOString(),
    outcome: logs[0].outcome,
    previousHash: null,
    reasonCode: null,
    userAgent: null,
  });
  logs[0].entry_hash = createHmac('sha256', config.get('AUDIT_INTEGRITY_KEY'))
    .update(canon1)
    .digest('hex');

  const mockDatabase = {
    auditLog: {
      findMany: async () => logs,
    },
    auditAnchor: {
      findMany: async () => [],
    },
    $transaction: async (fn) => {
      return await fn({
        securityAlert: { create: async () => {} },
        alertAuditLink: { create: async () => {} },
      });
    },
  };

  const verifier = new AuditVerifierService(writer, mockDatabase);

  const result = await verifier.verifyPartition('P1');

  assert.equal(result.valid, false);
  const gapViolation = result.violations.find((v) => v.code === AppErrorCode.AUDIT_SEQUENCE_GAP);
  assert.ok(gapViolation);
  assert.equal(gapViolation.sequence, 3n);
});

// ── 5. Scoped Access & IDOR Prevention Tests ──────────────────────────────────

test('AuditService: Document Owner can only view logs for owned documents', async () => {
  const ownedDocId = '11111111-1111-4111-8111-111111111111';
  const foreignDocId = '22222222-2222-4222-8222-222222222222';
  const ownerUserId = 999n;

  const mockDb = {
    document: {
      findUnique: async ({ where }) => {
        if (where.id === ownedDocId) return { id: ownedDocId, owner_id: ownerUserId };
        if (where.id === foreignDocId) return { id: foreignDocId, owner_id: 888n };
        return null;
      },
      findMany: async () => [{ id: ownedDocId }],
    },
    auditLog: {
      count: async () => 1,
      findMany: async () => [
        {
          id: 1n,
          occurred_at: new Date(),
          actor_user_id: ownerUserId,
          actor_username: 'owner',
          action: 'DOCUMENT_METADATA_UPDATED',
          object_type: 'DOCUMENT',
          object_id: ownedDocId,
          document_id: ownedDocId,
          access_session_id: null,
          outcome: 'SUCCESS',
          reason_code: null,
          ip_address: '127.0.0.1',
          user_agent: 'Browser',
          correlation_id: randomUUID(),
          details: {},
          chain_partition: 'DOCUMENT',
          chain_sequence: 1n,
          entry_hash: 'hash1',
          previous_hash: null,
          hmac_key_version: 1,
          chain_algorithm: 'HMAC-SHA-256',
        },
      ],
    },
  };

  const auditService = new AuditService({}, {}, mockDb);

  const ownerPrincipal = {
    userId: ownerUserId,
    username: 'owner',
    roles: ['DOCUMENT_OWNER'],
    sessionId: randomUUID(),
    mfa: true,
  };

  // 1. Success: viewing owned document logs
  const ownedResult = await auditService.queryAuditLogs(ownerPrincipal, {
    documentId: ownedDocId,
    page: 1,
    pageSize: 20,
    sort: 'occurred_at',
    order: 'desc',
  });
  assert.equal(ownedResult.data.length, 1);
  assert.equal(ownedResult.data[0].documentId, ownedDocId);

  // 2. Failure: trying to view foreign document logs (IDOR blocked)
  await assert.rejects(
    async () => {
      await auditService.queryAuditLogs(ownerPrincipal, {
        documentId: foreignDocId,
        page: 1,
        pageSize: 20,
        sort: 'occurred_at',
        order: 'desc',
      });
    },
    (err) => {
      assert.equal(err.status, 403);
      assert.match(err.message, /Access to audit logs for this document is denied/);
      return true;
    },
  );
});

test('AuditService: Auditor has global access; System Admin is rejected (SoD)', async () => {
  const mockDatabase = {
    auditLog: {
      count: async () => 5,
      findMany: async () => [],
    },
  };
  const auditService = new AuditService({}, {}, mockDatabase);

  const auditorPrincipal = {
    userId: 50n,
    username: 'auditor',
    roles: ['AUDITOR'],
    sessionId: randomUUID(),
    mfa: true,
  };

  const adminPrincipal = {
    userId: 1n,
    username: 'sysadmin',
    roles: ['SYSTEM_ADMIN'],
    sessionId: randomUUID(),
    mfa: true,
  };

  // Auditor query succeeds globally
  const result = await auditService.queryAuditLogs(auditorPrincipal, {
    page: 1,
    pageSize: 20,
    sort: 'occurred_at',
    order: 'desc',
  });
  assert.equal(result.pagination.total, 5);

  // System Admin is rejected (SoD principle)
  await assert.rejects(
    async () => {
      await auditService.queryAuditLogs(adminPrincipal, {
        page: 1,
        pageSize: 20,
        sort: 'occurred_at',
        order: 'desc',
      });
    },
    (err) => {
      assert.equal(err.status, 403);
      return true;
    },
  );
});

// ── 6. CSV Export & Escaping Tests ─────────────────────────────────────────────

test('AuditService: Export to CSV escapes special characters and does not leak keys', async () => {
  const mockDatabase = {
    auditLog: {
      findMany: async () => [
        {
          id: 101n,
          occurred_at: new Date('2026-09-23T10:00:00.000Z'),
          actor_user_id: 10n,
          actor_username: 'alice, with comma',
          action: 'DOCUMENT_SEARCHED',
          object_type: 'DOCUMENT',
          object_id: 'doc-1',
          document_id: 'doc-1',
          access_session_id: null,
          outcome: 'SUCCESS',
          reason_code: 'Searched "confidential" term',
          ip_address: '10.0.0.1',
          correlation_id: 'c-1',
          chain_partition: 'DOCUMENT',
          chain_sequence: 1n,
          entry_hash: 'hash-abc',
        },
      ],
    },
  };
  const auditService = new AuditService({}, {}, mockDatabase);

  const auditorPrincipal = {
    userId: 50n,
    username: 'auditor',
    roles: ['AUDITOR'],
    sessionId: randomUUID(),
    mfa: true,
  };

  const exported = await auditService.exportAuditLogs(auditorPrincipal, {
    format: 'CSV',
    limit: 100,
  });

  assert.equal(exported.format, 'CSV');
  assert.equal(exported.count, 1);
  assert.ok(exported.data.includes('"alice, with comma"'));
  assert.ok(exported.data.includes('"Searched ""confidential"" term"'));
});

// ── 7. Schema Validation Tests ────────────────────────────────────────────────

test('Contracts: Audit schemas validation rules', () => {
  const validQuery = QueryAuditLogsSchema.safeParse({
    action: 'USER_LOGIN',
    outcome: 'SUCCESS',
    page: '1',
    pageSize: '50',
    sort: 'occurred_at',
    order: 'desc',
  });
  assert.equal(validQuery.success, true);

  const invalidOutcome = QueryAuditLogsSchema.safeParse({
    outcome: 'INVALID_STATUS',
  });
  assert.equal(invalidOutcome.success, false);

  const validExport = ExportAuditLogsSchema.safeParse({
    format: 'CSV',
    limit: 500,
  });
  assert.equal(validExport.success, true);

  const validAnchor = CreateAuditAnchorSchema.safeParse({
    chainPartition: 'DOCUMENT',
  });
  assert.equal(validAnchor.success, true);

  const validVerify = VerifyAuditChainSchema.safeParse({
    chainPartition: 'AUTH',
    fromSequence: '1',
    toSequence: '100',
  });
  assert.equal(validVerify.success, true);
});
