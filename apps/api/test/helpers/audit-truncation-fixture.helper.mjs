import { createHmac, generateKeyPairSync, randomUUID } from 'node:crypto';
import { AppConfigService } from '../../dist/config/config.service.js';
import { AuditVerifierService } from '../../dist/modules/audit/audit-verifier.service.js';
import { AuditWriterService } from '../../dist/modules/audit/audit-writer.service.js';

/**
 * Thuật toán / Tổng quan module:
 * Bộ dựng bối cảnh giả lập chuỗi kiểm toán bị cắt đầu (`chain_sequence = 3`, mất `priorLog`)
 * phục vụ kiểm thử `AuditVerifierService` không rò rỉ oracle chữ ký HMAC.
 */
export function buildTruncatedAuditVerifierFixture() {
  const hmacKey = 'audit-verifier-hmac-test-key-at-least-32-chars!!';
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const config = new AppConfigService({
    NODE_ENV: 'test',
    APP_ENCRYPTION_MASTER_KEY: 'test-master-key-32-chars-long-000000000',
    AUDIT_INTEGRITY_KEY: hmacKey,
    AUTH_SIGNING_PRIVATE_KEY_PEM: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    AUTH_SIGNING_PUBLIC_KEYS_JSON: JSON.stringify({
      'kid-1': publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    }),
  });

  const occurredAt = new Date('2026-10-15T12:00:00.000Z');
  const corrId = randomUUID();
  const truncatedLog = {
    id: 3n,
    chain_partition: 'GLOBAL',
    chain_sequence: 3n,
    hmac_key_version: 1,
    chain_algorithm: 'HMAC-SHA-256',
    action: 'DOCUMENT_VIEWED',
    actor_user_id: 7n,
    actor_username: 'reader1',
    correlation_id: corrId,
    details: {},
    document_id: null,
    access_session_id: null,
    ip_address: '127.0.0.1',
    object_type: 'DOCUMENT',
    object_id: 'doc-1',
    occurred_at: occurredAt,
    outcome: 'SUCCESS',
    previous_hash: 'a'.repeat(64),
    reason_code: null,
    user_agent: null,
    entry_hash: 'f'.repeat(64),
  };

  const canonical = JSON.stringify({
    accessSessionId: null,
    action: 'DOCUMENT_VIEWED',
    actorUserId: '7',
    actorUsername: 'reader1',
    chainAlgorithm: 'HMAC-SHA-256',
    chainPartition: 'GLOBAL',
    chainSequence: '3',
    correlationId: corrId,
    details: {},
    documentId: null,
    ipAddress: '127.0.0.1',
    objectId: 'doc-1',
    objectType: 'DOCUMENT',
    occurredAt: occurredAt.toISOString(),
    outcome: 'SUCCESS',
    previousHash: 'a'.repeat(64),
    reasonCode: null,
    userAgent: null,
  });
  const realHmac = createHmac('sha256', hmacKey).update(canonical, 'utf8').digest('hex');

  const alertsPersisted = [];
  const mockDb = {
    auditLog: {
      findFirst: async () => null,
      findMany: async ({ where }) => (where?.chain_sequence?.gt === 3n ? [] : [truncatedLog]),
    },
    auditAnchor: {
      findFirst: async () => null,
      findMany: async () => [],
    },
    securityAlert: {
      findFirst: async () => null,
      create: async ({ data }) => {
        alertsPersisted.push(data);
        return { id: 11n, ...data };
      },
    },
    alertAuditLink: { create: async () => ({}), createMany: async () => ({ count: 1 }) },
    $transaction: async (fn) => fn(mockDb),
  };

  const writer = new AuditWriterService(config, mockDb);
  const verifier = new AuditVerifierService(writer, mockDb);
  return { verifier, realHmac, alertsPersisted };
}
