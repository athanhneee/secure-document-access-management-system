process.env.DATABASE_URL = 'postgresql://localhost:5432/secure_docs?schema=public';
process.env.NODE_ENV = 'test';

import { AuditRedactionService } from '../../dist/modules/audit/audit-redaction.service.js';
import { AuditWriterService } from '../../dist/modules/audit/audit-writer.service.js';

export function createMockConfig(overrides = {}) {
  const store = {
    AUDIT_INTEGRITY_KEY: 'test-integrity-key-32-chars-long-audit-key-00',
    DOCUMENT_AUDIT_HMAC_KEY: 'test-integrity-key-32-chars-long-audit-key-00',
    ...overrides,
  };
  return {
    get: (key) => store[key] ?? null,
  };
}

export function createAuditWriterHarness(overrides = {}) {
  const redaction = new AuditRedactionService();
  const config = createMockConfig(overrides);
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

  return { redaction, config, writer, logs, mockTx };
}
