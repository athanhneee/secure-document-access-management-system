/**
 * Module: Real Document Version Pointer & Distributed Redlock Version Serialization Tests
 * Thuật toán: Gọi trực tiếp `DocumentsService.setCurrentVersion` và `persistCleanIngestedVersion` kết hợp cụm 3 nút
 *   `RedlockService` thật để kiểm chứng đánh số phiên bản tuần tự không trùng lặp dưới tải đồng thời.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import { RedlockService } from '../dist/modules/concurrency/redlock.service.js';
import { persistCleanIngestedVersion } from '../dist/modules/documents/ingestion-version.helper.js';
import { createDocumentsTestService } from './helpers/document-lifecycle-mocks.mjs';
import { MockRedisNode, createMockConfig } from './helpers/redlock-mocks.mjs';

test('Document Lifecycle: cannot point current_version to another document or non-CLEAN version', async () => {
  const docA = randomUUID();
  const docB = randomUUID();

  const { versions, service } = createDocumentsTestService({
    documents: [
      [
        docA,
        {
          id: docA,
          document_code: 'DOC-A',
          title: 'Document A',
          owner_id: 1n,
          department_id: 100n,
          status: 'DRAFT',
          current_version_id: null,
        },
      ],
      [
        docB,
        {
          id: docB,
          document_code: 'DOC-B',
          title: 'Document B',
          owner_id: 1n,
          department_id: 100n,
          status: 'DRAFT',
          current_version_id: null,
        },
      ],
    ],
  });

  const versionDocB = 6001n;
  versions.set(versionDocB, {
    id: versionDocB,
    document_id: docB,
    version_no: 1,
    original_filename: 'file-b.pdf',
    scan_status: 'CLEAN',
  });

  const versionDocAPending = 6002n;
  versions.set(versionDocAPending, {
    id: versionDocAPending,
    document_id: docA,
    version_no: 1,
    original_filename: 'pending.pdf',
    scan_status: 'PENDING',
  });

  const principal = { userId: 1n, username: 'owner_user', roles: ['DOCUMENT_OWNER'], mfa: true };
  const context = { ip: '127.0.0.1', correlationId: randomUUID() };

  await assert.rejects(
    service.setCurrentVersion(docA, { versionId: versionDocB }, principal, context),
    (err) => err.response?.errorCode === 'INVALID_VERSION_TARGET',
  );

  await assert.rejects(
    service.setCurrentVersion(docA, { versionId: versionDocAPending }, principal, context),
    (err) => err.response?.errorCode === 'VERSION_NOT_CLEAN',
  );
});

test('Document Lifecycle: real persistCleanIngestedVersion + 3-node RedlockService serializes 10 concurrent uploads sequentially', async () => {
  const docId = randomUUID();
  const nodes = [new MockRedisNode('n1'), new MockRedisNode('n2'), new MockRedisNode('n3')];
  const redlock = new RedlockService(
    createMockConfig({
      REDLOCK_RETRY_COUNT: 60,
      REDLOCK_RETRY_DELAY_MS: 8,
      REDLOCK_RETRY_JITTER_MS: 4,
      REDLOCK_DEFAULT_TTL_MS: 5000,
    }),
    nodes,
  );

  let nextVersionRowId = 7000n;
  const storedDoc = {
    id: docId,
    owner_id: 1n,
    department_id: 10n,
    status: 'ACTIVE',
    current_version_id: null,
  };
  const storedVersions = [];

  const mockDb = {
    async $transaction(callback) {
      const tx = {
        document: {
          async findUnique() {
            // Intentional async yield so unserialized callers would read identical max(version_no)
            await new Promise((r) => setTimeout(r, 4));
            return {
              ...storedDoc,
              versions: storedVersions.map((v) => ({ version_no: v.version_no })),
              classification_history: [{ id: 1n }],
            };
          },
          async update({ data }) {
            Object.assign(storedDoc, data);
            return storedDoc;
          },
        },
        documentVersion: {
          async create({ data }) {
            if (storedVersions.some((v) => v.version_no === data.version_no)) {
              throw new Error(`DUPLICATE_VERSION_NO:${data.version_no}`);
            }
            const created = { id: ++nextVersionRowId, ...data };
            storedVersions.push(created);
            return created;
          },
        },
      };
      return callback(tx);
    },
  };

  const principal = {
    userId: 1n,
    sessionId: randomUUID(),
    username: 'owner_user',
    roles: ['DOCUMENT_OWNER'],
    departmentId: 10n,
    mfa: true,
  };

  const results = await Promise.all(
    Array.from({ length: 10 }, (_, idx) =>
      persistCleanIngestedVersion({
        database: mockDb,
        redlock,
        input: {
          documentId: docId,
          changeNote: `Concurrent revision ${idx + 1}`,
          principal,
          correlationId: randomUUID(),
        },
        targetDocId: docId,
        validatedInfo: {
          sanitizedFilename: `spec-v${idx + 1}.pdf`,
          mimeType: 'application/pdf',
          extension: 'pdf',
        },
        documentStorageKey: `docs/${docId}/v-${idx + 1}.enc`,
        totalBytes: 4096,
        sha256Hash: 'a'.repeat(64),
        dekReference: 'local:dek-ref',
      }),
    ),
  );

  const uniqueNumbers = new Set(results);
  assert.equal(uniqueNumbers.size, 10, 'All 10 persisted version numbers must be unique');
  assert.deepEqual(
    [...results].sort((a, b) => a - b),
    [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
    'Real persistCleanIngestedVersion must allocate sequential versions 1..10',
  );
  assert.equal(storedVersions.length, 10);
});
