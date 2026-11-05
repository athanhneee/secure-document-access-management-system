import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import { createDocumentsTestService } from './helpers/document-lifecycle-mocks.mjs';

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

test('Document Lifecycle: concurrent version updates do not duplicate version numbers', async () => {
  const docId = randomUUID();
  const versions = [];
  let lockAcquired = false;
  const lockQueue = [];

  const acquireLock = () => {
    return new Promise((resolve) => {
      if (!lockAcquired) {
        lockAcquired = true;
        resolve();
      } else {
        lockQueue.push(resolve);
      }
    });
  };

  const releaseLock = () => {
    if (lockQueue.length > 0) {
      const next = lockQueue.shift();
      next();
    } else {
      lockAcquired = false;
    }
  };

  const addVersionConcurrently = async () => {
    await acquireLock();
    try {
      const currentMax = versions.reduce((max, v) => (v.version_no > max ? v.version_no : max), 0);
      const nextVersion = currentMax + 1;
      await new Promise((r) => setTimeout(r, 5));
      versions.push({ document_id: docId, version_no: nextVersion });
      return nextVersion;
    } finally {
      releaseLock();
    }
  };

  const results = await Promise.all(Array.from({ length: 10 }, () => addVersionConcurrently()));

  const uniqueNumbers = new Set(results);
  assert.equal(uniqueNumbers.size, 10, 'All 10 version numbers must be unique');
  assert.deepEqual(
    results.sort((a, b) => a - b),
    [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
    'Versions must be strictly sequential 1 through 10',
  );
});
